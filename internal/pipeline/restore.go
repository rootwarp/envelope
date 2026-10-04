package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

type RestoreOptions struct {
	IdentityPaths []string
	InDirs        []string
	OutPath       string
	Terminal      Terminal
}

// RestoreReport carries counts, indices and paths only. No field may ever hold
// payload bytes.
type RestoreReport struct {
	OutPath string
	K, N    int
	Usable  int
	// FailedIndex lists every slot that had a shard file but no usable copy.
	// It is grouped by the reason the slot's first copy was rejected —
	// first the slots whose copy was not a usable regular file of the
	// authenticated stripe length, then the slots whose copy failed its
	// digest — and is in index order within each group, matching the order
	// of the stderr lines.
	FailedIndex  []int
	MissingIndex []int // slots with no shard file in any -in directory, index order
	PlaintextLen int64
}

func Restore(ctx context.Context, opts RestoreOptions, status io.Writer) (*RestoreReport, error) {
	captureTestContext(ctx)
	// Advisory: O_EXCL on .partial is the real gate. Fail here so a leftover
	// is reported in a second, not after reconstructing GiB of shards.
	partial := opts.OutPath + ".partial"
	if _, err := os.Lstat(partial); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrPartialExists, partial)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	set, err := openShardSet(ctx, opts.IdentityPaths, opts.InDirs, false, status, opts.Terminal)
	if err != nil {
		return nil, err
	}
	defer func() {
		if ObserveRunInteractions != nil {
			ObserveRunInteractions(set.keys.Interactions())
		}
		set.keys.Zero()
	}()

	if err := set.usableErr(); err != nil {
		return nil, err
	}

	ct, err := set.ciphertext()
	if err != nil {
		return nil, err
	}

	n, err := decryptToFile(ctx, opts.OutPath, ct, set.keys)
	if err != nil {
		return nil, err
	}

	if status != nil {
		fmt.Fprintf(status, "restored %d bytes to %s\n", n, opts.OutPath)
	}

	return &RestoreReport{
		OutPath:      opts.OutPath,
		K:            set.m.K,
		N:            set.m.N,
		Usable:       set.have,
		FailedIndex:  set.failed,
		MissingIndex: set.missing,
		PlaintextLen: n,
	}, nil
}

type shardSet struct {
	m       *manifest.Manifest
	keys    *key.Set
	shards  [][]byte
	failed  []int
	missing []int
	have    int
	multi   bool // true after dedup when two or more distinct directories remain
}

// ManifestKeys, not the Set. The Set's v1 key is an existence probe over the
// first scalar, and a manifest must be verified under the identity that
// opened it.
var (
	_ manifest.Opener       = (*key.ManifestKeys)(nil)
	_ manifest.MACKeySource = (*key.ManifestKeys)(nil)
)

func openShardSet(ctx context.Context, identityPaths []string, inDirs []string, scanAll bool, status io.Writer, term Terminal) (*shardSet, error) {
	if len(inDirs) == 0 {
		return nil, errors.New("at least one -in directory is required")
	}
	dirs, err := resolveInDirs(inDirs)
	if err != nil {
		return nil, err
	}
	// Every output-format decision follows the deduplicated directory list,
	// never len(inDirs): two spellings of one directory must still produce
	// single-directory output.
	multi := len(dirs) > 1

	// Blobs are read BEFORE LoadSet so ErrNoManifest and the manifest read
	// errors keep their Phase 1 precedence over an unloadable identity.
	cands, searched := gatherManifests(dirs)
	if len(cands) == 0 {
		return nil, noManifestErr(multi, searched)
	}
	allRead := false
	for _, c := range cands {
		if c.err == nil {
			allRead = true
			break
		}
	}
	if !allRead {
		return nil, cands[0].err
	}

	groups, order := groupCandidates(cands)

	src := terminalSource(term)
	keys, err := key.LoadSet(identityPaths, src, key.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	// Plugin-only: refuse with no TTY before any age-plugin-* process.
	// A native-with-scalar set never opens the terminal here; natives are decrypted first.
	if err := refuseInteractiveWithoutTerminal(keys); err != nil {
		keys.Zero()
		return nil, err
	}
	if nativeScalar(keys) == nil {
		noteFirstPlugin(keys, status)
	}
	ok := false
	defer func() {
		if ObserveOpenInteractions != nil {
			ObserveOpenInteractions(keys.Interactions())
		}
		if !ok {
			if ObserveRunInteractions != nil {
				ObserveRunInteractions(keys.Interactions())
			}
			keys.Zero()
		}
	}()
	// Every term of the budget is known (d from groups, p from the set, q from
	// the pin record) and no plugin identity has been tried yet.
	announceInteractionBudget(status, len(dirs), groups, keys)
	// Eager v1 scalar derivation keeps plugin-only v1 restores failing
	// closed with ErrNoScalar and zero invocations. A pin-bearing set
	// without a scalar is v2: Open resolves the pin, and KeyFor(1, 0)
	// here would abort before the manifest is read.
	if nativeScalar(keys) != nil || !keys.HasPin() {
		macKey, err := keys.KeyFor(1, 0)
		if err != nil {
			return nil, err
		}
		defer clear(macKey)
	}

	// One view is both the key source and the opener, so the MAC key is the
	// identity that decrypted this blob. Open calls DecryptBytes then KeyFor
	// for one blob before the next, which is why this view is not shared
	// across concurrent opens.
	mk := keys.ManifestKeys()
	op := manifest.Opener(mk)
	if testWrapManifestOpener != nil {
		op = testWrapManifestOpener(op)
	}
	m, err := chooseManifest(groups, order, mk, op, identitySource(keys, identityPaths), multi, status)
	if err != nil {
		return nil, err
	}

	// Positional: compacting survivors makes ReconstructData and Join both
	// return nil while emitting a different SHA-256.
	shards, failed, missing, err := selectShards(ctx, m, dirs, scanAll, multi, status)
	if err != nil {
		return nil, err
	}

	ok = true
	return &shardSet{
		m:       m,
		keys:    keys,
		shards:  shards,
		failed:  failed,
		missing: missing,
		have:    erasure.Usable(shards),
		multi:   multi,
	}, nil
}

func (s *shardSet) usableErr() error {
	if s.have < s.m.K {
		tf := &erasure.TooFewShardsError{Need: s.m.K, Have: s.have}
		if s.have == 0 {
			// MAC binds the owner, not a point in time; every current shard
			// screens as corrupt. Wrap ErrStaleManifest so callers can name
			// this diagnosis with errors.Is.
			return fmt.Errorf("%d of %d shards matched the manifest — the manifest may not belong to this shard set.: %w: %w",
				s.have, s.m.N, tf, ErrStaleManifest)
		}
		return tf
	}
	return nil
}

func (s *shardSet) ciphertext() ([]byte, error) {
	if testAtReconstruct != nil {
		testAtReconstruct(s.shards)
	}

	enc, err := erasure.New(s.m.K, s.m.N)
	if err != nil {
		return nil, err
	}
	if err := enc.Reconstruct(s.shards); err != nil {
		return nil, err
	}

	var ct bytes.Buffer
	if err := enc.Join(&ct, s.shards, s.m.CiphertextLen); err != nil {
		return nil, err
	}
	if testAtJoin != nil {
		testAtJoin(ct.Bytes(), s.m.CiphertextLen)
	}
	return ct.Bytes(), nil
}

// shardRead is what loadShard found at one path. A cancelled context returns
// a non-nil error and shardLoaded; callers must check the error first.
type shardRead uint8

const (
	shardLoaded shardRead = iota
	shardAbsent
	shardUnusable
)

func loadShard(ctx context.Context, path string, stripeLen int64) ([]byte, shardRead, error) {
	if testAtLoadShard != nil {
		testAtLoadShard(path)
	}
	if err := ctx.Err(); err != nil {
		return nil, shardLoaded, err
	}
	f, err := os.OpenFile(path, readOpenFlags, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, shardAbsent, nil
		}
		return nil, shardUnusable, nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, shardUnusable, nil
	}
	if !st.Mode().IsRegular() || st.Size() != stripeLen {
		return nil, shardUnusable, nil
	}
	b, err := io.ReadAll(io.LimitReader(f, stripeLen+1))
	if err != nil || int64(len(b)) != stripeLen {
		return nil, shardUnusable, nil
	}
	return b, shardLoaded, nil
}

func readManifestBlob(path string) ([]byte, error) {
	f, err := os.OpenFile(path, readOpenFlags, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNoManifest, path)
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("manifest.age is not a regular file: %s", path)
	}
	if st.Size() > crypt.MaxBytes {
		return nil, fmt.Errorf("%w: %s", ErrManifestTooLarge, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, crypt.MaxBytes))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// The named results exist for err alone — the deferred cleanup assigns to it.
// Every error path returns n=0; a partial count is not a fact the caller may report.
func decryptToFile(ctx context.Context, outPath string, ct []byte, keys *key.Set) (n int64, err error) {
	partial := outPath + ".partial"

	// O_EXCL: never silently truncate a leftover .partial — that file holds plaintext.
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", partial, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// Reaching here means err != nil: the only return n, nil sets committed first.
		f.Close() // best effort; the real error is already in err
		remove := os.Remove
		if testRemove != nil {
			remove = testRemove
		}
		if rerr := remove(partial); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			// Do NOT overwrite err: the operator needs the original diagnosis
			// AND must be told a plaintext file could not be removed.
			err = errors.Join(err, fmt.Errorf("could not remove %s: %w", partial, rerr))
		}
	}()

	// 0600 survives every realistic umask and O_EXCL removes the existing-file
	// case, so this chmod is belt and suspenders.
	if err = f.Chmod(0o600); err != nil {
		return 0, err
	}

	dst := io.Writer(f)
	if testWrapDst != nil {
		dst = testWrapDst(ctx, f)
	}
	n, err = keys.DecryptTo(dst, func() io.Reader {
		return ctxReader(ctx, bytes.NewReader(ct))
	})
	if err != nil {
		return 0, fmt.Errorf("payload: %w", err) // age authenticates HERE
	}
	if err = f.Sync(); err != nil { // data to stable storage
		return 0, fmt.Errorf("sync %s: %w", partial, err)
	}
	if err = f.Close(); err != nil { // Close can report deferred write errors
		return 0, fmt.Errorf("close %s: %w", partial, err)
	}
	// The rename publishes. A cancel seen before it aborts and removes only
	// this run's temp (the deferred cleanup deletes .partial).
	if err = ctx.Err(); err != nil {
		return 0, fmt.Errorf("payload: %w", err)
	}

	rename := os.Rename
	if testRename != nil {
		rename = testRename
	}
	if err = rename(partial, outPath); err != nil {
		return 0, fmt.Errorf("rename onto %s: %w", outPath, err)
	}
	committed = true // AFTER the rename, never before
	if err = syncDir(filepath.Dir(outPath)); err != nil {
		return n, fmt.Errorf("%w: %s: %w", ErrDirSync, outPath, err)
	}
	return n, nil
}

// syncDir fsyncs a directory so a rename into it survives a crash. EINVAL and
// ENOTSUP are tolerated: the file is already renamed and those errors mean the
// filesystem has no directory-sync operation.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	sync := d.Sync
	if testDirSync != nil {
		sync = testDirSync
	}
	if err := sync(); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

// ctxReader makes a copy observe cancellation, so a SIGINT turns into an
// ordinary read error and the deferred cleanup removes .partial.
func ctxReader(ctx context.Context, r io.Reader) io.Reader {
	return &contextReader{ctx: ctx, r: r}
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// ObserveOpenInteractions receives the identity-side Unwrap count after
// openShardSet finishes, before Zero on a failed return. Tests assert that
// identical copies cost one decrypt site and that a v1 representative
// consults no pin.
var ObserveOpenInteractions func(int)

// ObserveRunInteractions receives the identity-side Unwrap count at the end
// of Restore or Verify (and of a failed openShardSet), before Zero. Tests
// assert Interactions() stays within the announced bound, including identities
// tried and rejected. Production does not branch on the value.
var ObserveRunInteractions func(int)

// testWrapManifestOpener wraps the opener chooseManifest uses. Tests count
// decrypts of distinct blobs.
var testWrapManifestOpener func(manifest.Opener) manifest.Opener

// testAtLoadShard runs at the start of loadShard. Tests assert a conflicting
// pair returns before any shard path is opened.
var testAtLoadShard func(path string)

// testAtReconstruct runs at the Reconstruct call site (after the survivor
// count, before reconstruction). Tests assert len(shards)==n and index placement.
var testAtReconstruct func(shards [][]byte)

// testAtJoin observes the joined ciphertext. Tests assert length and SHA-256.
// It may mutate ct in place; Verify's tamper test relies on it.
var testAtJoin func(ct []byte, outSize int64)

// testWrapDst wraps the decrypt destination. Tests inject a mid-copy error or
// cancel the context after the first plaintext write, and the signal-test
// build parks here.
var testWrapDst func(context.Context, io.Writer) io.Writer

// testRename replaces os.Rename. Tests inject a rename failure without setting
// committed.
var testRename func(oldpath, newpath string) error

// testRemove replaces os.Remove of .partial during uncommitted cleanup. Tests
// join the leftover-file error with the original diagnosis.
var testRemove func(name string) error

// testDirSync replaces the directory Sync. Tests inject ENOTSUP (restore must
// still succeed) and EIO (restore must fail after commit).
var testDirSync func() error
