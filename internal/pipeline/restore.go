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
	IdentityPath string
	InDirs       []string
	OutPath      string
}

// RestoreReport carries counts, indices and paths only. No field may ever hold
// payload bytes.
type RestoreReport struct {
	OutPath      string
	K, N         int
	Usable       int
	FailedIndex  []int // digest mismatches, index order
	MissingIndex []int // absent shard files, index order
	PlaintextLen int64
}

func Restore(ctx context.Context, opts RestoreOptions, status io.Writer) (*RestoreReport, error) {
	// Advisory: O_EXCL on .partial is the real gate. Fail here so a leftover
	// is reported in a second, not after reconstructing GiB of shards.
	partial := opts.OutPath + ".partial"
	if _, err := os.Lstat(partial); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrPartialExists, partial)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	set, err := openShardSet(ctx, opts.IdentityPath, opts.InDirs, false, status)
	if err != nil {
		return nil, err
	}
	defer set.id.Zero()

	if err := set.usableErr(); err != nil {
		return nil, err
	}

	ct, err := set.ciphertext()
	if err != nil {
		return nil, err
	}

	n, err := decryptToFile(ctx, opts.OutPath, ct, set.id)
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
	id      *key.Identity
	shards  [][]byte
	failed  []int
	missing []int
	have    int
	multi   bool // I4: true after dedup when two or more distinct directories remain
}

func openShardSet(ctx context.Context, identityPath string, inDirs []string, scanAll bool, status io.Writer) (*shardSet, error) {
	if len(inDirs) == 0 {
		return nil, errors.New("at least one -in directory is required")
	}
	dirs, err := resolveInDirs(inDirs)
	if err != nil {
		return nil, err
	}
	// I4: format decisions follow the deduplicated list, never len(inDirs).
	// Two spellings of one directory must stay single-directory output (FR-MD-06, AD-3).
	multi := len(dirs) > 1

	// Blobs are read BEFORE key.Load so ErrNoManifest and the manifest read
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

	id, err := key.Load(identityPath)
	if err != nil {
		return nil, err
	}
	macKey, err := id.ManifestMACKey()
	if err != nil {
		id.Zero()
		return nil, err
	}
	ok := false
	defer func() {
		clear(macKey)
		if !ok {
			id.Zero()
		}
	}()

	m, err := chooseManifest(cands, id, identityPath, multi, status)
	if err != nil {
		return nil, err
	}

	// Positional: compacting survivors makes ReconstructData and Join both
	// return nil while emitting a different SHA-256. FR-15.
	shards, failed, missing, err := selectShards(ctx, m, dirs, scanAll, multi, status)
	if err != nil {
		return nil, err
	}

	ok = true
	return &shardSet{
		m:       m,
		id:      id,
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
			// screens as corrupt. Wrap so M7.2 can name the diagnosis without
			// a type change. Plan R6.
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

func loadShard(ctx context.Context, path string, stripeLen int64) (data []byte, missing, unusable bool, err error) {
	if testAtLoadShard != nil {
		testAtLoadShard(path)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, false, err
	}
	f, err := os.OpenFile(path, readOpenFlags, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, false, nil
		}
		return nil, false, true, nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, true, nil
	}
	if !st.Mode().IsRegular() || st.Size() != stripeLen {
		return nil, false, true, nil
	}
	b, err := io.ReadAll(io.LimitReader(f, stripeLen+1))
	if err != nil || int64(len(b)) != stripeLen {
		return nil, false, true, nil
	}
	return b, false, false, nil
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
func decryptToFile(ctx context.Context, outPath string, ct []byte, id *key.Identity) (n int64, err error) {
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
	// case, so this is belt — but FR-18 names it.
	if err = f.Chmod(0o600); err != nil {
		return 0, err
	}

	dst := io.Writer(f)
	if testWrapDst != nil {
		dst = testWrapDst(ctx, f)
	}
	n, err = id.DecryptTo(dst, func() io.Reader {
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
// ordinary read error and FR-18's existing deferred cleanup removes .partial.
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
