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
	InDir        string
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

	manPath := filepath.Join(opts.InDir, "manifest.age")
	blob, err := os.ReadFile(manPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNoManifest, manPath)
		}
		return nil, err
	}

	id, err := key.Load(opts.IdentityPath)
	if err != nil {
		return nil, err
	}
	macKey, err := id.ManifestMACKey()
	if err != nil {
		id.Zero()
		return nil, err
	}
	defer func() {
		clear(macKey)
		id.Zero()
	}()

	m, err := manifest.Open(blob, macKey, id.AgeIdentity())
	if err != nil {
		return nil, err
	}

	// Positional: compacting survivors makes ReconstructData and Join both
	// return nil while emitting a different SHA-256. FR-15.
	shards := make([][]byte, m.N)
	var missing []int
	for i := 0; i < m.N; i++ {
		b, rerr := os.ReadFile(filepath.Join(opts.InDir, shardFileName(i)))
		if rerr != nil {
			if errors.Is(rerr, os.ErrNotExist) {
				missing = append(missing, i)
				continue
			}
			return nil, rerr
		}
		shards[i] = b
	}

	var failed []int
	for i := 0; i < m.N; i++ {
		if shards[i] == nil {
			continue
		}
		if bytes.Equal(erasure.Digest(shards[i]), m.Digests[i]) {
			continue
		}
		// Present-but-corrupt is an erasure. RS does not detect bit flips;
		// Join would emit wrong bytes. FR-14.
		erasure.Erase(shards, i)
		failed = append(failed, i)
	}

	have := erasure.Usable(shards)
	if have < m.K {
		tf := &erasure.TooFewShardsError{Need: m.K, Have: have}
		if have == 0 {
			// MAC binds the owner, not a point in time; every current shard
			// screens as corrupt. Wrap so M7.2 can name the diagnosis without
			// a type change. Plan R6.
			return nil, fmt.Errorf("%w: %w", tf, ErrStaleManifest)
		}
		return nil, tf
	}

	if testAtReconstruct != nil {
		testAtReconstruct(shards)
	}

	enc, err := erasure.New(m.K, m.N)
	if err != nil {
		return nil, err
	}
	if err := enc.Reconstruct(shards); err != nil {
		return nil, err
	}

	var ct bytes.Buffer
	if err := enc.Join(&ct, shards, m.CiphertextLen); err != nil {
		return nil, err
	}
	if testAtJoin != nil {
		testAtJoin(ct.Bytes(), m.CiphertextLen)
	}

	n, err := decryptToFile(ctx, opts.OutPath, ct.Bytes(), id)
	if err != nil {
		return nil, err
	}

	if status != nil {
		fmt.Fprintf(status, "restored %d bytes to %s\n", n, opts.OutPath)
	}

	return &RestoreReport{
		OutPath:      opts.OutPath,
		K:            m.K,
		N:            m.N,
		Usable:       have,
		FailedIndex:  failed,
		MissingIndex: missing,
		PlaintextLen: n,
	}, nil
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
		dst = testWrapDst(f)
	}
	n, err = crypt.Decrypt(dst, ctxReader(ctx, bytes.NewReader(ct)), id.AgeIdentity())
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
	syncDir(filepath.Dir(outPath))
	return n, nil
}

// syncDir fsyncs a directory so a rename into it survives a crash. EINVAL and
// ENOTSUP are tolerated; the file is already renamed and correct.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	sync := d.Sync
	if testDirSync != nil {
		sync = testDirSync
	}
	if err := sync(); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		// never fail the restore
	}
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

// testAtReconstruct runs at the Reconstruct call site (after the survivor
// count, before reconstruction). Tests assert len(shards)==n and index placement.
var testAtReconstruct func(shards [][]byte)

// testAtJoin observes the joined ciphertext. Tests assert length and SHA-256.
var testAtJoin func(ct []byte, outSize int64)

// testWrapDst wraps the decrypt destination. Tests inject a mid-copy error or
// cancel the context after the first plaintext write.
var testWrapDst func(io.Writer) io.Writer

// testRename replaces os.Rename. Tests inject a rename failure without setting
// committed.
var testRename func(oldpath, newpath string) error

// testRemove replaces os.Remove of .partial during uncommitted cleanup. Tests
// join the leftover-file error with the original diagnosis.
var testRemove func(name string) error

// testDirSync replaces the directory Sync. Tests inject ENOTSUP; Restore must
// still succeed.
var testDirSync func() error
