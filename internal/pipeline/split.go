// Package pipeline owns split/restore/keygen filesystem layout, modes, and ordering.
package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

type SplitOptions struct {
	IdentityPath string
	InPath       string
	OutDir       string
	K, N         int
}

// SplitReport carries counts, indices and paths only. No field may ever hold
// payload bytes.
type SplitReport struct {
	OutDir        string
	K, N          int
	CiphertextLen int64
	StripeLen     int64
}

func Split(ctx context.Context, opts SplitOptions, status io.Writer) (*SplitReport, error) {
	// Validate before any filesystem call so a bad (k, n) cannot leave a
	// half-created directory.
	if err := erasure.Validate(opts.K, opts.N); err != nil {
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
		// Best-effort: hkdf.Key returns a fresh slice the GC may already have copied.
		clear(macKey)
		// Best-effort: cannot scrub copies already made by hkdf.Key or the GC.
		id.Zero()
	}()

	if entries, err := os.ReadDir(opts.OutDir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrOutDirNotEmpty, opts.OutDir)
	}
	if err := os.MkdirAll(opts.OutDir, 0o700); err != nil {
		return nil, err
	}
	// 0700 &^ umask is 0700 for every realistic umask; Chmod is belt, kept
	// for symmetry with the 0644 writes that umask can actually degrade.
	if err := os.Chmod(opts.OutDir, 0o700); err != nil {
		return nil, err
	}

	in, err := os.Open(opts.InPath)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	var buf bytes.Buffer
	ciphertextLen, err := crypt.Encrypt(&buf, in, id.Recipient())
	if err != nil {
		return nil, err
	}
	if testAtCiphertext != nil {
		testAtCiphertext(buf.Bytes())
	}

	// reedsolomon's ErrShortData names neither the parameter nor the file. Envelope's own
	// message names both numbers. erasure.Split carries ErrCiphertextTooShort as the
	// backstop so the rule holds even if a future caller skips this check.
	if ciphertextLen < int64(opts.K) {
		return nil, fmt.Errorf("ciphertext is %d bytes, shorter than k=%d", ciphertextLen, opts.K)
	}

	enc, err := erasure.New(opts.K, opts.N)
	if err != nil {
		return nil, err
	}
	shards, stripeLen, err := enc.Split(buf.Bytes())
	if err != nil {
		return nil, err
	}

	digests := make([][]byte, opts.N)
	for i, shard := range shards {
		d, err := writeShard(opts.OutDir, i, shard)
		if err != nil {
			return nil, err
		}
		digests[i] = d
	}

	sealed, err := manifest.Seal(&manifest.Manifest{
		Version:       manifest.Version,
		K:             opts.K,
		N:             opts.N,
		CiphertextLen: ciphertextLen,
		StripeLen:     stripeLen,
		Digests:       digests,
		MAC:           make([]byte, manifest.MACLen), // Seal validates shape before filling the tag
	}, macKey, id.Recipient())
	if err != nil {
		return nil, err
	}

	// Commit marker: a crash between the last shard and this write leaves
	// unusable ciphertext, never a false success.
	if testFailManifestWrite != nil {
		if err := testFailManifestWrite(); err != nil {
			return nil, err
		}
	}
	if err := writeExclusive(filepath.Join(opts.OutDir, "manifest.age"), bytes.NewReader(sealed), nil); err != nil {
		return nil, err
	}

	if status != nil {
		fmt.Fprintf(status, "encrypted %d bytes\n", ciphertextLen)
		fmt.Fprintf(status, "wrote %d shards to %s\n", opts.N, opts.OutDir)
	}

	return &SplitReport{
		OutDir:        opts.OutDir,
		K:             opts.K,
		N:             opts.N,
		CiphertextLen: ciphertextLen,
		StripeLen:     stripeLen,
	}, nil
}

// testFailManifestWrite, when set, runs after shards are on disk and before
// manifest.age is created. Tests inject a crash between S10 and S12.
var testFailManifestWrite func() error

// testAtCiphertext observes the ciphertext after Encrypt. Tests record its
// SHA-256 to assert Join used the manifest length.
var testAtCiphertext func([]byte)

func shardFileName(i int) string {
	return fmt.Sprintf("shard-%02d", i)
}

func writeShard(dir string, i int, data []byte) ([]byte, error) {
	h := erasure.NewDigest()
	path := filepath.Join(dir, shardFileName(i))
	if err := writeExclusive(path, bytes.NewReader(data), h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func writeExclusive(path string, r io.Reader, extra io.Writer) error {
	// O_EXCL: never truncate a file that appeared after the empty-dir listing.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	w := io.Writer(f)
	if extra != nil {
		w = io.MultiWriter(f, extra)
	}
	_, copyErr := io.Copy(w, r)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	// 0644 &^ umask degrades under umask 0027/0077; Chmod is the call that fires.
	return os.Chmod(path, 0o644)
}

var (
	ErrOutDirNotEmpty = errors.New("output directory is not empty")                  // FR-31
	ErrPartialExists  = errors.New("a .partial file from a previous run is present") // FR-33
	ErrNoManifest     = errors.New("no manifest.age in the shard directory")         // FR-12, FR-26
	ErrStaleManifest  = errors.New("no shard matched the manifest")                  // FR-26
)
