// Package pipeline owns split/restore/keygen filesystem layout, modes, and ordering.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/key"
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

	return &SplitReport{
		OutDir: opts.OutDir,
		K:      opts.K,
		N:      opts.N,
	}, nil
}

var (
	ErrOutDirNotEmpty = errors.New("output directory is not empty")                  // FR-31
	ErrPartialExists  = errors.New("a .partial file from a previous run is present") // FR-33
	ErrNoManifest     = errors.New("no manifest.age in the shard directory")         // FR-12, FR-26
	ErrStaleManifest  = errors.New("no shard matched the manifest")                  // FR-26
)
