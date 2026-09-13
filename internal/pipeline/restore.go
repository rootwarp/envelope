package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

	return &RestoreReport{
		OutPath:      opts.OutPath,
		K:            m.K,
		N:            m.N,
		Usable:       have,
		FailedIndex:  failed,
		MissingIndex: missing,
	}, nil
}

// testAtReconstruct runs at the Reconstruct call site (after the survivor
// count, before reconstruction). Tests assert len(shards)==n and index placement.
var testAtReconstruct func(shards [][]byte)
