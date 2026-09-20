package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

// ErrConflictingManifests is returned when two -in directories hold manifests
// that both authenticate but describe different shard sets.
var ErrConflictingManifests = errors.New("conflicting manifests")

// inDir is one resolved -in directory. given is exactly what the operator
// typed; every diagnostic is built from it (FR-MD-08). Identity is
// st_dev/st_ino via os.SameFile, never the string (AD-2).
type inDir struct {
	given string
	info  os.FileInfo // nil for the single-directory case, which is not stat'ed
}

// resolveInDirs de-duplicates by identity (os.SameFile), not by string, and
// with two or more directories checks each one before anything is read.
// With exactly one directory nothing is checked: Phase 1 surfaces the case as
// ErrNoManifest and FR-MD-05 freezes that message.
func resolveInDirs(given []string) ([]inDir, error) {
	// I7: this is not an optimisation. Phase 1 surfaces a bad single -in as
	// ErrNoManifest naming the path; an earlier Stat would replace that frozen
	// message (FR-MD-05). info is legitimately nil; nothing calls SameFile on it.
	if len(given) == 1 {
		return []inDir{{given: given[0]}}, nil
	}
	out := make([]inDir, 0, len(given))
	for _, g := range given {
		fi, err := os.Stat(g)
		if err != nil {
			return nil, fmt.Errorf("-in %s: %w", g, err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("-in %s: not a directory", g)
		}
		// Mode 0000 passes Stat; the open is what rejects it (FR-MD-07).
		d, err := os.Open(g)
		if err != nil {
			return nil, fmt.Errorf("-in %s: %w", g, err)
		}
		d.Close()
		dup := false
		for _, kept := range out {
			if os.SameFile(kept.info, fi) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		out = append(out, inDir{given: g, info: fi})
	}
	return out, nil
}

type manifestCandidate struct {
	path string
	blob []byte
	err  error
}

// gatherManifests reads each directory's manifest.age. An absent file
// contributes no candidate (the ordinary scatter case); searched records
// every path looked at.
func gatherManifests(dirs []inDir) (cands []manifestCandidate, searched []string) {
	for _, d := range dirs {
		p := filepath.Join(d.given, "manifest.age")
		searched = append(searched, p)
		blob, err := readManifestBlob(p)
		if errors.Is(err, ErrNoManifest) {
			continue
		}
		cands = append(cands, manifestCandidate{path: p, blob: blob, err: err})
	}
	return cands, searched
}

// chooseManifest applies FR-MD-03. Two authenticated manifests agree iff their
// MACs are equal: both were verified against the same key, and macInput covers
// exactly the fields that influence restore, so MAC equality is decoded-field
// equality without comparing the randomized .age blobs.
func chooseManifest(cands []manifestCandidate, id *key.Identity, identityPath string, multi bool, status io.Writer) (*manifest.Manifest, error) {
	var chosen *manifest.Manifest
	var chosenPath string
	var firstErr error
	var notes []error

	// Candidate failures are buffered, not printed as they happen: when NO
	// candidate authenticates the command fails with firstErr, which exitCode
	// prints once, and a per-candidate echo would print a wrong-identity
	// diagnosis d times plus once more from exitCode.
	noteFail := func(c manifestCandidate, err error) {
		shown := fmt.Errorf("%w: %s", err, c.path) // stderr: always the manifest file
		returned := shown
		if errors.Is(err, crypt.ErrWrongIdentity) {
			returned = fmt.Errorf("%w: %s", err, identityPath) // Phase 1's frozen form
		}
		if firstErr == nil {
			firstErr = returned
		}
		notes = append(notes, shown)
	}

	for _, c := range cands {
		if c.err != nil {
			// readManifestBlob already formatted a path-bearing error.
			if firstErr == nil {
				firstErr = c.err
			}
			notes = append(notes, c.err)
			continue
		}
		m, err := manifest.Open(c.blob, id, id)
		if err != nil {
			noteFail(c, err)
			continue
		}
		if chosen == nil {
			chosen, chosenPath = m, c.path
			continue
		}
		if !bytes.Equal(chosen.MAC, m.MAC) {
			return nil, fmt.Errorf("%w: %s and %s describe different shard sets", ErrConflictingManifests, chosenPath, c.path)
		}
	}
	if chosen == nil {
		return nil, firstErr
	}
	if multi && status != nil {
		for _, n := range notes {
			fmt.Fprintf(status, "%v\n", n)
		}
	}
	return chosen, nil
}

// Branch on multi, not len(searched): the same flag as every other format
// decision (AD-11). searched[0] is safe because openShardSet rejects empty InDirs.
func noManifestErr(multi bool, searched []string) error {
	if !multi {
		return fmt.Errorf("%w: %s", ErrNoManifest, searched[0])
	}
	return fmt.Errorf("%w: searched %s", ErrNoManifest, strings.Join(searched, ", "))
}

// selectShards is the single selection pass of FR-MD-04. scanAll makes verify
// examine every copy of every slot; restore stops at the first usable one.
//
// Reporting keeps Phase 1's two-phase ORDER — every "unusable" line, then every
// "failed digest" line — so a single-directory run is byte-identical.
func selectShards(ctx context.Context, m *manifest.Manifest, dirs []inDir, scanAll bool, multi bool, status io.Writer) (shards [][]byte, failed, missing []int, err error) {
	shards = make([][]byte, m.N)
	type reject struct {
		index int
		path  string
	}
	var unusableLines, digestLines []reject
	// slotReason: 0 none, 1 unusable first, 2 digest first
	slotReason := make([]int, m.N)

	for i := 0; i < m.N; i++ {
		present := false
		for _, d := range dirs {
			if shards[i] != nil && !scanAll {
				break
			}
			p := filepath.Join(d.given, shardFileName(i))
			b, miss, unusable, rerr := loadShard(ctx, p, m.StripeLen)
			if rerr != nil {
				return nil, nil, nil, rerr
			}
			if miss {
				continue
			}
			present = true
			if unusable {
				unusableLines = append(unusableLines, reject{i, p})
				if slotReason[i] == 0 {
					slotReason[i] = 1
				}
				continue
			}
			if !bytes.Equal(erasure.Digest(b), m.Digests[i]) {
				digestLines = append(digestLines, reject{i, p})
				if slotReason[i] == 0 {
					slotReason[i] = 2
				}
				continue
			}
			if shards[i] == nil {
				shards[i] = b
			}
		}
		if shards[i] == nil && !present {
			missing = append(missing, i)
		}
	}

	emit := func(rs []reject, form string) {
		for _, r := range rs {
			if status == nil {
				continue
			}
			if multi {
				fmt.Fprintf(status, form+": %s\n", r.index, r.path)
			} else {
				fmt.Fprintf(status, form+"\n", r.index)
			}
		}
	}
	emit(unusableLines, "unusable shard at index %d")
	// Two loops: FailedIndex is grouped by reason (every unusable slot, then
	// every digest slot), matching Phase 1 stderr order. Merging them into
	// one index-order loop would change single-in FailedIndex and stderr (I3).
	for i := 0; i < m.N; i++ {
		if shards[i] == nil && slotReason[i] == 1 {
			failed = append(failed, i)
		}
	}
	emit(digestLines, "failed digest at index %d")
	for i := 0; i < m.N; i++ {
		if shards[i] == nil && slotReason[i] == 2 {
			failed = append(failed, i)
		}
	}
	return shards, failed, missing, nil
}
