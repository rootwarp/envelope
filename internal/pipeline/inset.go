package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/manifest"
)

// ErrConflictingManifests is returned when two -in directories hold manifests
// that both authenticate but disagree: same-version bodies that describe
// different shard sets, or a mixed-version pair from different splits.
var ErrConflictingManifests = errors.New("conflicting manifests")

// inDir is one resolved -in directory. given is exactly what the operator
// typed; every diagnostic is built from it. Identity is st_dev/st_ino via
// os.SameFile, never the string.
type inDir struct {
	given string
	info  os.FileInfo // nil for the single-directory case, which is not stat'ed
}

// resolveInDirs de-duplicates by identity (os.SameFile), not by string, and
// with two or more directories checks each one before anything is read.
// With exactly one directory nothing is checked: Phase 1 surfaces the case as
// ErrNoManifest, and that message stays frozen.
func resolveInDirs(given []string) ([]inDir, error) {
	// This is not an optimisation. Phase 1 surfaces a bad single -in as
	// ErrNoManifest naming the path; an earlier Stat would replace that frozen
	// message. info is legitimately nil; nothing calls SameFile on it.
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
		// Mode 0000 passes Stat; the open is what rejects it.
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

type manifestGroup struct {
	rep   manifestCandidate // first candidate of the group, in -in order
	paths []string          // every path whose blob was byte-identical, in -in order
}

// memberRef is one candidate's position in the grouped lists. Positions exist
// so a missing one cannot be skipped: groupCandidates returns them beside the
// groups, rather than as a field a caller could leave empty.
type memberRef struct {
	group int
	k     int
}

// groupCandidates groups the candidates whose read succeeded by SHA-256 of the
// already-read blob (not a re-read: that would be a TOCTOU the current code
// does not have). Byte-identical blobs decrypt to identical bodies and
// identical MACs, so opening one representative decides for the group.
//
// Three rules make the optimisation unobservable, and each is a bug if missed:
//
//  1. Dedup collapses decryptions, never diagnostics. The representative's
//     outcome is replayed for every path in its group at each path's own
//     position, not group by group, because members of different groups
//     interleave. Buffered stderr notes and firstErr stay byte-identical to
//     opening every copy, which keeps a v1 multi-directory run byte-identical.
//
//  2. Only c.err == nil candidates may be grouped. An error candidate carries
//     a nil or partial blob, and chooseManifest buffers one stderr note per
//     error candidate. Grouping them would stop a three-USB-stick run naming
//     the paths it names today. Error candidates pass through one group each.
//
//  3. Version dispatch and MAC-key resolution happen per representative,
//     after decryption. A blob's version is unknown until it is decrypted, so
//     resolving a key up front is forbidden — it is exactly what would break
//     the lazy KeyFor promise. A v1 representative in a mixed run is
//     opened, and opening it consults no pin and costs no card.
//
// order[i] is candidate i. That slice is the only record of positions.
func groupCandidates(cands []manifestCandidate) ([]manifestGroup, []memberRef) {
	groups := make([]manifestGroup, 0, len(cands))
	order := make([]memberRef, 0, len(cands))
	seen := make(map[[sha256.Size]byte]int, len(cands))
	for _, c := range cands {
		if c.err != nil {
			order = append(order, memberRef{group: len(groups), k: 0})
			groups = append(groups, manifestGroup{rep: c, paths: []string{c.path}})
			continue
		}
		sum := sha256.Sum256(c.blob)
		if i, ok := seen[sum]; ok {
			order = append(order, memberRef{group: i, k: len(groups[i].paths)})
			groups[i].paths = append(groups[i].paths, c.path)
			continue
		}
		seen[sum] = len(groups)
		order = append(order, memberRef{group: len(groups), k: 0})
		groups = append(groups, manifestGroup{rep: c, paths: []string{c.path}})
	}
	if len(order) != len(cands) {
		panic(fmt.Sprintf("groupCandidates: len(order)=%d len(cands)=%d", len(order), len(cands)))
	}
	return groups, order
}

// Two authenticated manifests agree iff their
// MACs are equal: both were verified against the same key, and macInput covers
// exactly the fields that influence restore, so MAC equality is decoded-field
// equality without comparing the randomized .age blobs.
func chooseManifest(groups []manifestGroup, order []memberRef, src manifest.MACKeySource, op manifest.Opener, identityPath string, multi bool, status io.Writer) (*manifest.Manifest, error) {
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

	// len(order) == len(cands). A short order would skip a member; that is a
	// programming error, not a candidate to drop.
	nCands := 0
	for _, g := range groups {
		nCands += len(g.paths)
	}
	if len(order) != nCands {
		panic(fmt.Sprintf("chooseManifest: len(order)=%d len(cands)=%d", len(order), nCands))
	}

	// One lazy pass in -in order. A group is opened at its first member, its
	// representative, and the outcome (open error and the choose-or-conflict
	// decision) is cached so later members only replay noteFail at their own
	// path. Opening every group first would add opens after a conflict
	// return. An optional position field skipped when the group index is
	// negative would drop a member that was never recorded.
	type groupOutcome struct {
		opened bool
		err    error
	}
	outs := make([]groupOutcome, len(groups))
	for _, mb := range order {
		g := groups[mb.group]
		if g.rep.err != nil {
			// readManifestBlob already formatted a path-bearing error.
			// groupCandidates keeps error candidates one group each, so this
			// is one note per failed read, as before.
			if firstErr == nil {
				firstErr = g.rep.err
			}
			notes = append(notes, g.rep.err)
		} else {
			o := &outs[mb.group]
			if !o.opened {
				o.opened = true
				m, err := manifest.Open(g.rep.blob, src, op)
				o.err = err
				if err == nil {
					if chosen == nil {
						chosen, chosenPath = m, g.rep.path
					} else if !bytes.Equal(chosen.MAC, m.MAC) {
						if chosen.Version != m.Version {
							return nil, fmt.Errorf("%w: %s and %s: these directories hold manifests from different splits", ErrConflictingManifests, chosenPath, g.rep.path)
						}
						return nil, fmt.Errorf("%w: %s and %s describe different shard sets", ErrConflictingManifests, chosenPath, g.rep.path)
					}
				}
			}
			if o.err != nil {
				noteFail(manifestCandidate{path: g.paths[mb.k], blob: g.rep.blob}, o.err)
			}
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
// decision. searched[0] is safe because openShardSet rejects empty InDirs.
func noManifestErr(multi bool, searched []string) error {
	if !multi {
		return fmt.Errorf("%w: %s", ErrNoManifest, searched[0])
	}
	return fmt.Errorf("%w: searched %s", ErrNoManifest, strings.Join(searched, ", "))
}

// slotReject is why a slot's first rejected copy was rejected.
// rejectNone is the zero value, so an untouched slot stays unset.
type slotReject uint8

const (
	rejectNone slotReject = iota
	rejectUnusable
	rejectDigest
)

// selectShards is the single selection pass. scanAll makes verify
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
	slotReason := make([]slotReject, m.N)

	for i := 0; i < m.N; i++ {
		present := false
		for _, d := range dirs {
			if shards[i] != nil && !scanAll {
				break
			}
			p := filepath.Join(d.given, shardFileName(i))
			b, read, rerr := loadShard(ctx, p, m.StripeLen)
			if rerr != nil {
				return nil, nil, nil, rerr
			}
			if read == shardAbsent {
				continue
			}
			present = true
			if read == shardUnusable {
				unusableLines = append(unusableLines, reject{i, p})
				if slotReason[i] == rejectNone {
					slotReason[i] = rejectUnusable
				}
				continue
			}
			if !bytes.Equal(erasure.Digest(b), m.Digests[i]) {
				digestLines = append(digestLines, reject{i, p})
				if slotReason[i] == rejectNone {
					slotReason[i] = rejectDigest
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
	// one index-order loop would change single-in FailedIndex and stderr.
	for i := 0; i < m.N; i++ {
		if shards[i] == nil && slotReason[i] == rejectUnusable {
			failed = append(failed, i)
		}
	}
	emit(digestLines, "failed digest at index %d")
	for i := 0; i < m.N; i++ {
		if shards[i] == nil && slotReason[i] == rejectDigest {
			failed = append(failed, i)
		}
	}
	return shards, failed, missing, nil
}
