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
	"slices"
	"testing"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/manifest"
)

// chooseManifestRef is the pre-dedup loop, frozen in this file. Every
// candidate is its own group and is opened in -in order. It must stay a copy:
// walking the code under test one group per candidate would hide a regression
// that affects every group size the same way.
func chooseManifestRef(cands []manifestCandidate, src manifest.MACKeySource, op manifest.Opener, identityPath string, multi bool, status io.Writer) (*manifest.Manifest, error) {
	groups := make([]manifestGroup, 0, len(cands))
	for _, c := range cands {
		groups = append(groups, manifestGroup{rep: c, paths: []string{c.path}})
	}
	var chosen *manifest.Manifest
	var chosenPath string
	var firstErr error
	var notes []error
	noteFail := func(c manifestCandidate, err error) {
		shown := fmt.Errorf("%w: %s", err, c.path)
		returned := shown
		if errors.Is(err, crypt.ErrWrongIdentity) {
			returned = fmt.Errorf("%w: %s", err, identityPath)
		}
		if firstErr == nil {
			firstErr = returned
		}
		notes = append(notes, shown)
	}
	for _, g := range groups {
		if g.rep.err != nil {
			for range g.paths {
				if firstErr == nil {
					firstErr = g.rep.err
				}
				notes = append(notes, g.rep.err)
			}
			continue
		}
		m, err := manifest.Open(g.rep.blob, src, op)
		if err != nil {
			for _, p := range g.paths {
				noteFail(manifestCandidate{path: p, blob: g.rep.blob}, err)
			}
			continue
		}
		if chosen == nil {
			chosen, chosenPath = m, g.rep.path
			continue
		}
		if !bytes.Equal(chosen.MAC, m.MAC) {
			if chosen.Version != m.Version {
				return nil, fmt.Errorf("%w: %s and %s: these directories hold manifests from different splits", ErrConflictingManifests, chosenPath, g.rep.path)
			}
			return nil, fmt.Errorf("%w: %s and %s describe different shard sets", ErrConflictingManifests, chosenPath, g.rep.path)
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

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

type recordingOpener struct {
	inner manifest.Opener
	opens []string
}

func (o *recordingOpener) DecryptBytes(blob []byte) ([]byte, error) {
	sum := sha256.Sum256(blob)
	o.opens = append(o.opens, fmt.Sprintf("%x", sum))
	return o.inner.DecryptBytes(blob)
}

func TestGroupedDiagnosticsFollowCandidateOrder(t *testing.T) {
	restore, split := splitFixture(t)
	blob, err := os.ReadFile(filepath.Join(split.OutDir, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	cands := []manifestCandidate{
		{path: "a/manifest.age", blob: []byte("not an age file")},
		{path: "b/manifest.age", err: errors.New("read failed: b/manifest.age")},
		{path: "c/manifest.age", blob: []byte("not an age file")},
		{path: "d/manifest.age", blob: blob},
	}
	keys := loadKeys(t, restore.IdentityPaths)
	assertChooseReplay(t, cands, keys, restore.IdentityPaths[0], true)
}

// Every interleaving of 1–4 candidates drawn from {malformed, unreadable,
// valid, re-sealed valid, conflicting, other identity} — a repeated letter
// is a byte-identical duplicate — must match the frozen reference's error
// string and stderr, and the grouped pass must open the reference's blobs
// deduped to first occurrence.
func TestGroupedReplayMatchesUngroupedReference(t *testing.T) {
	restore, split := splitFixture(t)
	idPath := restore.IdentityPaths[0]
	man := filepath.Join(split.OutDir, "manifest.age")
	read := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid := read(man)
	resealed := filepath.Join(t.TempDir(), "manifest.age")
	reseal(t, idPath, man, resealed)
	in2 := filepath.Join(t.TempDir(), "in2.bin")
	if err := os.WriteFile(in2, []byte("a different payload entirely"), 0o600); err != nil {
		t.Fatal(err)
	}
	d2 := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: split.IdentityPath, InPath: in2, OutDir: d2, K: split.K, N: split.N,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	_, other := splitFixture(t)
	blobs := map[byte][]byte{
		'B': []byte("not an age file"),
		'V': valid,
		'R': read(resealed),
		'C': read(filepath.Join(d2, "manifest.age")),
		'W': read(filepath.Join(other.OutDir, "manifest.age")),
	}
	keys := loadKeys(t, restore.IdentityPaths)

	const alphabet = "BUVRCW"
	var seqs []string
	var gen func(prefix string)
	gen = func(prefix string) {
		if len(prefix) > 0 {
			seqs = append(seqs, prefix)
		}
		if len(prefix) == 4 {
			return
		}
		for i := 0; i < len(alphabet); i++ {
			gen(prefix + string(alphabet[i]))
		}
	}
	gen("")
	if len(seqs) != 1554 {
		t.Fatalf("interleavings = %d, want 1554", len(seqs))
	}

	for _, seq := range seqs {
		t.Run(seq, func(t *testing.T) {
			cands := make([]manifestCandidate, len(seq))
			for i := 0; i < len(seq); i++ {
				p := fmt.Sprintf("d%d/manifest.age", i)
				if seq[i] == 'U' {
					cands[i] = manifestCandidate{path: p, err: fmt.Errorf("read failed: %s", p)}
					continue
				}
				cands[i] = manifestCandidate{path: p, blob: blobs[seq[i]]}
			}

			ref := &recordingOpener{inner: keys}
			each := &recordingOpener{inner: keys}
			groupedOp := &recordingOpener{inner: keys}
			var refOut, eachOut, groupedOut bytes.Buffer
			_, refErr := chooseManifestRef(cands, keys, ref, idPath, true, &refOut)
			_, eachErr := chooseManifestEach(cands, keys, each, idPath, true, &eachOut)
			groups, order := groupCandidates(cands)
			_, groupedErr := chooseManifest(groups, order, keys, groupedOp, idPath, true, &groupedOut)
			if errString(eachErr) != errString(refErr) || eachOut.String() != refOut.String() {
				t.Fatalf("singleton: err=%q status=%q, reference err=%q status=%q", errString(eachErr), eachOut.String(), errString(refErr), refOut.String())
			}
			if errString(groupedErr) != errString(refErr) || groupedOut.String() != refOut.String() {
				t.Fatalf("grouped: err=%q status=%q, reference err=%q status=%q", errString(groupedErr), groupedOut.String(), errString(refErr), refOut.String())
			}
			if !slices.Equal(each.opens, ref.opens) {
				t.Fatalf("singleton opens %v, reference %v", each.opens, ref.opens)
			}
			var want []string
			for _, o := range ref.opens {
				if !slices.Contains(want, o) {
					want = append(want, o)
				}
			}
			if !slices.Equal(groupedOp.opens, want) {
				t.Fatalf("grouped opens %v, want first occurrences %v of reference %v", groupedOp.opens, want, ref.opens)
			}
		})
	}
}
