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
	"testing"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestGroupCandidates(t *testing.T) {
	same := []byte("same-blob")
	other := []byte("other-blob")
	errA := errors.New("unread-a")
	errB := errors.New("unread-b")
	cands := []manifestCandidate{
		{path: "p1", blob: same},
		{path: "e1", err: errA},
		{path: "p2", blob: append([]byte(nil), same...)},
		{path: "e2", err: errB},
		{path: "p3", blob: other},
		{path: "p4", blob: same},
	}
	groups := groupCandidates(cands)
	if len(groups) != 4 {
		t.Fatalf("len(groups) = %d, want 4", len(groups))
	}
	assertGroup(t, groups[0], "p1", []string{"p1", "p2", "p4"}, nil)
	assertGroup(t, groups[1], "e1", []string{"e1"}, errA)
	assertGroup(t, groups[2], "e2", []string{"e2"}, errB)
	assertGroup(t, groups[3], "p3", []string{"p3"}, nil)
}

func assertGroup(t *testing.T, g manifestGroup, rep string, paths []string, err error) {
	t.Helper()
	if g.rep.path != rep {
		t.Fatalf("rep.path = %q, want %q", g.rep.path, rep)
	}
	if !errors.Is(g.rep.err, err) && (g.rep.err == nil || err == nil || g.rep.err.Error() != err.Error()) {
		t.Fatalf("rep.err = %v, want %v", g.rep.err, err)
	}
	if len(g.paths) != len(paths) {
		t.Fatalf("paths = %v, want %v", g.paths, paths)
	}
	for i := range paths {
		if g.paths[i] != paths[i] {
			t.Fatalf("paths = %v, want %v", g.paths, paths)
		}
	}
}

func TestDecryptsEqualDistinctBlobs(t *testing.T) {
	restore, split := splitFixture(t)
	src := split.OutDir
	dirs := []string{src, cloneSplitDir(t, src, split.N), cloneSplitDir(t, src, split.N)}
	c := countOpens(t)
	opts := restore
	opts.InDirs = dirs
	if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	if c.n != 1 {
		t.Fatalf("decrypts = %d, want 1", c.n)
	}

	c.n = 0
	opts.InDirs = []string{src}
	opts.OutPath = filepath.Join(t.TempDir(), "one.bin")
	if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	if c.n != 1 {
		t.Fatalf("one-dir decrypts = %d, want 1", c.n)
	}
}

func TestThreeDirsTwoBlobsCostTwoDecrypts(t *testing.T) {
	restore, split := splitFixture(t)
	src := split.OutDir
	dirB := cloneSplitDir(t, src, split.N)
	dirC := t.TempDir()
	reseal(t, restore.IdentityPaths[0], filepath.Join(src, "manifest.age"), filepath.Join(dirC, "manifest.age"))
	copyShards(t, src, dirC, split.N)
	c := countOpens(t)
	opts := restore
	opts.InDirs = []string{src, dirB, dirC}
	if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	if c.n != 2 {
		t.Fatalf("decrypts = %d, want 2", c.n)
	}
}

func TestResealedManifestCostsTwoDecrypts(t *testing.T) {
	restore, split := splitFixture(t)
	dirA := split.OutDir
	dirB := t.TempDir()
	reseal(t, restore.IdentityPaths[0], filepath.Join(dirA, "manifest.age"), filepath.Join(dirB, "manifest.age"))
	c := countOpens(t)
	opts := restore
	opts.InDirs = []string{dirA, dirB}
	if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	if c.n != 2 {
		t.Fatalf("decrypts = %d, want 2 (distinct blobs still both open)", c.n)
	}
}

func TestThreeDirIdenticalCopiesMatchOneDirInteractions(t *testing.T) {
	skipWindows(t)
	bundle, shards := v2PluginShardSet(t)
	one := observeOpen(t)
	if _, err := Verify(context.Background(), VerifyOptions{
		IdentityPaths: []string{bundle},
		InDirs:        []string{shards},
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := *one
	if want < 1 {
		t.Fatalf("one-dir Interactions = %d, want ≥ 1", want)
	}

	dirs := []string{shards, cloneSplitDir(t, shards, 5), cloneSplitDir(t, shards, 5)}
	three := observeOpen(t)
	if _, err := Verify(context.Background(), VerifyOptions{
		IdentityPaths: []string{bundle},
		InDirs:        dirs,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if *three != want {
		t.Fatalf("three-dir Interactions = %d, want %d (same as one dir)", *three, want)
	}
}

func TestErrorCandidatesNamedIndividually(t *testing.T) {
	restore, split := splitFixture(t)
	src := split.OutDir
	man := filepath.Join(src, "manifest.age")
	idPath := restore.IdentityPaths[0]
	keys := loadKeys(t, restore.IdentityPaths)

	rows := []struct {
		name  string
		kinds []string // "ok" or "unread"
	}{
		{name: "one readable two unreadable", kinds: []string{"ok", "unread", "unread"}},
		{name: "two unreadable one readable", kinds: []string{"unread", "unread", "ok"}},
		{name: "unreadable readable unreadable", kinds: []string{"unread", "ok", "unread"}},
		{name: "all unreadable", kinds: []string{"unread", "unread", "unread"}},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			dirs := make([]string, len(tt.kinds))
			var cands []manifestCandidate
			var wantNotes []string
			for i, k := range tt.kinds {
				dirs[i] = t.TempDir()
				copyShards(t, src, dirs[i], split.N)
				p := filepath.Join(dirs[i], "manifest.age")
				switch k {
				case "ok":
					copyFile(t, man, p)
				case "unread":
					if err := os.Mkdir(p, 0o755); err != nil {
						t.Fatal(err)
					}
					wantNotes = append(wantNotes, "manifest.age is not a regular file: "+p)
				default:
					t.Fatalf("kind %q", k)
				}
				blob, err := readManifestBlob(p)
				if errors.Is(err, ErrNoManifest) {
					t.Fatal(err)
				}
				cands = append(cands, manifestCandidate{path: p, blob: blob, err: err})
			}

			assertChooseReplay(t, cands, keys, idPath, true)

			var status bytes.Buffer
			opts := restore
			opts.InDirs = dirs
			opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
			_, err := Restore(context.Background(), opts, &status)
			allUnread := true
			for _, k := range tt.kinds {
				if k == "ok" {
					allUnread = false
					break
				}
			}
			if allUnread {
				if err == nil || err.Error() != wantNotes[0] {
					t.Fatalf("err = %v, want %q", err, wantNotes[0])
				}
				if status.Len() != 0 {
					t.Fatalf("status len = %d, want 0", status.Len())
				}
				return
			}
			if err != nil {
				t.Fatalf("Restore err = %v, want nil", err)
			}
			got := status.String()
			pos := 0
			for _, n := range wantNotes {
				i := strings.Index(got[pos:], n)
				if i < 0 {
					t.Fatalf("status missing %q in -in order; got %q", n, got)
				}
				pos += i + len(n)
			}
		})
	}
}

func TestWrongIdentityFirstErr(t *testing.T) {
	restore, split := splitFixture(t)
	src := filepath.Join(split.OutDir, "manifest.age")
	other := filepath.Join(t.TempDir(), "other.txt")
	if _, err := key.Create(other); err != nil {
		t.Fatal(err)
	}
	wrongKeys := loadKeys(t, []string{other})
	rightKeys := loadKeys(t, restore.IdentityPaths)

	t.Run("three identical", func(t *testing.T) {
		dirs := []string{t.TempDir(), t.TempDir(), t.TempDir()}
		var cands []manifestCandidate
		for _, d := range dirs {
			p := filepath.Join(d, "manifest.age")
			copyFile(t, src, p)
			blob, err := readManifestBlob(p)
			cands = append(cands, manifestCandidate{path: p, blob: blob, err: err})
		}
		assertChooseReplay(t, cands, wrongKeys, other, true)

		c := countOpens(t)
		opts := restore
		opts.IdentityPaths = []string{other}
		opts.InDirs = dirs
		_, err := Restore(context.Background(), opts, io.Discard)
		want := crypt.ErrWrongIdentity.Error() + ": " + other
		if err == nil || err.Error() != want {
			t.Fatalf("err = %v, want %q", err, want)
		}
		if c.n != 1 {
			t.Fatalf("decrypts = %d, want 1", c.n)
		}
	})

	t.Run("unread then copies", func(t *testing.T) {
		// firstErr is the unreadable path, not the identity path: the read
		// error precedes Open, matching today's assignment order.
		unread := t.TempDir()
		copyShards(t, split.OutDir, unread, split.N)
		up := filepath.Join(unread, "manifest.age")
		if err := os.Mkdir(up, 0o755); err != nil {
			t.Fatal(err)
		}
		d2, d3 := t.TempDir(), t.TempDir()
		copyFile(t, src, filepath.Join(d2, "manifest.age"))
		copyFile(t, src, filepath.Join(d3, "manifest.age"))
		cands := gatherFrom(t, []string{unread, d2, d3})
		assertChooseReplay(t, cands, wrongKeys, other, true)
		assertChooseReplay(t, cands, rightKeys, restore.IdentityPaths[0], true)
	})
}

func TestMixedV1V2ConflictingManifests(t *testing.T) {
	bundle, v1Dir, v2Dir := mixedV1V2(t)
	opened := 0
	testAtLoadShard = func(string) { opened++ }
	t.Cleanup(func() { testAtLoadShard = nil })

	c := countOpens(t)
	_, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{bundle},
		InDirs:        []string{v1Dir, v2Dir},
		OutPath:       filepath.Join(t.TempDir(), "out.bin"),
	}, io.Discard)
	if !errors.Is(err, ErrConflictingManifests) {
		t.Fatalf("errors.Is(., ErrConflictingManifests) = false, err=%v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "these directories hold manifests from different splits") {
		t.Fatalf("err = %v, want mixed-version message", err)
	}
	if strings.Contains(err.Error(), "describe different shard sets") {
		t.Fatalf("err used the same-version wording: %v", err)
	}
	if opened != 0 {
		t.Fatalf("opened %d shards, want 0", opened)
	}
	if c.n != 2 {
		t.Fatalf("decrypts = %d, want 2", c.n)
	}
}

func TestV1RepresentativeConsultsNoPin(t *testing.T) {
	bundle, v1Dir, v2Dir := mixedV1V2(t)
	dirs, err := resolveInDirs([]string{v1Dir, v2Dir})
	if err != nil {
		t.Fatal(err)
	}
	cands, _ := gatherManifests(dirs)
	keys := loadKeys(t, []string{bundle})
	var events []string
	src := &tracingMAC{inner: keys, events: &events}
	op := &tracingOpener{inner: keys, events: &events}
	_, err = chooseManifest(groupCandidates(cands), src, op, bundle, true, io.Discard)
	if !errors.Is(err, ErrConflictingManifests) {
		t.Fatalf("errors.Is(., ErrConflictingManifests) = false, err=%v", err)
	}
	want := []string{
		"decrypt",
		"keyid 1 0",
		"keyfor 1 0",
		"decrypt",
		"keyid 2 1",
		"keyfor 2 1",
	}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func countOpens(t *testing.T) *countingOpener {
	t.Helper()
	c := &countingOpener{}
	testWrapManifestOpener = func(inner manifest.Opener) manifest.Opener {
		c.inner = inner
		return c
	}
	t.Cleanup(func() { testWrapManifestOpener = nil })
	return c
}

func observeOpen(t *testing.T) *int {
	t.Helper()
	n := new(int)
	*n = -1
	ObserveOpenInteractions = func(got int) { *n = got }
	t.Cleanup(func() { ObserveOpenInteractions = nil })
	return n
}

func loadKeys(t *testing.T, paths []string) *key.Set {
	t.Helper()
	keys, err := key.LoadSet(paths, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Zero)
	return keys
}

func gatherFrom(t *testing.T, inDirs []string) []manifestCandidate {
	t.Helper()
	dirs, err := resolveInDirs(inDirs)
	if err != nil {
		t.Fatal(err)
	}
	cands, _ := gatherManifests(dirs)
	return cands
}

// chooseManifestEach is the pre-dedup loop: one group per candidate. Replay
// must match it byte-for-byte on firstErr and flushed notes.
func chooseManifestEach(cands []manifestCandidate, src manifest.MACKeySource, op manifest.Opener, identityPath string, multi bool, status io.Writer) (*manifest.Manifest, error) {
	groups := make([]manifestGroup, 0, len(cands))
	for _, c := range cands {
		groups = append(groups, manifestGroup{rep: c, paths: []string{c.path}})
	}
	return chooseManifest(groups, src, op, identityPath, multi, status)
}

func assertChooseReplay(t *testing.T, cands []manifestCandidate, keys *key.Set, idPath string, multi bool) {
	t.Helper()
	var wantStatus, gotStatus bytes.Buffer
	_, wantErr := chooseManifestEach(cands, keys, keys, idPath, multi, &wantStatus)
	_, gotErr := chooseManifest(groupCandidates(cands), keys, keys, idPath, multi, &gotStatus)
	if (wantErr == nil) != (gotErr == nil) {
		t.Fatalf("err grouped=%v ungrouped=%v", gotErr, wantErr)
	}
	if wantErr != nil && gotErr.Error() != wantErr.Error() {
		t.Fatalf("err = %q, want %q", gotErr.Error(), wantErr.Error())
	}
	if gotStatus.String() != wantStatus.String() {
		t.Fatalf("status =\n%q\nwant\n%q", gotStatus.String(), wantStatus.String())
	}
}

func mixedV1V2(t *testing.T) (bundle, v1Dir, v2Dir string) {
	t.Helper()
	paper, paperRec := mustNativeID(t)
	bundle = filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{paper},
		Recipients:    []string{paperRec},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	in1 := filepath.Join(t.TempDir(), "in1.bin")
	if err := os.WriteFile(in1, []byte("v1-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	v1Dir = t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: paper,
		InPath:       in1,
		OutDir:       v1Dir,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	in2 := filepath.Join(t.TempDir(), "in2.bin")
	if err := os.WriteFile(in2, []byte("v2-payload-xx"), 0o600); err != nil {
		t.Fatal(err)
	}
	v2Dir = t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in2,
		OutDir:       v2Dir,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	return bundle, v1Dir, v2Dir
}

func v2PluginShardSet(t *testing.T) (bundle, shards string) {
	t.Helper()
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
	rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	bundle = filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{stub},
		Recipients:    []string{rec},
		OutPath:       bundle,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("v2-plugin-set"), 0o600); err != nil {
		t.Fatal(err)
	}
	shards = t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	return bundle, shards
}

type tracingMAC struct {
	inner  manifest.MACKeySource
	events *[]string
}

func (t *tracingMAC) KeyIDFor(version, macSource uint32) ([]byte, error) {
	*t.events = append(*t.events, fmt.Sprintf("keyid %d %d", version, macSource))
	return t.inner.KeyIDFor(version, macSource)
}

func (t *tracingMAC) KeyFor(version, macSource uint32) ([]byte, error) {
	*t.events = append(*t.events, fmt.Sprintf("keyfor %d %d", version, macSource))
	return t.inner.KeyFor(version, macSource)
}

type tracingOpener struct {
	inner  manifest.Opener
	events *[]string
}

func (t *tracingOpener) DecryptBytes(blob []byte) ([]byte, error) {
	*t.events = append(*t.events, "decrypt")
	return t.inner.DecryptBytes(blob)
}
