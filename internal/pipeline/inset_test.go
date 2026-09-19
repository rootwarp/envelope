package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
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
)

// FR-MD-06 I4: identity is os.SameFile, first spelling kept.
func TestResolveInDirsDedup(t *testing.T) {
	dir := t.TempDir()
	x := filepath.Join(dir, "X")
	if err := os.Mkdir(x, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("twice", func(t *testing.T) {
		assertOneGiven(t, []string{x, x}, x)
	})
	t.Run("trailing slash", func(t *testing.T) {
		assertOneGiven(t, []string{x, x + string(os.PathSeparator)}, x)
	})
	t.Run("dot slash", func(t *testing.T) {
		t.Chdir(dir)
		assertOneGiven(t, []string{"X", "./X"}, "X")
	})
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "link-to-X")
		if err := os.Symlink(x, link); err != nil {
			t.Skipf("symlink: %v", err)
		}
		assertOneGiven(t, []string{x, link}, x)
	})
	t.Run("case fold", func(t *testing.T) {
		lower := filepath.Join(dir, "x")
		fiX, err := os.Stat(x)
		if err != nil {
			t.Fatal(err)
		}
		fiLower, err := os.Stat(lower)
		if err != nil || !os.SameFile(fiX, fiLower) {
			t.Skip("filesystem is case-sensitive")
		}
		assertOneGiven(t, []string{x, lower}, x)
	})
}

// FR-MD-06: two directories that share a basename are still two directories.
func TestResolveInDirsSameBasenameNotDeduped(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a", "shards")
	b := filepath.Join(root, "b", "shards")
	if err := os.MkdirAll(a, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}

	dirs, err := resolveInDirs([]string{a, b})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("len(dirs) = %d, want 2; given=%v", len(dirs), givenPaths(dirs))
	}
	if dirs[0].given != a || dirs[1].given != b {
		t.Fatalf("dirs[0].given=%q dirs[1].given=%q, want %q and %q", dirs[0].given, dirs[1].given, a, b)
	}
}

// FR-MD-07 I7: existence check runs for d≥2 before any manifest or shard read.
func TestResolveInDirsExistence(t *testing.T) {
	good := t.TempDir()

	t.Run("nonexistent", func(t *testing.T) {
		given := filepath.Join(t.TempDir(), "missing")
		_, err := resolveInDirs([]string{good, given})
		if err == nil {
			t.Fatal("err = nil, want error")
		}
		want := fmt.Sprintf("-in %s: stat %s: no such file or directory", given, given)
		if err.Error() != want {
			t.Fatalf("err = %q, want %q", err.Error(), want)
		}
	})

	t.Run("not a directory", func(t *testing.T) {
		given := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(given, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := resolveInDirs([]string{good, given})
		if err == nil {
			t.Fatal("err = nil, want error")
		}
		want := fmt.Sprintf("-in %s: not a directory", given)
		if err.Error() != want {
			t.Fatalf("err = %q, want %q", err.Error(), want)
		}
	})

	t.Run("mode 0000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not deny root")
		}
		given := t.TempDir()
		if err := os.Chmod(given, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(given, 0o700) })
		if d, err := os.Open(given); err == nil {
			d.Close()
			t.Skip("process can still open chmod 0000 directory")
		}
		_, err := resolveInDirs([]string{good, given})
		if err == nil {
			t.Fatal("err = nil, want error")
		}
		want := fmt.Sprintf("-in %s: open %s: permission denied", given, given)
		if err.Error() != want {
			t.Fatalf("err = %q, want %q", err.Error(), want)
		}
	})
}

// FR-MD-07 I7: a single -in is not stat'ed, so ErrNoManifest stays the diagnosis.
func TestSingleInDirIsNeverStatted(t *testing.T) {
	const given = "/nonexistent"
	dirs, err := resolveInDirs([]string{given})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("len(dirs) = %d, want 1; given=%v", len(dirs), givenPaths(dirs))
	}
	if dirs[0].given != given {
		t.Fatalf("dirs[0].given = %q, want %q", dirs[0].given, given)
	}
	if dirs[0].info != nil {
		t.Fatalf("dirs[0].info != nil for single -in")
	}
}

func assertOneGiven(t *testing.T, in []string, want string) {
	t.Helper()
	dirs, err := resolveInDirs(in)
	if err != nil {
		t.Fatalf("resolveInDirs(%v): err = %v, want nil", in, err)
	}
	if len(dirs) != 1 {
		t.Fatalf("len(dirs) = %d, want 1; given=%v want %q", len(dirs), givenPaths(dirs), want)
	}
	if dirs[0].given != want {
		t.Fatalf("dirs[0].given = %q, want %q", dirs[0].given, want)
	}
}

func givenPaths(dirs []inDir) []string {
	out := make([]string, len(dirs))
	for i, d := range dirs {
		out[i] = d.given
	}
	return out
}

// reseal decrypts a manifest and re-encrypts the SAME decoded content to the
// same identity. age is randomized, so the blob differs byte-wise while every
// decoded field — and therefore the MAC — is identical. This is the fixture
// FR-MD-03's "byte-differing but content-identical" AC needs.
func reseal(t *testing.T, identityPath, srcManifest, dstManifest string) {
	t.Helper()
	blob, err := os.ReadFile(srcManifest)
	if err != nil {
		t.Fatal(err)
	}
	id, err := key.Load(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Zero()
	macKey, err := id.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(macKey)
	m, err := manifest.Open(blob, macKey, id.AgeIdentity())
	if err != nil {
		t.Fatal(err)
	}
	out, err := manifest.Seal(m, macKey, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(out, blob) {
		t.Fatal("reseal produced a byte-identical blob; the fixture proves nothing")
	}
	if err := os.WriteFile(dstManifest, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyShards(t *testing.T, src, dst string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		copyFile(t, filepath.Join(src, shardFileName(i)), filepath.Join(dst, shardFileName(i)))
	}
}

func openManifest(t *testing.T, identityPath, manPath string) (*key.Identity, []byte, *manifest.Manifest) {
	t.Helper()
	blob, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := key.Load(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := id.ManifestMACKey()
	if err != nil {
		id.Zero()
		t.Fatal(err)
	}
	m, err := manifest.Open(blob, macKey, id.AgeIdentity())
	if err != nil {
		clear(macKey)
		id.Zero()
		t.Fatal(err)
	}
	return id, macKey, m
}

// FR-MD-03 ADR 0010: byte-differing, content-identical manifests are not a conflict.
func TestResealedManifestIsNotAConflict(t *testing.T) {
	restore, split := splitFixture(t)
	dirA := split.OutDir
	dirB := t.TempDir()
	reseal(t, restore.IdentityPath, filepath.Join(dirA, "manifest.age"), filepath.Join(dirB, "manifest.age"))

	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}

	var status bytes.Buffer
	opts := restore
	opts.InDirs = []string{dirA, dirB}
	_, restoreErr := Restore(context.Background(), opts, &status)
	if restoreErr != nil {
		t.Fatalf("Restore err = %v, want nil (status len=%d)", restoreErr, status.Len())
	}
	got, err := os.ReadFile(opts.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	if strings.Contains(status.String(), "conflict") {
		t.Fatalf("status names a conflict; len=%d", status.Len())
	}
}

// FR-MD-03 I5: a conflict is detected before any shard is opened.
func TestConflictingManifests(t *testing.T) {
	restore, split := splitFixture(t)
	dirA := split.OutDir
	dirB := t.TempDir()
	src := filepath.Join(dirA, "manifest.age")
	reseal(t, restore.IdentityPath, src, src)

	id, macKey, m := openManifest(t, restore.IdentityPath, src)
	defer id.Zero()
	defer clear(macKey)
	if len(m.Digests) == 0 || len(m.Digests[0]) == 0 {
		t.Fatalf("digests len = %d", len(m.Digests))
	}
	m.Digests[0] = bytes.Clone(m.Digests[0])
	m.Digests[0][0] ^= 0x01
	altered, err := manifest.Seal(m, macKey, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	bMan := filepath.Join(dirB, "manifest.age")
	if err := os.WriteFile(bMan, altered, 0o600); err != nil {
		t.Fatal(err)
	}

	opened := 0
	testAtLoadShard = func(string) { opened++ }
	t.Cleanup(func() { testAtLoadShard = nil })

	opts := restore
	opts.InDirs = []string{dirA, dirB}
	_, err = Restore(context.Background(), opts, io.Discard)
	if !errors.Is(err, ErrConflictingManifests) {
		t.Fatalf("errors.Is(., ErrConflictingManifests) = false, err=%v", err)
	}
	aMan := src
	if err == nil || !strings.Contains(err.Error(), aMan) || !strings.Contains(err.Error(), bMan) {
		t.Fatalf("err does not name both paths a=%s b=%s", aMan, bMan)
	}
	if opened != 0 {
		t.Fatalf("opened %d shards, want 0", opened)
	}
	assertNoOutOrPartial(t, opts.OutPath)
}

// FR-MD-03 I1: blobs are read before key.Load.
func TestNoManifestPrecedesIdentityLoad(t *testing.T) {
	_, err := Restore(context.Background(), RestoreOptions{
		IdentityPath: filepath.Join(t.TempDir(), "missing-identity.txt"),
		InDirs:       []string{t.TempDir()},
		OutPath:      filepath.Join(t.TempDir(), "out.bin"),
	}, io.Discard)
	if !errors.Is(err, ErrNoManifest) {
		t.Fatalf("errors.Is(., ErrNoManifest) = false")
	}
}

// FR-MD-03 AD-11: both no-manifest suffixes in one test, because the branch is the point.
func TestNoManifestWording(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	out := filepath.Join(t.TempDir(), "out.bin")
	opts := RestoreOptions{
		IdentityPath: filepath.Join(t.TempDir(), "missing-identity.txt"),
		InDirs:       []string{a},
		OutPath:      out,
	}

	_, err := Restore(context.Background(), opts, io.Discard)
	want := fmt.Sprintf("%s: %s", ErrNoManifest, filepath.Join(a, "manifest.age"))
	if err == nil || err.Error() != want {
		t.Fatalf("one dir: err = %v, want %q", err, want)
	}

	opts.InDirs = []string{a, b}
	_, err = Restore(context.Background(), opts, io.Discard)
	want = fmt.Sprintf("%s: searched %s, %s", ErrNoManifest,
		filepath.Join(a, "manifest.age"), filepath.Join(b, "manifest.age"))
	if err == nil || err.Error() != want {
		t.Fatalf("two dirs: err = %v, want %q", err, want)
	}
}

// FR-MD-03 rule 3: a foreign candidate note names its own manifest path, never the identity.
func TestForeignManifestNamesItsOwnPath(t *testing.T) {
	restore, split := splitFixture(t)
	dirA := split.OutDir
	dirB := t.TempDir()

	otherID := filepath.Join(t.TempDir(), "other-identity.txt")
	if _, err := key.Create(otherID); err != nil {
		t.Fatal(err)
	}
	otherIn := filepath.Join(t.TempDir(), "other.bin")
	if err := os.WriteFile(otherIn, []byte{0x01}, 0o600); err != nil {
		t.Fatal(err)
	}
	otherOut := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: otherID,
		InPath:       otherIn,
		OutDir:       otherOut,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	bMan := filepath.Join(dirB, "manifest.age")
	copyFile(t, filepath.Join(otherOut, "manifest.age"), bMan)

	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}

	var status bytes.Buffer
	opts := restore
	opts.InDirs = []string{dirA, dirB}
	if _, err := Restore(context.Background(), opts, &status); err != nil {
		t.Fatalf("Restore err = %v, want nil (status len=%d)", err, status.Len())
	}
	got, err := os.ReadFile(opts.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)

	note := status.String()
	wantNote := crypt.ErrWrongIdentity.Error() + ": " + bMan
	if !strings.Contains(note, wantNote) {
		t.Fatalf("status missing %q; len=%d", wantNote, status.Len())
	}
	if strings.Contains(note, restore.IdentityPath) {
		t.Fatalf("status names identity path %s; len=%d", restore.IdentityPath, status.Len())
	}
}

// FR-MD-03 rule 3: a MAC-failing candidate is reported and is not fatal.
func TestFailingManifestNoteIsNotFatal(t *testing.T) {
	restore, split := splitFixture(t)
	dirA := split.OutDir
	dirB := t.TempDir()
	src := filepath.Join(dirA, "manifest.age")

	id, macKey, m := openManifest(t, restore.IdentityPath, src)
	defer id.Zero()
	clear(macKey)
	if len(m.MAC) == 0 {
		t.Fatal("MAC len = 0")
	}
	m.MAC = bytes.Clone(m.MAC)
	m.MAC[0] ^= 0x01
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := crypt.EncryptBytes(body, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	bMan := filepath.Join(dirB, "manifest.age")
	if err := os.WriteFile(bMan, bad, 0o600); err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}

	var status bytes.Buffer
	opts := restore
	opts.InDirs = []string{dirA, dirB}
	if _, err := Restore(context.Background(), opts, &status); err != nil {
		t.Fatalf("Restore err = %v, want nil (status len=%d)", err, status.Len())
	}
	got, err := os.ReadFile(opts.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)

	wantNote := manifest.ErrMACMismatch.Error() + ": " + bMan
	if !strings.Contains(status.String(), wantNote) {
		t.Fatalf("status missing %q; len=%d", wantNote, status.Len())
	}
}

// FR-MD-03 I2: when nothing authenticates, notes are not flushed.
func TestWrongIdentityBuffersNoNotes(t *testing.T) {
	restore, split := splitFixture(t)
	other := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := key.Create(other); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(split.OutDir, "manifest.age")
	dirs := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	for _, d := range dirs {
		copyFile(t, src, filepath.Join(d, "manifest.age"))
	}

	var status bytes.Buffer
	opts := restore
	opts.IdentityPath = other
	opts.InDirs = dirs
	_, err := Restore(context.Background(), opts, &status)
	want := crypt.ErrWrongIdentity.Error() + ": " + other
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if n := status.Len(); n != 0 {
		t.Fatalf("status len = %d, want 0", n)
	}
	assertNoOutOrPartial(t, opts.OutPath)
}

// FR-MD-03 rules 1, 2 and 5: last-only, all directories, and none.
func TestManifestPresence(t *testing.T) {
	restore, split := splitFixture(t)
	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}
	src := split.OutDir
	man := filepath.Join(src, "manifest.age")

	t.Run("last only", func(t *testing.T) {
		a, b := t.TempDir(), t.TempDir()
		copyShards(t, src, a, split.N)
		copyFile(t, man, filepath.Join(b, "manifest.age"))
		opts := restore
		opts.InDirs = []string{a, b}
		opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
		if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
			t.Fatalf("Restore err = %v, want nil", err)
		}
		got, err := os.ReadFile(opts.OutPath)
		if err != nil {
			t.Fatal(err)
		}
		assertSameBytes(t, got, want)
	})

	t.Run("all directories", func(t *testing.T) {
		a, b := t.TempDir(), t.TempDir()
		copyShards(t, src, a, split.N)
		copyFile(t, man, filepath.Join(a, "manifest.age"))
		copyFile(t, man, filepath.Join(b, "manifest.age"))
		opts := restore
		opts.InDirs = []string{a, b}
		opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
		if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
			t.Fatalf("Restore err = %v, want nil", err)
		}
		got, err := os.ReadFile(opts.OutPath)
		if err != nil {
			t.Fatal(err)
		}
		assertSameBytes(t, got, want)
	})

	t.Run("none", func(t *testing.T) {
		a, b := t.TempDir(), t.TempDir()
		opts := restore
		opts.InDirs = []string{a, b}
		opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
		_, err := Restore(context.Background(), opts, io.Discard)
		if !errors.Is(err, ErrNoManifest) {
			t.Fatalf("errors.Is(., ErrNoManifest) = false, err=%v", err)
		}
		assertNoOutOrPartial(t, opts.OutPath)
	})
}
