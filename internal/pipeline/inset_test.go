package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
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
