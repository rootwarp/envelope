//go:build unix

package pipeline

// syscall.Umask is process-global, so tests in this package stay serial —
// not just this file. A parallel sibling creating a file under a temporary
// mask fails nondeterministically.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) }) // Cleanup, not defer: still runs after t.Fatal
}

func TestSplitModesUmask0022(t *testing.T) {
	withUmask(t, 0o022)
	assertSplitModes(t)
}

func TestSplitModesUmask0077(t *testing.T) {
	withUmask(t, 0o077)
	assertSplitModes(t)
}

func assertSplitModes(t *testing.T) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	opts := validOpts(t, out)
	if _, err := Split(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	assertPerm(t, out, 0o700)
	for i := 0; i < opts.N; i++ {
		assertPerm(t, filepath.Join(out, shardFileName(i)), 0o644)
	}
	assertPerm(t, filepath.Join(out, "manifest.age"), 0o644)
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s: mode = %04o, want %04o", path, got, want)
	}
}
