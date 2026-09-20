//go:build unix

package key

import (
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

func TestCreateModeUmask0022(t *testing.T) {
	withUmask(t, 0o022)
	assertCreateMode600(t)
}

func TestCreateModeUmask0077(t *testing.T) {
	withUmask(t, 0o077)
	assertCreateMode600(t)
}

func assertCreateMode600(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := Create(path); err != nil {
		t.Fatal(err)
	}
	assertMode600(t, path)
}

func TestWriteNewModeUmask0022(t *testing.T) {
	withUmask(t, 0o022)
	assertWriteNewMode600(t)
}

func TestWriteNewModeUmask0077(t *testing.T) {
	withUmask(t, 0o077)
	assertWriteNewMode600(t)
}

func assertWriteNewMode600(t *testing.T) {
	t.Helper()
	b, _ := mustNativeBundle(t)
	path := filepath.Join(t.TempDir(), "bundle.txt")
	if err := WriteNew(path, b); err != nil {
		t.Fatal(err)
	}
	assertMode600(t, path)
}

func assertMode600(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("%s: mode = %04o, want 0600", path, got)
	}
}
