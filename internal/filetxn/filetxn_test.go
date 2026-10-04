package filetxn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func writeOwned(t *testing.T, txn *Txn, path, body string) {
	t.Helper()
	f, err := txn.Create(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateExistingOwnsNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	txn := Begin(dir, Options{Remove: func(string) error {
		t.Fatal("Abort removed a path")
		return nil
	}})
	f, err := txn.Create(path, 0o600)
	if f != nil {
		f.Close()
	}
	var pe *os.PathError
	if err == nil || !errors.As(err, &pe) || !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v, want a raw exist PathError", err)
	}
	if txn.Owns(path) {
		t.Fatal("EEXIST owns the path")
	}
	if err := txn.Abort(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "keep" {
		t.Fatalf("file = %q, %v", got, err)
	}
}

func TestCommitCancelRenamesNothing(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "from")
	to := filepath.Join(dir, "to")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	renamed := false
	synced := false
	removed := false
	txn := Begin(dir, Options{
		Rename: func(string, string) error {
			renamed = true
			return errors.New("renamed")
		},
		Remove: func(string) error {
			removed = true
			return errors.New("removed")
		},
		SyncDir: func(string) error {
			synced = true
			return errors.New("synced")
		},
	})
	writeOwned(t, txn, from, "x")
	if !txn.Owns(from) {
		t.Fatal("Create did not own the path")
	}
	err := txn.Commit(ctx, from, to)
	if err != ctx.Err() {
		t.Fatalf("err = %v, want %v", err, ctx.Err())
	}
	if renamed || synced || removed {
		t.Fatal("canceled commit renamed, synced, or removed")
	}
	if _, err := os.Stat(to); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("destination created")
	}
	got, err := os.ReadFile(from)
	if err != nil || string(got) != "x" {
		t.Fatalf("source = %q, %v", got, err)
	}
}

func TestCommitSyncDirFailureStaysCommitted(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "from")
	to := filepath.Join(dir, "to")
	injected := errors.New("dir sync")
	var removed []string
	txn := Begin(dir, Options{
		SyncDir: func(got string) error {
			if got != dir {
				t.Fatalf("SyncDir dir = %s, want %s", got, dir)
			}
			return injected
		},
		Remove: func(name string) error {
			removed = append(removed, name)
			return os.Remove(name)
		},
	})
	writeOwned(t, txn, from, "body")
	err := txn.Commit(context.Background(), from, to)
	if err != injected {
		t.Fatalf("err = %v, want raw dir sync", err)
	}
	if err := txn.Abort(); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("Abort removed %v after a committed sync failure", removed)
	}
	got, err := os.ReadFile(to)
	if err != nil || string(got) != "body" {
		t.Fatalf("committed file = %q, %v", got, err)
	}
	if _, err := os.Lstat(from); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source still present")
	}
}

func TestCommitForeignFrom(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "foreign")
	dest := filepath.Join(dir, "dest")
	owned := filepath.Join(dir, "owned")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	renamed := false
	txn := Begin(dir, Options{Rename: func(string, string) error {
		renamed = true
		return nil
	}})
	writeOwned(t, txn, owned, "owned")
	err := txn.Commit(context.Background(), foreign, dest)
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("errors.Is(., ErrNotOwned) = false: %v", err)
	}
	if renamed {
		t.Fatal("Commit renamed a foreign path")
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("destination created")
	}
	got, err := os.ReadFile(foreign)
	if err != nil || string(got) != "keep" {
		t.Fatalf("foreign = %q, %v", got, err)
	}
	if _, err := os.Stat(owned); err != nil {
		t.Fatal(err)
	}
}

func TestCommitRenameFailureDoesNotAbort(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "from")
	to := filepath.Join(dir, "to")
	injected := errors.New("rename")
	removed := false
	txn := Begin(dir, Options{
		Rename: func(string, string) error { return injected },
		Remove: func(string) error {
			removed = true
			return nil
		},
	})
	writeOwned(t, txn, from, "body")
	err := txn.Commit(context.Background(), from, to)
	if err != injected {
		t.Fatalf("err = %v, want raw rename", err)
	}
	if removed {
		t.Fatal("Commit aborted after a rename failure")
	}
	got, err := os.ReadFile(from)
	if err != nil || string(got) != "body" {
		t.Fatalf("source = %q, %v", got, err)
	}
	if _, err := os.Stat(to); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("destination created")
	}
}

func TestAbortRemovesOwnedInReverseOrder(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "foreign")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(dir, "a"),
		filepath.Join(dir, "b"),
		filepath.Join(dir, "c"),
	}
	var got []string
	txn := Begin(dir, Options{Remove: func(name string) error {
		got = append(got, name)
		return os.Remove(name)
	}})
	for _, path := range paths {
		writeOwned(t, txn, path, "x")
	}
	if _, err := txn.Create(foreign, 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("Create(existing) = %v, want exist", err)
	}
	if err := txn.Abort(); err != nil {
		t.Fatal(err)
	}
	want := []string{paths[2], paths[1], paths[0]}
	if len(got) != len(want) {
		t.Fatalf("removed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("removed %v, want %v", got, want)
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still present", path)
		}
	}
	body, err := os.ReadFile(foreign)
	if err != nil || string(body) != "keep" {
		t.Fatalf("foreign = %q, %v", body, err)
	}
}

func TestAbortJoinsRemovalErrors(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	third := filepath.Join(dir, "third")
	errFirst := errors.New("denied-first")
	errSecond := errors.New("denied-second")
	txn := Begin(dir, Options{Remove: func(name string) error {
		switch name {
		case first:
			return errFirst
		case second:
			return errSecond
		case third:
			return os.ErrNotExist
		default:
			t.Errorf("removed unowned %s", name)
			return nil
		}
	}})
	for _, path := range []string{first, second, third} {
		writeOwned(t, txn, path, "x")
	}
	err := txn.Abort()
	want := fmt.Sprintf("could not remove %s: %s\ncould not remove %s: %s", second, errSecond, first, errFirst)
	if err == nil || err.Error() != want {
		t.Fatalf("err = %q, want %q", err, want)
	}
	if !errors.Is(err, errFirst) || !errors.Is(err, errSecond) {
		t.Fatalf("joined error does not unwrap both failures: %v", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatal("ErrNotExist was joined")
	}
}

func TestSyncDirToleratesUnsupported(t *testing.T) {
	dir := t.TempDir()
	for _, injected := range []error{syscall.EINVAL, syscall.ENOTSUP} {
		txn := Begin(dir, Options{SyncDir: func(string) error { return injected }})
		if err := txn.SyncDir(); err != nil {
			t.Fatalf("SyncDir(%v) = %v, want nil", injected, err)
		}
	}
	txn := Begin(dir, Options{SyncDir: func(string) error { return syscall.EIO }})
	if err := txn.SyncDir(); err != syscall.EIO {
		t.Fatalf("SyncDir = %v, want raw EIO", err)
	}
	if err := Begin(dir, Options{}).SyncDir(); err != nil {
		t.Fatal(err)
	}
}

func TestAbortAfterCommitIsNoop(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "from")
	to := filepath.Join(dir, "to")
	txn := Begin(dir, Options{Remove: func(string) error {
		return errors.New("removed")
	}})
	writeOwned(t, txn, from, "body")
	if err := txn.Commit(context.Background(), from, to); err != nil {
		t.Fatal(err)
	}
	if err := txn.Abort(); err != nil {
		t.Fatalf("Abort after Commit = %v", err)
	}
	got, err := os.ReadFile(to)
	if err != nil || string(got) != "body" {
		t.Fatalf("file = %q, %v", got, err)
	}
}

func TestDoneMakesAbortANoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "direct")
	txn := Begin(dir, Options{Remove: func(string) error {
		return errors.New("removed")
	}})
	writeOwned(t, txn, path, "body")
	txn.Done()
	if err := txn.Abort(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "body" {
		t.Fatalf("file = %q, %v", got, err)
	}
}
