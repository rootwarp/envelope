package pipeline

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/key"
)

func TestRestoreNoManifest(t *testing.T) {
	restore, split := splitFixture(t)
	if err := os.Remove(filepath.Join(split.OutDir, "manifest.age")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < split.N; i++ {
		if _, err := os.Stat(filepath.Join(split.OutDir, shardFileName(i))); err != nil {
			t.Fatalf("%s missing", shardFileName(i))
		}
	}

	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, ErrNoManifest) {
		t.Fatalf("errors.Is(., ErrNoManifest) = false")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestRestoreWrongIdentity(t *testing.T) {
	restore, _ := splitFixture(t)
	other := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := key.Create(other); err != nil {
		t.Fatal(err)
	}
	restore.IdentityPath = other

	_, err := Restore(context.Background(), restore, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want error")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestRestoreTruncatedManifest(t *testing.T) {
	restore, _ := splitFixture(t)
	p := filepath.Join(restore.InDir, "manifest.age")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 2 {
		t.Fatal("manifest.age too short to truncate")
	}
	if err := os.WriteFile(p, b[:len(b)-1], 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Restore(context.Background(), restore, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want error")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestRestoreTamperedMAC(t *testing.T) {
	restore, _ := splitFixture(t)
	p := filepath.Join(restore.InDir, "manifest.age")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("manifest.age is empty")
	}
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Restore(context.Background(), restore, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want error")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestRestoreLeftoverPartialRefused(t *testing.T) {
	restore, _ := splitFixture(t)
	partial := restore.OutPath + ".partial"
	want := make([]byte, 32)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partial, want, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, ErrPartialExists) {
		t.Fatalf("errors.Is(., ErrPartialExists) = false")
	}
	if !strings.Contains(err.Error(), partial) {
		t.Fatal("error does not name the leftover file")
	}

	got, err := os.ReadFile(partial)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	assertPathAbsent(t, restore.OutPath)
}

func TestShardsAtOriginalIndices(t *testing.T) {
	restore, split := splitFixture(t)
	for _, i := range []int{1, 3} {
		if err := os.Remove(filepath.Join(split.OutDir, shardFileName(i))); err != nil {
			t.Fatal(err)
		}
	}

	called := false
	testAtReconstruct = func(shards [][]byte) {
		called = true
		if len(shards) != split.N {
			t.Errorf("len(shards) = %d, want %d", len(shards), split.N)
		}
		for i := 0; i < split.N; i++ {
			path := filepath.Join(split.OutDir, shardFileName(i))
			want, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				if shards[i] != nil {
					t.Errorf("shards[%d] != nil for absent file", i)
				}
				continue
			}
			if err != nil {
				t.Errorf("read %s: %v", shardFileName(i), err)
				continue
			}
			if shards[i] == nil {
				t.Errorf("shards[%d] = nil, want survivor at written index", i)
				continue
			}
			assertSameBytes(t, shards[i], want)
		}
	}
	t.Cleanup(func() { testAtReconstruct = nil })

	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Reconstruct site was not reached")
	}
}

func TestDigestScreenErases(t *testing.T) {
	restore, split := splitFixture(t)
	const idx = 1
	path := filepath.Join(split.OutDir, shardFileName(idx))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("shard is empty")
	}
	b[0] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	called := false
	testAtReconstruct = func(shards [][]byte) {
		called = true
		if len(shards) != split.N {
			t.Errorf("len(shards) = %d, want %d", len(shards), split.N)
		}
		if shards[idx] == nil {
			t.Errorf("shards[%d] = nil after Erase, want [:0]", idx)
			return
		}
		if len(shards[idx]) != 0 {
			t.Errorf("shards[%d] len = %d after Erase, want 0", idx, len(shards[idx]))
		}
	}
	t.Cleanup(func() { testAtReconstruct = nil })

	rep, err := Restore(context.Background(), restore, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Reconstruct site was not reached")
	}
	if rep == nil {
		t.Fatal("report is nil")
	}
	if len(rep.FailedIndex) != 1 || rep.FailedIndex[0] != idx {
		t.Fatalf("FailedIndex = %v, want [%d]", rep.FailedIndex, idx)
	}
}

func TestTooFewShardsCountedMessage(t *testing.T) {
	restore, split := splitFixture(t)
	for _, i := range []int{0, 1, 2} {
		if err := os.Remove(filepath.Join(split.OutDir, shardFileName(i))); err != nil {
			t.Fatal(err)
		}
	}

	_, err := Restore(context.Background(), restore, io.Discard)
	var tf *erasure.TooFewShardsError
	if !errors.As(err, &tf) {
		t.Fatalf("errors.As(., *TooFewShardsError) = false")
	}
	if tf.Need != 3 || tf.Have != 2 {
		t.Fatalf("Need=%d Have=%d, want 3, 2", tf.Need, tf.Have)
	}
	const want = "need at least 3 usable shards, have 2"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestStaleManifestZeroMatch(t *testing.T) {
	idPath := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := key.Create(idPath); err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(t.TempDir(), "in.bin")
	writeRandomFile(t, inPath, 1024)

	dirA := t.TempDir()
	dirB := t.TempDir()
	opts := SplitOptions{
		IdentityPath: idPath,
		InPath:       inPath,
		OutDir:       dirA,
		K:            3,
		N:            5,
	}
	if _, err := Split(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	stale, err := os.ReadFile(filepath.Join(dirA, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}

	opts.OutDir = dirB
	if _, err := Split(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirB, "manifest.age"), stale, 0o644); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(t.TempDir(), "out.bin")
	_, err = Restore(context.Background(), RestoreOptions{
		IdentityPath: idPath,
		InDir:        dirB,
		OutPath:      outPath,
	}, io.Discard)
	if !errors.Is(err, ErrStaleManifest) {
		t.Fatalf("errors.Is(., ErrStaleManifest) = false")
	}
	assertNoOutOrPartial(t, outPath)
}

func splitFixture(t *testing.T) (RestoreOptions, SplitOptions) {
	t.Helper()
	outDir := t.TempDir()
	split := validOpts(t, outDir)
	if _, err := Split(context.Background(), split, io.Discard); err != nil {
		t.Fatal(err)
	}
	return RestoreOptions{
		IdentityPath: split.IdentityPath,
		InDir:        outDir,
		OutPath:      filepath.Join(t.TempDir(), "out.bin"),
	}, split
}

func assertNoOutOrPartial(t *testing.T, outPath string) {
	t.Helper()
	assertPathAbsent(t, outPath)
	assertPathAbsent(t, outPath+".partial")
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	if err == nil {
		t.Errorf("%s exists", path)
		return
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Lstat %s: %v", path, err)
	}
}
