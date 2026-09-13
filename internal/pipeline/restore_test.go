package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestRestoreRoundTripLarge(t *testing.T) {
	assertRestoreRoundTrip(t, 1<<20)
}

func TestRestoreRoundTripEmpty(t *testing.T) {
	assertRestoreRoundTrip(t, 0)
}

func TestRestoreDestinationMode(t *testing.T) {
	restore, _ := splitFixture(t)
	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm = %04o, want 0600", got)
	}
	assertPathAbsent(t, restore.OutPath+".partial")
}

func TestMidCopyErrorLeavesNothing(t *testing.T) {
	restore, _ := splitFixture(t)
	testWrapDst = func(w io.Writer) io.Writer {
		return &failAfterN{w: w, left: 1, err: errInjectedCopy}
	}
	t.Cleanup(func() { testWrapDst = nil })

	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, errInjectedCopy) {
		t.Fatalf("errors.Is(., injected copy) = false")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestFailedRestoreLeavesExistingOutUntouched(t *testing.T) {
	restore, _ := splitFixture(t)
	want := make([]byte, 32)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restore.OutPath, want, 0o600); err != nil {
		t.Fatal(err)
	}

	testWrapDst = func(w io.Writer) io.Writer {
		return &failAfterN{w: w, left: 1, err: errInjectedCopy}
	}
	t.Cleanup(func() { testWrapDst = nil })

	_, err := Restore(context.Background(), restore, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want error")
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	assertPathAbsent(t, restore.OutPath+".partial")
}

func TestCleanupFailureJoinsErrors(t *testing.T) {
	restore, _ := splitFixture(t)
	partial := restore.OutPath + ".partial"
	testWrapDst = func(w io.Writer) io.Writer {
		return &failAfterN{w: w, left: 1, err: errInjectedCopy}
	}
	testRemove = func(string) error { return errInjectedRemove }
	t.Cleanup(func() {
		testWrapDst = nil
		testRemove = nil
	})

	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, errInjectedCopy) {
		t.Fatal("errors.Is(., original) = false")
	}
	if !errors.Is(err, errInjectedRemove) {
		t.Fatal("errors.Is(., leftover-file error) = false")
	}
	if !strings.Contains(err.Error(), partial) {
		t.Fatal("error does not name the leftover file")
	}
}

func TestContextCancelMidCopy(t *testing.T) {
	restore, _, _ := splitSized(t, 1<<20)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	testWrapDst = func(w io.Writer) io.Writer {
		return &cancelOnWrite{w: w, cancel: cancel}
	}
	t.Cleanup(func() { testWrapDst = nil })

	_, err := Restore(ctx, restore, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want context cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(., context.Canceled) = false")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestCommittedSetAfterRename(t *testing.T) {
	restore, _ := splitFixture(t)
	testRename = func(string, string) error { return errInjectedRename }
	t.Cleanup(func() { testRename = nil })

	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, errInjectedRename) {
		t.Fatal("errors.Is(., injected rename) = false")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestSyncDirTolerantOfENOTSUP(t *testing.T) {
	testDirSync = func() error { return syscall.ENOTSUP }
	t.Cleanup(func() { testDirSync = nil })

	restore, _ := splitFixture(t)
	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(restore.OutPath); err != nil {
		t.Fatal("out missing after ENOTSUP from syncDir")
	}
	assertPathAbsent(t, restore.OutPath+".partial")

	// No error return: a missing directory cannot fail the restore.
	syncDir(filepath.Join(t.TempDir(), "missing"))
}

func TestJoinUsesManifestLength(t *testing.T) {
	var splitCT []byte
	testAtCiphertext = func(ct []byte) {
		splitCT = bytes.Clone(ct)
	}
	t.Cleanup(func() { testAtCiphertext = nil })

	restore, split := splitFixture(t)
	m := openSplitManifest(t, split)

	called := false
	testAtJoin = func(ct []byte, outSize int64) {
		called = true
		if outSize != m.CiphertextLen {
			t.Errorf("Join outSize = %d, CiphertextLen = %d", outSize, m.CiphertextLen)
		}
		if int64(len(ct)) != m.CiphertextLen {
			t.Errorf("joined len = %d, CiphertextLen = %d", len(ct), m.CiphertextLen)
		}
		assertSameBytes(t, ct, splitCT)
	}
	t.Cleanup(func() { testAtJoin = nil })

	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Join site was not reached")
	}
}

func assertRestoreRoundTrip(t *testing.T, size int) {
	t.Helper()
	restore, _, want := splitSized(t, size)
	rep, err := Restore(context.Background(), restore, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	if rep.PlaintextLen != int64(size) {
		t.Fatalf("PlaintextLen = %d, want %d", rep.PlaintextLen, size)
	}
	assertPathAbsent(t, restore.OutPath+".partial")
}

func splitSized(t *testing.T, size int) (RestoreOptions, SplitOptions, []byte) {
	t.Helper()
	outDir := t.TempDir()
	split := validOpts(t, outDir)
	writeRandomFile(t, split.InPath, size)
	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Split(context.Background(), split, io.Discard); err != nil {
		t.Fatal(err)
	}
	return RestoreOptions{
		IdentityPath: split.IdentityPath,
		InDir:        outDir,
		OutPath:      filepath.Join(t.TempDir(), "out.bin"),
	}, split, want
}

var (
	errInjectedCopy   = errors.New("injected mid-copy error")
	errInjectedRename = errors.New("injected rename failure")
	errInjectedRemove = errors.New("injected remove failure")
)

type failAfterN struct {
	w    io.Writer
	left int
	err  error
}

func (f *failAfterN) Write(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, f.err
	}
	if len(p) > f.left {
		p = p[:f.left]
	}
	n, err := f.w.Write(p)
	f.left -= n
	if err != nil {
		return n, err
	}
	if f.left <= 0 {
		return n, f.err
	}
	return n, nil
}

type cancelOnWrite struct {
	w      io.Writer
	cancel context.CancelFunc
}

func (c *cancelOnWrite) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.cancel()
	return n, err
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
