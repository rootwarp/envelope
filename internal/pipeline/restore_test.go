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

	"filippo.io/age"

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
	testWrapDst = func(_ context.Context, w io.Writer) io.Writer {
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

	testWrapDst = func(_ context.Context, w io.Writer) io.Writer {
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
	testWrapDst = func(_ context.Context, w io.Writer) io.Writer {
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
	testWrapDst = func(_ context.Context, w io.Writer) io.Writer {
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
}

func TestSyncDirEIOFailsAfterCommit(t *testing.T) {
	testDirSync = func() error { return syscall.EIO }
	t.Cleanup(func() { testDirSync = nil })

	restore, _, want := splitSized(t, 4096)
	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, ErrDirSync) {
		t.Fatalf("errors.Is(., ErrDirSync) = false, err=%v", err)
	}
	got, rerr := os.ReadFile(restore.OutPath)
	if rerr != nil {
		t.Fatal("out missing after directory-sync failure")
	}
	assertSameBytes(t, got, want)
	assertPathAbsent(t, restore.OutPath+".partial")
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

func TestRestoreWithTwoShardsDeleted(t *testing.T) {
	restore, _, want := splitSized(t, 1<<20)
	removeShardFiles(t, restore.InDir, 3, 4)

	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestRestoreWithThreeShardsDeleted(t *testing.T) {
	restore, _, _ := splitSized(t, 4096)
	removeShardFiles(t, restore.InDir, 0, 1, 2)

	_, err := Restore(context.Background(), restore, io.Discard)
	assertTooFewShards(t, err, 3, 2)
	assertPathAbsent(t, restore.OutPath)
	assertPathAbsent(t, restore.OutPath+".partial")
}

func TestRestoreFromNonContiguousSurvivors(t *testing.T) {
	restore, _, want := splitSized(t, 1<<20)
	removeShardFiles(t, restore.InDir, 1, 3)

	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestRestoreDirectoryShardIsUnusable(t *testing.T) {
	restore, _, want := splitSized(t, 1<<20)
	path := filepath.Join(restore.InDir, shardFileName(4))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	var status bytes.Buffer
	rep, err := Restore(context.Background(), restore, &status)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	if rep == nil || len(rep.FailedIndex) != 1 || rep.FailedIndex[0] != 4 {
		t.Fatalf("FailedIndex = %v, want [4]", rep.FailedIndex)
	}
	if !strings.Contains(status.String(), "unusable shard at index 4") {
		t.Fatalf("status %q missing unusable line", status.String())
	}
}

func TestRestoreCanceledDuringShardScan(t *testing.T) {
	restore, _ := splitFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Restore(ctx, restore, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(., context.Canceled) = false, err=%v", err)
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestRestoreWithOneCorruptShard(t *testing.T) {
	restore, _, want := splitSized(t, 1<<20)
	const idx, offset = 2, 0
	flipFileByte(t, filepath.Join(restore.InDir, shardFileName(idx)), offset)

	rep, err := Restore(context.Background(), restore, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	if rep == nil {
		t.Fatal("report is nil")
	}
	if len(rep.FailedIndex) != 1 || rep.FailedIndex[0] != idx {
		t.Fatalf("FailedIndex = %v, want [%d]", rep.FailedIndex, idx)
	}
}

func TestRestoreWithThreeCorruptShards(t *testing.T) {
	restore, _, _ := splitSized(t, 4096)
	const offset = 0
	for _, i := range []int{0, 1, 2} {
		flipFileByte(t, filepath.Join(restore.InDir, shardFileName(i)), offset)
	}

	_, err := Restore(context.Background(), restore, io.Discard)
	assertTooFewShards(t, err, 3, 2)
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestRestoreWrongIdentityEndToEnd(t *testing.T) {
	restore, _, _ := splitSized(t, 4096)
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

func TestRestoreTamperedMACEndToEnd(t *testing.T) {
	restore, _, _ := splitSized(t, 4096)
	// Reconstruction is the first step that could emit plaintext; it must not run.
	reconstructed := false
	testAtReconstruct = func([][]byte) { reconstructed = true }
	t.Cleanup(func() { testAtReconstruct = nil })

	p := filepath.Join(restore.InDir, "manifest.age")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	flipFileByte(t, p, int(fi.Size())/2)

	_, err = Restore(context.Background(), restore, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want error")
	}
	if reconstructed {
		t.Fatal("reconstruction ran")
	}
	assertNoOutOrPartial(t, restore.OutPath)
}

func TestForgottenCloseFailsRestore(t *testing.T) {
	// With Close skipped the counted ciphertext length is ALSO short, so the manifest is
	// self-consistent and every digest matches. age.Decrypt reaches the payload, emits
	// 196,608 bytes, and THEN returns "unexpected EOF" from the copy. The restore fails
	// ONLY because that copy error is propagated. An implementation that swallowed it
	// would write 196,608 bytes of genuine plaintext to .partial and rename it — a silent
	// partial-secret restore.

	outDir := t.TempDir()
	split := validOpts(t, outDir)
	id, err := key.Load(split.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}

	// 200000 bytes flush three 64KiB STREAM chunks; Close would have written the 3392-byte tail.
	payload := make([]byte, 200000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// Build ciphertext the wrong way on purpose: write N bytes through age.Encrypt and
	// never Close. The tail — including the final chunk's Poly1305 tag — is missing.
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	// NO w.Close() — this is the bug being guarded against.

	testInjectCiphertext = func() []byte { return ct.Bytes() }
	t.Cleanup(func() { testInjectCiphertext = nil })

	if _, err := Split(context.Background(), split, io.Discard); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(t.TempDir(), "out.bin")
	_, restoreErr := Restore(context.Background(), RestoreOptions{
		IdentityPath: split.IdentityPath,
		InDir:        outDir,
		OutPath:      outPath,
	}, io.Discard)

	t.Run("restore returns an error", func(t *testing.T) {
		if restoreErr == nil {
			t.Fatal("err = nil, want error")
		}
	})
	t.Run("neither -out nor .partial exists", func(t *testing.T) {
		assertNoOutOrPartial(t, outPath)
	})
}

func TestRestoreMarkerNeverOnDiskOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *RestoreOptions)
	}{
		{
			name: "three shards deleted",
			mutate: func(t *testing.T, restore *RestoreOptions) {
				removeShardFiles(t, restore.InDir, 0, 1, 2)
			},
		},
		{
			name: "three corrupt shards",
			mutate: func(t *testing.T, restore *RestoreOptions) {
				for _, i := range []int{0, 1, 2} {
					flipFileByte(t, filepath.Join(restore.InDir, shardFileName(i)), 0)
				}
			},
		},
		{
			name: "wrong identity",
			mutate: func(t *testing.T, restore *RestoreOptions) {
				other := filepath.Join(t.TempDir(), "identity.txt")
				if _, err := key.Create(other); err != nil {
					t.Fatal(err)
				}
				restore.IdentityPath = other
			},
		},
		{
			name: "tampered MAC",
			mutate: func(t *testing.T, restore *RestoreOptions) {
				p := filepath.Join(restore.InDir, "manifest.age")
				fi, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				flipFileByte(t, p, int(fi.Size())/2)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, marker := splitMarkedRestore(t)
			tc.mutate(t, &restore)
			_, err := Restore(context.Background(), restore, io.Discard)
			if err == nil {
				t.Fatal("err = nil, want error")
			}
			assertNoOutOrPartial(t, restore.OutPath)
			assertMarkerAbsentUnder(t, restore.InDir, marker)
			assertMarkerAbsentUnder(t, filepath.Dir(restore.OutPath), marker)
		})
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

func removeShardFiles(t *testing.T, dir string, indices ...int) {
	t.Helper()
	for _, i := range indices {
		if err := os.Remove(filepath.Join(dir, shardFileName(i))); err != nil {
			t.Fatal(err)
		}
	}
}

func flipFileByte(t *testing.T, path string, offset int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset < 0 || offset >= len(b) {
		t.Fatalf("offset %d out of range (len %d)", offset, len(b))
	}
	b[offset] ^= 0x01
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertTooFewShards(t *testing.T, err error, need, have int) {
	t.Helper()
	var tf *erasure.TooFewShardsError
	if !errors.As(err, &tf) {
		t.Fatalf("errors.As(., *TooFewShardsError) = false")
	}
	if tf.Need != need || tf.Have != have {
		t.Fatalf("Need=%d Have=%d, want %d, %d", tf.Need, tf.Have, need, have)
	}
}

func splitMarkedRestore(t *testing.T) (RestoreOptions, []byte) {
	t.Helper()
	marker := make([]byte, 32)
	if _, err := rand.Read(marker); err != nil {
		t.Fatal(err)
	}
	in := make([]byte, 4096)
	if _, err := rand.Read(in); err != nil {
		t.Fatal(err)
	}
	copy(in[1024:], marker)

	outDir := t.TempDir()
	split := validOpts(t, outDir)
	if err := os.WriteFile(split.InPath, in, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Split(context.Background(), split, io.Discard); err != nil {
		t.Fatal(err)
	}
	return RestoreOptions{
		IdentityPath: split.IdentityPath,
		InDir:        outDir,
		OutPath:      filepath.Join(t.TempDir(), "out.bin"),
	}, marker
}

func assertMarkerAbsentUnder(t *testing.T, dir string, marker []byte) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, marker) {
			t.Errorf("marker present in %s", d.Name())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
