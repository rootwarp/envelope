package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/klauspost/reedsolomon"

	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

func TestSplitRefusesNonEmptyOutDir(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{name: "unrelated file", file: "notes.txt"},
		{name: "prior manifest.age", file: "manifest.age"},
		{name: "stale shard-07", file: "shard-07"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.file)
			want := make([]byte, 32)
			if _, err := rand.Read(want); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}

			beforeNames, beforeContents := snapshotDir(t, dir)

			_, err := Split(context.Background(), validOpts(t, dir), io.Discard)
			if !errors.Is(err, ErrOutDirNotEmpty) {
				t.Fatalf("errors.Is(., ErrOutDirNotEmpty) = false")
			}
			if !strings.Contains(err.Error(), dir) {
				t.Fatalf("error does not name the directory")
			}

			afterNames, afterContents := snapshotDir(t, dir)
			if len(afterNames) != len(beforeNames) {
				t.Fatalf("listing length changed: got %d want %d", len(afterNames), len(beforeNames))
			}
			for i := range beforeNames {
				if afterNames[i] != beforeNames[i] {
					t.Fatalf("listing changed: got %v want %v", afterNames, beforeNames)
				}
			}
			if len(afterContents) != len(beforeContents) {
				t.Fatalf("new file was written")
			}
			for name, before := range beforeContents {
				got, ok := afterContents[name]
				if !ok {
					t.Fatalf("%s missing after Split", name)
				}
				assertSameBytes(t, got, before)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			assertSameBytes(t, got, want)
		})
	}
}

func TestSplitCreatesMissingOutDir(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	rep, err := Split(context.Background(), validOpts(t, out), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if rep == nil {
		t.Fatal("report is nil")
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatal("out path is not a directory")
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("perm = %04o, want 0700", got)
	}
}

func TestSplitAcceptsEmptyOutDir(t *testing.T) {
	out := t.TempDir()
	if _, err := Split(context.Background(), validOpts(t, out), io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestSplitInvalidKNLeavesNothing(t *testing.T) {
	tests := []struct {
		name string
		k, n int
		want error
	}{
		{name: "k=0", k: 0, n: 5, want: erasure.ErrInvalidK},
		{name: "k=-1", k: -1, n: 5, want: erasure.ErrInvalidK},
		{name: "(k=3,n=2)", k: 3, n: 2, want: erasure.ErrInvalidN},
		{name: "(k=3,n=3)", k: 3, n: 3, want: erasure.ErrInvalidN},
		{name: "n=257", k: 3, n: 257, want: erasure.ErrTooManyShards},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			opts := validOpts(t, out)
			opts.K, opts.N = tt.k, tt.n
			_, err := Split(context.Background(), opts, io.Discard)
			if !errors.Is(err, tt.want) {
				t.Fatalf("errors.Is(., %v) = false", tt.want)
			}
			if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
				if statErr == nil {
					assertNoShardOrManifest(t, out)
				}
				t.Fatal("output directory was created")
			}
		})
	}
}

func TestSplitRejectsBadIdentity(t *testing.T) {
	tests := []struct {
		name  string
		write func(t *testing.T, path string)
		want  error
	}{
		{
			name: "two identities",
			write: func(t *testing.T, path string) {
				a, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				b, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(a.String()+"\n"+b.String()+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: key.ErrNotSingleIdentity,
		},
		{
			name: "zero identities",
			write: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("# comment only\n\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: key.ErrNotSingleIdentity,
		},
		{
			name: "non-X25519",
			write: func(t *testing.T, path string) {
				h, err := age.GenerateHybridIdentity()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(h.String()+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: key.ErrNotX25519,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idPath := filepath.Join(t.TempDir(), "identity.txt")
			tt.write(t, idPath)
			out := filepath.Join(t.TempDir(), "out")
			_, err := Split(context.Background(), SplitOptions{
				IdentityPath: idPath,
				OutDir:       out,
				K:            3,
				N:            5,
			}, io.Discard)
			if !errors.Is(err, tt.want) {
				t.Fatalf("errors.Is(., %v) = false", tt.want)
			}
			if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("output directory was created")
			}
		})
	}
}

func TestSplitDigestsMatchShards(t *testing.T) {
	out := t.TempDir()
	opts := validOpts(t, out)
	if _, err := Split(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	m := openSplitManifest(t, opts)
	if len(m.Digests) != opts.N {
		t.Fatalf("len(digests) = %d, want %d", len(m.Digests), opts.N)
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	mrand.Shuffle(len(entries), func(i, j int) {
		entries[i], entries[j] = entries[j], entries[i]
	})

	seen := 0
	for _, e := range entries {
		name := e.Name()
		if name == "manifest.age" {
			continue
		}
		var i int
		if _, err := fmt.Sscanf(name, "shard-%d", &i); err != nil || name != shardFileName(i) {
			t.Fatalf("unexpected file %s", name)
		}
		if i < 0 || i >= len(m.Digests) {
			t.Fatalf("shard index %d out of range", i)
		}
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(got)
		assertSameBytes(t, m.Digests[i], sum[:])
		seen++
	}
	if seen != opts.N {
		t.Fatalf("shard files = %d, want %d", seen, opts.N)
	}
}

func TestSplitStripeLen(t *testing.T) {
	out := t.TempDir()
	opts := validOpts(t, out)
	rep, err := Split(context.Background(), opts, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	m := openSplitManifest(t, opts)
	want := manifest.StripeLen(rep.CiphertextLen, opts.K)
	if m.StripeLen != want {
		t.Fatalf("manifest stripe_len = %d, want ceil(ct/k) = %d", m.StripeLen, want)
	}
	if rep.StripeLen != want {
		t.Fatalf("report stripe_len = %d, want %d", rep.StripeLen, want)
	}
	for i := 0; i < opts.N; i++ {
		fi, err := os.Stat(filepath.Join(out, shardFileName(i)))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != want {
			t.Fatalf("len(%s) = %d, want %d", shardFileName(i), fi.Size(), want)
		}
	}
}

func TestSplitRecordedLengthMatchesDisk(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"0 B", 0},
		{"1 B", 1},
		{"65535 B", 65535},
		{"65536 B", 65536},
		{"65537 B", 65537},
		{"1 MiB", 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := t.TempDir()
			opts := validOpts(t, out)
			writeRandomFile(t, opts.InPath, tt.size)
			rep, err := Split(context.Background(), opts, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			m := openSplitManifest(t, opts)
			if m.CiphertextLen != rep.CiphertextLen {
				t.Fatalf("manifest ciphertext_len = %d, report = %d", m.CiphertextLen, rep.CiphertextLen)
			}

			var sum int64
			shards := make([][]byte, m.N)
			for i := 0; i < m.N; i++ {
				b, err := os.ReadFile(filepath.Join(out, shardFileName(i)))
				if err != nil {
					t.Fatal(err)
				}
				shards[i] = b
				if i < m.K {
					sum += int64(len(b))
				}
			}
			trimmed := sum
			if trimmed > m.CiphertextLen {
				trimmed = m.CiphertextLen
			}
			if trimmed != m.CiphertextLen {
				t.Fatalf("trimmed data-shard bytes = %d, ciphertext_len = %d", trimmed, m.CiphertextLen)
			}

			enc, err := erasure.New(m.K, m.N)
			if err != nil {
				t.Fatal(err)
			}
			var joined bytes.Buffer
			if err := enc.Join(&joined, shards, m.CiphertextLen); err != nil {
				t.Fatal(err)
			}
			if int64(joined.Len()) != m.CiphertextLen {
				t.Fatalf("joined len = %d, ciphertext_len = %d", joined.Len(), m.CiphertextLen)
			}
		})
	}
}

func TestSplitCiphertextShorterThanK(t *testing.T) {
	out := t.TempDir()
	opts := validOpts(t, out)
	// 0-byte age ciphertext is 200 bytes, so k must exceed that for the
	// architecture's "-k 200 on a small file" case to fire.
	opts.K, opts.N = 201, 202
	if err := os.WriteFile(opts.InPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Split(context.Background(), opts, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want ciphertext shorter than k")
	}
	var ct, k int
	if _, scanErr := fmt.Sscanf(err.Error(), "ciphertext is %d bytes, shorter than k=%d", &ct, &k); scanErr != nil {
		t.Fatal("error does not name byte count and k")
	}
	if k != opts.K {
		t.Fatalf("k in message = %d, want %d", k, opts.K)
	}
	if ct >= opts.K {
		t.Fatalf("named byte count is not shorter than k")
	}
	if errors.Is(err, reedsolomon.ErrShortData) {
		t.Fatal("reedsolomon.ErrShortData in chain")
	}
	if strings.Contains(err.Error(), reedsolomon.ErrShortData.Error()) {
		t.Fatal("reedsolomon.ErrShortData string in chain")
	}
	assertNoShardOrManifest(t, out)
}

func TestSplitManifestWrittenLast(t *testing.T) {
	testFailManifestWrite = func() error {
		return errors.New("injected manifest write failure")
	}
	t.Cleanup(func() { testFailManifestWrite = nil })

	out := t.TempDir()
	opts := validOpts(t, out)
	_, err := Split(context.Background(), opts, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want injected failure")
	}
	if err.Error() != "injected manifest write failure" {
		t.Fatal("err is not the injected failure")
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	shards := 0
	for _, e := range entries {
		name := e.Name()
		if name == "manifest.age" {
			t.Fatal("manifest.age was written")
		}
		if strings.HasPrefix(name, "shard-") {
			shards++
		}
	}
	if shards != opts.N {
		t.Fatalf("shards = %d, want %d", shards, opts.N)
	}
}

func TestSplitShardExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, shardFileName(0))
	want := make([]byte, 32)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 32)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	_, err := writeShard(dir, 0, payload)
	if err == nil {
		t.Fatal("err = nil, want O_EXCL failure")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("errors.Is(., os.ErrExist) = false")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func validOpts(t *testing.T, outDir string) SplitOptions {
	t.Helper()
	idPath := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := key.Create(idPath); err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(inPath, []byte{0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	return SplitOptions{
		IdentityPath: idPath,
		InPath:       inPath,
		OutDir:       outDir,
		K:            3,
		N:            5,
	}
}

func writeRandomFile(t *testing.T, path string, size int) {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openSplitManifest(t *testing.T, opts SplitOptions) *manifest.Manifest {
	t.Helper()
	id, err := key.Load(opts.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := id.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(opts.OutDir, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Open(blob, macKey, id.AgeIdentity())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func snapshotDir(t *testing.T, dir string) ([]string, map[string][]byte) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	contents := make(map[string][]byte, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[e.Name()] = b
	}
	return names, contents
}

func assertNoShardOrManifest(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "shard-") || name == "manifest.age" {
			t.Errorf("output directory contains %s", name)
		}
	}
}

// assertSameBytes compares payloads without ever putting them in the log.
func assertSameBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	off := -1
	for i := 0; i < min(len(got), len(want)); i++ {
		if got[i] != want[i] {
			off = i
			break
		}
	}
	t.Errorf("payload mismatch: len got=%d want=%d, first diff at %d, sha256 got=%x want=%x",
		len(got), len(want), off, sha256.Sum256(got), sha256.Sum256(want))
}
