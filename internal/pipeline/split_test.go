package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/key"
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
	assertNoShardOrManifest(t, out)
}

func TestSplitAcceptsEmptyOutDir(t *testing.T) {
	out := t.TempDir()
	if _, err := Split(context.Background(), validOpts(t, out), io.Discard); err != nil {
		t.Fatal(err)
	}
	assertNoShardOrManifest(t, out)
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
