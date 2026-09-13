package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestCiphertextLengthMatchesOnDisk(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

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
			plain := make([]byte, tt.size)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}

			path := filepath.Join(t.TempDir(), "ciphertext")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			n, err := Encrypt(f, bytes.NewReader(plain), id.Recipient())
			if cerr := f.Close(); cerr != nil {
				t.Fatal(cerr)
			}
			if err != nil {
				t.Fatal(err)
			}

			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if n != st.Size() {
				t.Fatalf("Encrypt n = %d, on-disk size = %d", n, st.Size())
			}

			ct, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := decryptAge(t, ct, id)
			assertSameBytes(t, got, plain)
		})
	}
}

func TestCountReadAfterClose(t *testing.T) {
	// Close flushes the last STREAM chunk. An empty payload makes that write
	// exactly the 16-byte Poly1305 tag, so a regression that reads n before
	// Close is 16 bytes short.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	dst := &writeRecorder{}
	n, err := Encrypt(dst, bytes.NewReader(nil), id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if dst.last != 16 {
		t.Fatalf("last write = %d bytes, want 16 (Poly1305 tag)", dst.last)
	}
	pre := dst.n - dst.last
	if n != pre+16 {
		t.Fatalf("Encrypt n = %d, want pre-Close %d + 16", n, pre)
	}
	if n != dst.n {
		t.Fatalf("Encrypt n = %d, dst count = %d", n, dst.n)
	}
}

type writeRecorder struct {
	n    int64
	last int64
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.last = int64(len(p))
	w.n += w.last
	return len(p), nil
}

func decryptAge(t *testing.T, ciphertext []byte, id age.Identity) []byte {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("age.Decrypt read: %v", err)
	}
	return got
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
