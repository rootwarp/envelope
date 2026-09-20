package crypt

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

func TestDecryptRoundTrip(t *testing.T) {
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

			var ct bytes.Buffer
			if _, err := Encrypt(&ct, bytes.NewReader(plain), id.Recipient()); err != nil {
				t.Fatal(err)
			}

			var got bytes.Buffer
			n, err := Decrypt(&got, bytes.NewReader(ct.Bytes()), id)
			if err != nil {
				t.Fatal(err)
			}
			if n != int64(tt.size) {
				t.Fatalf("Decrypt n = %d, want %d", n, tt.size)
			}
			assertSameBytes(t, got.Bytes(), plain)
		})
	}
}

func TestDecryptBytesRejectsOversize(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBytes(make([]byte, MaxBytes+1), id)
	if !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("errors.Is(., ErrBlobTooLarge) = false, err=%v", err)
	}
	if got != nil {
		t.Fatalf("DecryptBytes returned %d-byte slice, want nil", len(got))
	}
}

func TestDecryptCanceledReaderIsNotMalformed(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(io.Discard, errReader{context.Canceled}, id)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(., context.Canceled) = false, err=%v", err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestDecryptMalformedDoesNotQuoteInput(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	marker := "AGE-SECRET-KEY-" + "1" + "TESTLEAKMARKER"

	var dst bytes.Buffer
	_, err = Decrypt(&dst, strings.NewReader(marker+"\n"), id)
	if !errors.Is(err, ErrMalformedAge) {
		t.Fatalf("errors.Is(., ErrMalformedAge) = false, err=%v", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("decrypt error quoted private input")
	}
	if dst.Len() != 0 {
		t.Fatalf("Decrypt malformed: dst received %d bytes, want 0", dst.Len())
	}

	got, err := DecryptBytes([]byte(marker+"\n"), id)
	if !errors.Is(err, ErrMalformedAge) {
		t.Fatalf("DecryptBytes: errors.Is(., ErrMalformedAge) = false, err=%v", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("DecryptBytes error quoted private input")
	}
	if got != nil {
		t.Fatalf("DecryptBytes returned %d-byte slice, want nil", len(got))
	}
}

func TestDecryptWrongIdentity(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	var ct bytes.Buffer
	if _, err := Encrypt(&ct, bytes.NewReader(plain), id.Recipient()); err != nil {
		t.Fatal(err)
	}

	var dst bytes.Buffer
	_, err = Decrypt(&dst, bytes.NewReader(ct.Bytes()), other)
	if !errors.Is(err, ErrWrongIdentity) {
		t.Fatalf("Decrypt wrong identity: errors.Is(., ErrWrongIdentity) = false")
	}
	if dst.Len() != 0 {
		t.Fatalf("Decrypt wrong identity: dst received %d bytes, want 0", dst.Len())
	}
}

func TestDecryptBytesAuthenticatesBeforeReturn(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Two STREAM chunks: truncating the last tag fails after the first chunk
	// has already authenticated. A `return io.ReadAll(r)` would leak that prefix.
	plain := make([]byte, 65536+1)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	var ct bytes.Buffer
	if _, err := Encrypt(&ct, bytes.NewReader(plain), id.Recipient()); err != nil {
		t.Fatal(err)
	}
	raw := ct.Bytes()
	if len(raw) < 17 {
		t.Fatalf("ciphertext length %d, want > 16", len(raw))
	}
	truncated := raw[:len(raw)-1]

	got, err := DecryptBytes(truncated, id)
	if err == nil {
		t.Fatal("DecryptBytes(truncated): err = nil, want authentication error")
	}
	if got != nil {
		t.Fatalf("DecryptBytes(truncated) returned %d-byte slice, want nil", len(got))
	}
}

func TestEncryptTwoRecipientsEitherDecrypts(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	var ct bytes.Buffer
	if _, err := Encrypt(&ct, bytes.NewReader(plain), a.Recipient(), b.Recipient()); err != nil {
		t.Fatal(err)
	}

	assertSameBytes(t, decryptAge(t, ct.Bytes(), a), plain)
	assertSameBytes(t, decryptAge(t, ct.Bytes(), b), plain)

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var dst bytes.Buffer
	_, err = Decrypt(&dst, bytes.NewReader(ct.Bytes()), other)
	if !errors.Is(err, ErrWrongIdentity) {
		t.Fatalf("third identity: errors.Is(., ErrWrongIdentity) = false")
	}
	if dst.Len() != 0 {
		t.Fatalf("third identity: dst received %d bytes, want 0", dst.Len())
	}
}

func TestEncryptBytesDecryptBytesRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 64)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptBytes(plain, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBytes(ct, id)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, plain)
}

func TestCloselessCiphertextFailsDecrypt(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Below one STREAM chunk, skipped Close writes only the header. Decrypt
	// then cannot emit authentic plaintext a caller could take as success.
	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// Build ciphertext the wrong way on purpose: write N bytes through age.Encrypt and
	// never Close. The tail — including the final chunk's Poly1305 tag — is missing.
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	// NO w.Close() — this is the bug being guarded against.

	var dst bytes.Buffer
	_, decErr := Decrypt(&dst, bytes.NewReader(buf.Bytes()), id)

	t.Run("decrypt returns an error", func(t *testing.T) {
		if decErr == nil {
			t.Fatal("Decrypt closeless ciphertext: err = nil, want error")
		}
	})
	t.Run("dst is not a valid prefix", func(t *testing.T) {
		got := dst.Bytes()
		if len(got) > 0 && bytes.HasPrefix(payload, got) {
			t.Fatalf("Decrypt wrote %d-byte plaintext prefix, want no plausible plaintext", len(got))
		}
	})

	var full bytes.Buffer
	n, err := Encrypt(&full, bytes.NewReader(payload), id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if n <= int64(buf.Len()) {
		t.Fatalf("Encrypt n = %d, closeless count = %d, want n larger (missing tail)", n, buf.Len())
	}
}

func TestCloseErrorPropagates(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 31)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	L := len(payload)

	// 70 + 98*r + 16 + L + 16*ceil(L/65536), for r recipients and L plaintext bytes.
	// Computed, not guessed: a 250-byte limit against a 31-byte payload produced no error
	// at all, because the total output was only 231 bytes.
	limit := 70 + 98*1 + 16 + L + 16*((L+65535)/65536) - 1

	n, err := Encrypt(&failingWriter{limit: limit}, bytes.NewReader(payload), id.Recipient())
	if err == nil {
		t.Fatalf("Encrypt: err = nil, n = %d; want age close error", n)
	}
	if !strings.Contains(err.Error(), "age close:") {
		t.Fatalf("Encrypt error missing %q in chain", "age close:")
	}
	if n > int64(limit) {
		t.Fatalf("Encrypt n = %d, want <= limit %d (not a complete write)", n, limit)
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

var errWriteLimit = errors.New("write limit")

// failingWriter errors once n reaches limit. A bytes.Buffer never errors, so it
// cannot exercise Encrypt's Close-error path.
type failingWriter struct {
	n, limit int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n >= w.limit {
		return 0, errWriteLimit
	}
	remain := w.limit - w.n
	if len(p) > remain {
		w.n += remain
		return remain, errWriteLimit
	}
	w.n += len(p)
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
