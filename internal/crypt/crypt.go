// Package crypt encrypts and decrypts readers with age and counts ciphertext
// bytes that actually flowed.
package crypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// Encrypt writes age ciphertext for src to dst and returns the number of
// ciphertext bytes that actually flowed. Named returns are required: n and err
// are both assigned inside the deferred Close.
func Encrypt(dst io.Writer, src io.Reader, r age.Recipient) (n int64, err error) {
	cw := &countingWriter{w: dst} // innermost sink, wrapping dst BEFORE age.Encrypt
	w, aerr := age.Encrypt(cw, r)
	if aerr != nil {
		return 0, aerr
	}
	defer func() {
		if cerr := w.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("age close: %w", cerr) // Close is the last write
		}
		n = cw.n // read the count ONLY after Close: before, it omits the final chunk's 16-byte Poly1305 tag, silently
	}()
	if _, err = io.Copy(w, src); err != nil {
		return 0, err
	}
	return 0, nil
}

// Decrypt writes the plaintext of src to dst. The returned error includes
// payload-chunk authentication failures that surface during the copy, not only
// at header parse.
func Decrypt(dst io.Writer, src io.Reader, id age.Identity) (n int64, err error) {
	r, aerr := age.Decrypt(src, id)
	if aerr != nil {
		return 0, wrapDecryptErr(aerr)
	}
	return io.Copy(dst, r)
}

// EncryptBytes encrypts plaintext in memory for callers that hold a small blob
// (manifest).
func EncryptBytes(plaintext []byte, r age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := Encrypt(&buf, bytes.NewReader(plaintext), r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MaxBytes is the cap for DecryptBytes (manifest bodies). Payload decrypt
// streams to a file and is not subject to this limit.
const MaxBytes = 1 << 20

// ErrBlobTooLarge is returned when a DecryptBytes input or body exceeds MaxBytes.
var ErrBlobTooLarge = errors.New("age blob exceeds size limit")

// DecryptBytes decrypts ciphertext in memory. It returns the plaintext only
// after io.ReadAll succeeds: age authenticates each 64 KiB chunk at Read time,
// so returning earlier would hand the caller unauthenticated bytes.
func DecryptBytes(ciphertext []byte, id age.Identity) ([]byte, error) {
	if int64(len(ciphertext)) > MaxBytes {
		return nil, ErrBlobTooLarge
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, wrapDecryptErr(err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(plain)) > MaxBytes {
		return nil, ErrBlobTooLarge
	}
	return plain, nil
}

// ErrWrongIdentity is returned when no supplied identity matches the file.
var ErrWrongIdentity = errors.New("no identity matched the file")

// ErrMalformedAge is returned for age header/parse failures. age quotes the
// input line; never wrap or return that error.
var ErrMalformedAge = errors.New("malformed age file")

func wrapDecryptErr(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var noMatch *age.NoIdentityMatchError
	if errors.As(err, &noMatch) {
		return ErrWrongIdentity
	}
	return ErrMalformedAge
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	nw, err := c.w.Write(p)
	c.n += int64(nw)
	return nw, err
}
