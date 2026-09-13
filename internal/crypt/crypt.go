// Package crypt encrypts and decrypts readers with age and counts ciphertext
// bytes that actually flowed.
package crypt

import (
	"bytes"
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
		return 0, wrapIdentityErr(aerr)
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

// DecryptBytes decrypts ciphertext in memory. It returns the plaintext only
// after io.ReadAll succeeds: age authenticates each 64 KiB chunk at Read time,
// so returning earlier would hand the caller unauthenticated bytes.
func DecryptBytes(ciphertext []byte, id age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, wrapIdentityErr(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// ErrWrongIdentity is returned when no supplied identity matches the file.
// It wraps *age.NoIdentityMatchError so callers use errors.Is, never string-match.
var ErrWrongIdentity = errors.New("no identity matched the file")

func wrapIdentityErr(err error) error {
	var noMatch *age.NoIdentityMatchError
	if errors.As(err, &noMatch) {
		return fmt.Errorf("%w: %w", ErrWrongIdentity, err)
	}
	return err
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
