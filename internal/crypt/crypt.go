// Package crypt encrypts readers with age and counts ciphertext bytes that
// actually flowed.
package crypt

import (
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

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	nw, err := c.w.Write(p)
	c.n += int64(nw)
	return nw, err
}
