// Package erasure constructs Reed–Solomon encoders over opaque bytes
// (ciphertext). It never sees plaintext and does not know what a shard means.
package erasure

import (
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const (
	MaxShards = 256 // FR-7: above this, New silently selects Leopard
)

type Encoder struct {
	enc  reedsolomon.Encoder
	k, n int
}

var (
	ErrInvalidK          = errors.New("k must be at least 1")
	ErrInvalidN          = errors.New("n must be greater than k")
	ErrTooManyShards     = errors.New("n must not exceed 256")
	ErrShardSizeMultiple = errors.New("encoder selected a codec with ShardSizeMultiple != 1")
)

// Validate applies FR-7's rules with no allocation, so the CLI can reject bad
// (k, n) before touching the filesystem.
func Validate(k, n int) error {
	if k < 1 {
		return ErrInvalidK
	}
	if n <= k {
		return ErrInvalidN
	}
	if n > MaxShards {
		return ErrTooManyShards
	}
	return nil
}

// New validates, constructs with no options, and asserts ShardSizeMultiple()==1.
// It branches on err: the Leopard constructor returns a non-nil interface
// wrapping a typed nil, and calling a method on it panics. FR-6, FR-7.
func New(k, n int) (*Encoder, error) {
	if err := Validate(k, n); err != nil {
		return nil, err
	}
	return newEncoder(k, n)
}

func newEncoder(k, n int) (*Encoder, error) {
	enc, err := reedsolomon.New(k, n-k)
	if err != nil {
		return nil, fmt.Errorf("reedsolomon: %w", err)
	}
	ext, ok := enc.(reedsolomon.Extensions)
	if !ok || ext.ShardSizeMultiple() != 1 {
		return nil, ErrShardSizeMultiple
	}
	return &Encoder{enc: enc, k: k, n: n}, nil
}

func (e *Encoder) K() int { return e.k }

func (e *Encoder) N() int { return e.n }
