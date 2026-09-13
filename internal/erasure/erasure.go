// Package erasure constructs Reed–Solomon encoders over opaque bytes
// (ciphertext). A shard is opaque bytes: this package never sees plaintext
// and does not know what a shard means.
//
// Reed–Solomon detects absence, not corruption. A corrupt-but-present shard
// yields Verify → (false, nil), a no-op Reconstruct, and a Join that returns
// nil while emitting wrong bytes. Digests convert corruption into an erasure;
// RS Verify/Reconstruct does not.
package erasure

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/klauspost/reedsolomon"
)

const (
	MaxShards = 256 // FR-7: above this, New silently selects Leopard
	DigestLen = 32
)

type Encoder struct {
	enc  reedsolomon.Encoder
	k, n int
}

var (
	ErrInvalidK           = errors.New("k must be at least 1")
	ErrInvalidN           = errors.New("n must be greater than k")
	ErrTooManyShards      = errors.New("n must not exceed 256")
	ErrShardSizeMultiple  = errors.New("encoder selected a codec with ShardSizeMultiple != 1")
	ErrCiphertextTooShort = errors.New("ciphertext is shorter than k bytes")
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

// Split stripes ciphertext into n shards and returns stripeLen == ceil(len/k).
// It rejects int64(len(ciphertext)) < int64(e.k) with ErrCiphertextTooShort
// rather than passing it to the library, whose ErrShortData is ambiguous. FR-9.
//
// Data shards alias ciphertext. The caller must not mutate ciphertext until
// the shards are consumed; Split does not copy.
func (e *Encoder) Split(ciphertext []byte) ([][]byte, int64, error) {
	if int64(len(ciphertext)) < int64(e.k) {
		return nil, 0, ErrCiphertextTooShort
	}
	shards, err := e.enc.Split(ciphertext)
	if err != nil {
		// Library string names neither k nor the file; never let ErrShortData escape.
		if errors.Is(err, reedsolomon.ErrShortData) {
			return nil, 0, ErrCiphertextTooShort
		}
		return nil, 0, fmt.Errorf("reedsolomon: %w", err)
	}
	if err := e.enc.Encode(shards); err != nil {
		return nil, 0, fmt.Errorf("reedsolomon: %w", err)
	}
	stripeLen := (int64(len(ciphertext)) + int64(e.k) - 1) / int64(e.k)
	return shards, stripeLen, nil
}

// NewDigest returns a SHA-256 hasher for one shard. Pipeline composes it with
// io.MultiWriter so hashing on write costs no extra I/O. FR-8.
func NewDigest() hash.Hash {
	return sha256.New()
}

// Digest is the one-shot SHA-256 of a shard. The result is always DigestLen bytes.
func Digest(shard []byte) []byte {
	sum := sha256.Sum256(shard)
	return sum[:]
}
