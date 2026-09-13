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
	"io"
	"math"

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
	ErrWrongSliceLength   = errors.New("reconstruct slice length must equal n")
	ErrOutSizeRange       = errors.New("join outSize must be non-negative and fit in int")
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

// Reconstruct asserts len(shards) == n, counts usable shards itself, and
// returns *TooFewShardsError below k before calling the library. FR-15, FR-16.
// It uses ReconstructData (data shards only); the library Reconstruct rebuilds
// parity that Join never reads.
func (e *Encoder) Reconstruct(shards [][]byte) error {
	if len(shards) != e.n {
		return ErrWrongSliceLength
	}
	have := Usable(shards)
	if have < e.k {
		return &TooFewShardsError{Need: e.k, Have: have}
	}
	if err := e.enc.ReconstructData(shards); err != nil {
		// ErrTooFewShards also means "wrong length, including too many"; never let it escape.
		if errors.Is(err, reedsolomon.ErrTooFewShards) {
			return &TooFewShardsError{Need: e.k, Have: have}
		}
		return fmt.Errorf("reedsolomon: %w", err)
	}
	return nil
}

// Join narrows outSize to int with an explicit range check and calls the
// library's Join, which reads only shards[:k]. A data shard with len==0
// (Erase or absent) fails closed: Reconstruct must run first. FR-17.
func (e *Encoder) Join(dst io.Writer, shards [][]byte, outSize int64) error {
	if outSize < 0 || outSize > int64(math.MaxInt) {
		return ErrOutSizeRange
	}
	if len(shards) != e.n {
		return ErrWrongSliceLength
	}
	have := Usable(shards)
	if have < e.k {
		return &TooFewShardsError{Need: e.k, Have: have}
	}
	// Library Join treats only nil as missing. Erase uses [:0] to donate the
	// buffer, which Join would take as a zero-length data shard and emit
	// shifted bytes. Fail closed unless every data shard has been filled.
	for i := 0; i < e.k; i++ {
		if len(shards[i]) == 0 {
			return fmt.Errorf("reedsolomon: %w", reedsolomon.ErrReconstructRequired)
		}
	}
	if err := e.enc.Join(dst, shards, int(outSize)); err != nil {
		if errors.Is(err, reedsolomon.ErrTooFewShards) {
			return &TooFewShardsError{Need: e.k, Have: have}
		}
		return fmt.Errorf("reedsolomon: %w", err)
	}
	return nil
}

// Erase marks index i as an erasure. A present-but-corrupt shard is truncated
// to shards[i][:0], donating its buffer back to the reconstructor; an absent
// shard has no buffer and stays nil. Both are len == 0, which is what the
// library reads. FR-14.
func Erase(shards [][]byte, i int) {
	if shards[i] != nil {
		shards[i] = shards[i][:0]
	}
}

// Usable counts entries with len > 0. nil and [:0] are identical. FR-16.
func Usable(shards [][]byte) int {
	n := 0
	for _, s := range shards {
		if len(s) > 0 {
			n++
		}
	}
	return n
}

// TooFewShardsError is a type, not a sentinel: FR-26 needs the two counts in
// the message, and pipeline branches on Have == 0 for the stale-manifest
// diagnosis.
type TooFewShardsError struct{ Need, Have int }

func (e *TooFewShardsError) Error() string {
	return fmt.Sprintf("need at least %d usable shards, have %d", e.Need, e.Have)
}
