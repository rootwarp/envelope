// Package manifest is a pure format package: fields, macInput, HMAC,
// version dispatch, and no internal imports (D4).
package manifest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
)

const Version uint32 = 1

const (
	DigestLen = 32
	MACLen    = 32
)

// Manifest is the decoded manifest body. Every field that influences restore
// is in this struct and in macInput; nothing else may be read.
type Manifest struct {
	Version       uint32   `json:"version"`
	MACSource     uint32   `json:"mac_source,omitempty"`
	MACKeyID      []byte   `json:"mac_key_id,omitempty"`
	K             int      `json:"k"`
	N             int      `json:"n"`
	CiphertextLen int64    `json:"ciphertext_len"`
	StripeLen     int64    `json:"stripe_len"`
	Digests       [][]byte `json:"digests"` // each exactly 32 bytes; [][]byte, never [][32]byte
	MAC           []byte   `json:"mac"`     // 32 bytes; NOT part of macInput
}

// MACKeySource resolves the HMAC key a manifest names. KeyIDFor is card-free
// and is consulted first; KeyFor may start a plugin process.
type MACKeySource interface {
	KeyIDFor(version, macSource uint32) ([]byte, error)
	KeyFor(version, macSource uint32) ([]byte, error)
}

// Opener decrypts a manifest blob.
type Opener interface {
	DecryptBytes(blob []byte) ([]byte, error)
}

// Sealer encrypts a manifest body.
type Sealer interface {
	EncryptBytes(plaintext []byte) ([]byte, error)
}

// StripeLen is ceil(ciphertextLen / k). Split computes it; Open re-derives
// it and compares, after the MAC.
func StripeLen(ciphertextLen int64, k int) int64 {
	return (ciphertextLen + int64(k) - 1) / int64(k)
}

var (
	ErrUnsupportedVersion = errors.New("unsupported manifest version")
	ErrMalformed          = errors.New("manifest failed shape validation")
	ErrMACMismatch        = errors.New("manifest MAC mismatch")
	ErrInconsistent       = errors.New("authentic manifest is internally inconsistent")
)

// Seal computes the MAC, marshals the body, and encrypts it with s.
func Seal(m *Manifest, macKey []byte, s Sealer) ([]byte, error) {
	in, err := m.macInput()
	if err != nil {
		return nil, err
	}
	m.MAC = hmacSHA256(macKey, in)
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return s.EncryptBytes(body)
}

// Open decrypts blob and verifies it in architecture §5.3 order.
// It returns a *Manifest only when every check passed.
func Open(blob []byte, src MACKeySource, op Opener) (*Manifest, error) {
	body, err := op.DecryptBytes(blob)
	if err != nil {
		return nil, err
	}
	var m Manifest
	// Unknown keys must be inert (FR-11): extra JSON keys are dropped, not rejected.
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	if m.Version != Version {
		return nil, ErrUnsupportedVersion
	}
	if err := m.validateShape(); err != nil {
		return nil, err
	}
	in, err := m.macInput()
	if err != nil {
		return nil, err
	}
	macKey, err := src.KeyFor(m.Version, m.MACSource)
	if err != nil {
		return nil, err
	}
	defer clear(macKey)
	if !hmac.Equal(hmacSHA256(macKey, in), m.MAC) {
		return nil, ErrMACMismatch
	}
	if m.StripeLen != StripeLen(m.CiphertextLen, m.K) {
		return nil, ErrInconsistent
	}
	return &m, nil
}

func hmacSHA256(macKey, in []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(in)
	// HMAC-SHA256 tag width equals the HKDF-derived MAC key.
	return mac.Sum(make([]byte, 0, MACLen))
}

func (m *Manifest) validateShape() error {
	if m.K < 1 || m.N <= m.K || m.N > 256 {
		return ErrMalformed
	}
	// Signed fields must be range-checked before any uint32/uint64 conversion:
	// uint32(-1) wraps, and JSON -1 unmarshals into int64.
	if m.CiphertextLen < 0 || m.StripeLen < 0 {
		return ErrMalformed
	}
	if len(m.Digests) != m.N {
		return ErrMalformed
	}
	for _, d := range m.Digests {
		// The encoding is injective ONLY because every digest is exactly 32 bytes. A 31-byte
		// digest would shift every subsequent one and let (31,33) collide with (32,32). This
		// check is what makes the format unambiguous — it is not defensive tidiness. Do not
		// delete it.
		if len(d) != DigestLen {
			return ErrMalformed
		}
	}
	if len(m.MAC) != MACLen {
		return ErrMalformed
	}
	if m.MACSource != 0 || len(m.MACKeyID) != 0 {
		return ErrMalformed
	}
	return nil
}

// macInput builds the stable binary encoding HMAC sees. validateShape runs first
// so the uint32/uint64 conversions cannot wrap a negative int. Fields are
// appended by hand; a serializer (or a Go int) must never define this layout.
func (m *Manifest) macInput() ([]byte, error) {
	if err := m.validateShape(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 28+32*len(m.Digests))
	b = binary.BigEndian.AppendUint32(b, m.Version)
	b = binary.BigEndian.AppendUint32(b, uint32(m.K))
	b = binary.BigEndian.AppendUint32(b, uint32(m.N))
	b = binary.BigEndian.AppendUint64(b, uint64(m.CiphertextLen))
	b = binary.BigEndian.AppendUint64(b, uint64(m.StripeLen))
	for _, d := range m.Digests {
		b = append(b, d...) // validateShape guarantees len(d) == 32
	}
	return b, nil
}
