// Package key generates, writes, and loads age X25519 identities.
package key

import (
	"bufio"
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/key/bech32"
)

const (
	HRP       = "AGE-SECRET-KEY-" // compared case-sensitively, as age does
	ScalarLen = 32
	MACKeyLen = 32

	macSalt = "envelope"
	macInfo = "envelope v1 manifest mac"
)

// Identity is the only holder of the X25519 scalar in the program.
type Identity struct {
	age    *age.X25519Identity
	scalar [ScalarLen]byte
}

func Generate() (*Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return newIdentity(id)
}

// Create generates an identity and writes it with O_EXCL, then Chmod 0600.
// It never truncates an existing file.
func Create(path string) (*Identity, error) {
	id, err := Generate()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrIdentityExists
		}
		return nil, err
	}
	_, werr := io.WriteString(f, id.age.String()+"\n")
	if werr != nil {
		f.Close()
		return nil, werr
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	// os.WriteFile/O_CREATE supply a mode only at creation, so writing over a
	// stale world-readable identity.txt would leave it world-readable. O_EXCL
	// removes that case; keep both.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return id, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil &&
		!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

// Load parses path with age.ParseIdentities and rejects anything that is not
// exactly one *age.X25519Identity, then recovers the scalar.
func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		if nonCommentLines(data) == 0 {
			return nil, ErrNotSingleIdentity
		}
		// age quotes the identity line; never return or wrap that error.
		return nil, ErrInvalidIdentity
	}
	if len(ids) != 1 {
		return nil, ErrNotSingleIdentity
	}
	x25519, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, ErrNotX25519
	}
	return newIdentity(x25519)
}

func (id *Identity) RecipientString() (string, error) {
	return id.age.Recipient().String(), nil
}

func (id *Identity) DecryptBytes(blob []byte) ([]byte, error) {
	return crypt.DecryptBytes(blob, id.age)
}

// DecryptTo streams a payload. open is a function because a reader handed
// to a failed age.Decrypt has already been consumed past the header.
func (id *Identity) DecryptTo(dst io.Writer, open func() io.Reader) (int64, error) {
	return crypt.Decrypt(dst, open(), id.age)
}

func (id *Identity) EncryptBytes(plaintext []byte) ([]byte, error) {
	return crypt.EncryptBytes(plaintext, id.age.Recipient())
}

func (id *Identity) KeyIDFor(version, macSource uint32) ([]byte, error) {
	if version != 1 || macSource != 0 {
		return nil, errMACSourceUnsupported
	}
	return nil, nil
}

func (id *Identity) KeyFor(version, macSource uint32) ([]byte, error) {
	if version != 1 || macSource != 0 {
		return nil, errMACSourceUnsupported
	}
	return id.ManifestMACKey()
}

// ManifestMACKey returns a fresh 32-byte key. The caller owns its lifetime.
func (id *Identity) ManifestMACKey() ([]byte, error) {
	// FR-3: never sha256(identity.String()) — that hashes the Bech32 encoding, so a
	// format change silently rotates every MAC on files that must open in ten years.
	// Never the raw scalar as an HMAC key — domain collision with its X25519 use.
	return hkdf.Key(sha256.New, id.scalar[:], []byte(macSalt), macInfo, MACKeyLen)
}

// Zero best-effort clears the in-memory scalar. It cannot scrub copies already
// made by hkdf.Key or the garbage collector.
func (id *Identity) Zero() {
	clear(id.scalar[:])
}

var (
	ErrIdentityExists    = errors.New("identity file already exists")
	ErrNotSingleIdentity = errors.New("identity file must contain exactly one identity")
	ErrNotX25519         = errors.New("identity is not an X25519 identity")
	ErrInvalidIdentity   = errors.New("identity file is invalid")
	ErrScalarLength      = errors.New("X25519 scalar must be 32 bytes")
	ErrHRPMismatch       = errors.New("identity has an unexpected human-readable prefix")

	errMACSourceUnsupported = errors.New("manifest MAC source is not supported")
)

func newIdentity(id *age.X25519Identity) (*Identity, error) {
	scalar, err := scalarFrom(id)
	if err != nil {
		return nil, err
	}
	return &Identity{age: id, scalar: scalar}, nil
}

func scalarFrom(id *age.X25519Identity) (out [ScalarLen]byte, err error) {
	hrp, data, err := bech32.Decode(strings.TrimSpace(id.String()))
	if err != nil {
		return out, err
	}
	return acceptScalar(hrp, data)
}

func acceptScalar(hrp string, data []byte) (out [ScalarLen]byte, err error) {
	if hrp != HRP { // case-sensitive, as age's own ParseX25519Identity is
		return out, ErrHRPMismatch
	}
	if len(data) != ScalarLen {
		return out, ErrScalarLength
	}
	copy(out[:], data)
	return out, nil
}

func nonCommentLines(data []byte) int {
	n := 0
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := s.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}
