// Package key generates, writes, and loads age identities.
//
// Load is the Phase 1 loader: exactly one X25519 identity. LoadSet pre-scans
// each file, routes lines starting with PluginPrefix to plugin.NewIdentity,
// and hands the remainder to age.ParseIdentities in one call. age's parse
// error quotes the offending line, so neither that error nor a plugin parse
// error is ever wrapped or returned.
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
	HRP          = "AGE-SECRET-KEY-" // compared case-sensitively, as age does
	PluginPrefix = "AGE-PLUGIN-"     // case-sensitive, as plugin.ParseIdentity's HRP check is
	ScalarLen    = 32
	MACKeyLen    = 32

	// Duplicated from internal/manifest: D8 forbids the import.
	versionScalar   uint32 = 1
	versionPin      uint32 = 2
	macSourceScalar uint32 = 0
	macSourcePin    uint32 = 1

	macSalt = "envelope"
	macInfo = "envelope v1 manifest mac"
)

// Kind is what an identity or recipient is. It is the only property of a key
// that leaves this package, and nothing outside branches on more than this.
type Kind int

const (
	KindNative Kind = iota + 1 // native age secret-key identities
	KindPlugin                 // AGE-PLUGIN-<NAME>-1
)

// Identity is one usable decryption identity. A native identity may carry the
// X25519 scalar; a plugin identity never carries key material at all.
type Identity struct {
	age        *age.X25519Identity
	native     age.Identity // non-X25519 native (hybrid); nil for X25519 and plugins
	plugin     age.Identity
	kind       Kind
	pluginName string
	source     string // the -identity path, for diagnoses; never key material
	scalar     [ScalarLen]byte
	hasScalar  bool
	attempt    attemptState
}

func (id *Identity) Kind() Kind         { return id.kind }
func (id *Identity) PluginName() string { return id.pluginName }
func (id *Identity) Source() string     { return id.source }
func (id *Identity) Interactive() bool  { return id.kind == KindPlugin }
func (id *Identity) HasScalar() bool    { return id.hasScalar }

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
	if err := writeNew0600(path, []byte(id.age.String()+"\n")); err != nil {
		return nil, err
	}
	return id, nil
}

// writeNew0600 is the keygen durability sequence: O_EXCL 0600, write, Sync,
// Close, Chmod 0600, syncDir. ErrIdentityExists on an existing path.
func writeNew0600(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrIdentityExists
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// os.WriteFile/O_CREATE supply a mode only at creation, so writing over a
	// stale world-readable identity.txt would leave it world-readable. O_EXCL
	// removes that case; keep both.
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
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
	if id.kind == KindPlugin {
		return "", ErrNoLocalRecipient
	}
	if id.age != nil {
		return id.age.Recipient().String(), nil
	}
	if s, ok := nativeRecipientString(id.native); ok {
		return s, nil
	}
	return "", errNoNativeRecipient
}

func nativeRecipientString(id age.Identity) (string, bool) {
	if id == nil {
		return "", false
	}
	switch v := id.(type) {
	case *age.X25519Identity:
		return v.Recipient().String(), true
	case *age.HybridIdentity:
		return v.Recipient().String(), true
	default:
		return "", false
	}
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
	if version != versionScalar || macSource != macSourceScalar {
		return nil, errMACSourceUnsupported
	}
	return nil, nil
}

func (id *Identity) KeyFor(version, macSource uint32) ([]byte, error) {
	if version != versionScalar || macSource != macSourceScalar {
		return nil, errMACSourceUnsupported
	}
	return id.ManifestMACKey()
}

// ManifestMACKey returns a fresh 32-byte key. The caller owns its lifetime.
// ErrNoScalar unless this identity holds an X25519 scalar: never HKDF zeros.
func (id *Identity) ManifestMACKey() ([]byte, error) {
	if !id.hasScalar {
		return nil, ErrNoScalar
	}
	// FR-3: never sha256(identity.String()) — that hashes the Bech32 encoding, so a
	// format change silently rotates every MAC on files that must open in ten years.
	// Never the raw scalar as an HMAC key — domain collision with its X25519 use.
	return hkdf.Key(sha256.New, id.scalar[:], []byte(macSalt), macInfo, MACKeyLen)
}

// Zero best-effort clears the in-memory scalar. It cannot scrub copies already
// made by hkdf.Key or the garbage collector.
func (id *Identity) Zero() {
	clear(id.scalar[:])
	id.attempt.mu.Lock()
	id.attempt.err = nil
	id.attempt.attempted = false
	id.attempt.mu.Unlock()
}

var (
	ErrIdentityExists    = errors.New("identity file already exists")
	ErrNotSingleIdentity = errors.New("identity file must contain exactly one identity")
	ErrNotX25519         = errors.New("identity is not an X25519 identity")
	ErrInvalidIdentity   = errors.New("identity file is invalid")
	ErrScalarLength      = errors.New("X25519 scalar must be 32 bytes")
	ErrHRPMismatch       = errors.New("identity has an unexpected human-readable prefix")

	errMACSourceUnsupported = errors.New("manifest MAC source is not supported")
	errNoNativeRecipient    = errors.New("native identity has no local recipient string")
)

func newIdentity(id *age.X25519Identity) (*Identity, error) {
	scalar, err := scalarFrom(id)
	if err != nil {
		return nil, err
	}
	return &Identity{age: id, scalar: scalar, kind: KindNative, hasScalar: true}, nil
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
