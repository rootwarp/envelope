package key

import (
	"bufio"
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const (
	MACKeyIDLen = 16

	seedLen        = 32
	bundleMaxBytes = 64 << 10

	bundleHeader    = bundleHeaderPrefix + " v1"
	fieldPrefix     = "# envelope-"
	pinMACInfo      = "envelope v2 manifest mac"
	pinMACKeyIDInfo = "envelope v2 manifest mac key id"
	macKeyIDField   = "mac-key-id"
	recipientField  = "recipient"
	pinField        = "pin"
)

// Bundle is a long-lived identity bundle (format v1). The seed never appears
// in this struct: Pin is the age ciphertext of the 32-byte seed, wrapped to
// Recipients.
//
// One seed is minted per identity and is never regenerated (I-3). A silently
// new seed would be indistinguishable from every shard set having been forged.
// Any copy of the bundle, of any age, must verify any shard set made with it.
type Bundle struct {
	Path       string
	MACKeyID   []byte
	Recipients []string
	Pin        []byte
	Identities []string
}

var (
	ErrBundleVersion     = errors.New("identity bundle version is not supported")
	ErrBundleField       = errors.New("identity bundle has an unknown or malformed field")
	ErrBundleTooLarge    = errors.New("identity bundle exceeds size limit")
	ErrBundleNoRecipient = errors.New("identity bundle requires at least one recipient")
	ErrPinCorrupt        = errors.New("identity bundle pin is corrupt")
)

func errNoRecipient() error {
	return fmt.Errorf("%w: get the public recipient from the plugin's own listing", ErrBundleNoRecipient)
}

// NewBundle mints the seed with crypto/rand, derives mac_key and mac_key_id,
// wraps the seed to rs, and zeroes the seed before returning. It refuses an
// empty recipient set: such a bundle could not split and envelope recipient
// would have nothing to print. It takes no *Bundle: it can never mint a seed
// on an existing bundle (I-3).
func NewBundle(identityLines []string, rs *RecipientSet) (*Bundle, error) {
	if rs == nil || rs.Len() == 0 {
		return nil, errNoRecipient()
	}
	idents, err := normalizeIdentityLines(identityLines)
	if err != nil {
		return nil, err
	}
	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	defer clear(seed)

	macKey, err := derivePinMACKey(seed)
	if err != nil {
		return nil, err
	}
	clear(macKey)
	macKeyID, err := derivePinMACKeyID(seed)
	if err != nil {
		return nil, err
	}
	pin, err := rs.EncryptBytes(seed)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		MACKeyID:   macKeyID,
		Recipients: rs.Strings(),
		Pin:        pin,
		Identities: idents,
	}, nil
}

// AddRecipients re-wraps the same seed to the extended set. It unwraps the pin
// through set (one plugin interaction), re-derives the key id, and refuses if
// it does not equal b.MACKeyID (ErrPinCorrupt). It can never mint a seed.
func (b *Bundle) AddRecipients(set *Set, extra *RecipientSet) error {
	if b == nil {
		return ErrPinCorrupt
	}
	if extra == nil || extra.Len() == 0 {
		return errNoRecipient()
	}
	seed, err := unwrapPin(set, b.Pin, b.MACKeyID)
	if err != nil {
		return err
	}
	defer clear(seed)

	strs := make([]string, 0, len(b.Recipients)+extra.Len())
	strs = append(strs, b.Recipients...)
	strs = append(strs, extra.Strings()...)
	var ui *ClientUI
	if set != nil {
		ui = set.ui
	}
	rs, err := ParseRecipients(strs, ui)
	if err != nil {
		return err
	}
	pin, err := rs.EncryptBytes(seed)
	if err != nil {
		return err
	}
	b.Recipients = rs.Strings()
	b.Pin = pin
	return nil
}

// ReplaceIdentities swaps the identity lines and touches nothing else: the pin
// ciphertext is copied verbatim, so this mode costs zero plugin interactions.
func (b *Bundle) ReplaceIdentities(lines []string) error {
	if b == nil {
		return ErrInvalidIdentity
	}
	idents, err := normalizeIdentityLines(lines)
	if err != nil {
		return err
	}
	b.Identities = idents
	return nil
}

// Marshal encodes the bundle in write order: header, mac-key-id, recipients,
// pin, identity lines. Metadata lives on # lines and the pin is
// base64.StdEncoding, never armor, so the file stays a valid age identity file.
func (b *Bundle) Marshal() []byte {
	var buf strings.Builder
	buf.WriteString(bundleHeader)
	buf.WriteByte('\n')
	buf.WriteString(fieldPrefix)
	buf.WriteString(macKeyIDField)
	buf.WriteString(": ")
	buf.WriteString(hex.EncodeToString(b.MACKeyID))
	buf.WriteByte('\n')
	for _, r := range b.Recipients {
		buf.WriteString(fieldPrefix)
		buf.WriteString(recipientField)
		buf.WriteString(": ")
		buf.WriteString(r)
		buf.WriteByte('\n')
	}
	buf.WriteString(fieldPrefix)
	buf.WriteString(pinField)
	buf.WriteString(": ")
	buf.WriteString(base64.StdEncoding.EncodeToString(b.Pin))
	buf.WriteByte('\n')
	for _, id := range b.Identities {
		buf.WriteString(id)
		buf.WriteByte('\n')
	}
	return []byte(buf.String())
}

// ReadBundle parses path as a v1 identity bundle. The whole file must be
// ≤ 64 KiB. Unknown envelope- fields are refused so a future load-bearing
// field cannot be silently dropped.
func ReadBundle(path string) (*Bundle, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > bundleMaxBytes {
		return nil, ErrBundleTooLarge
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := parseBundle(data)
	if err != nil {
		return nil, err
	}
	b.Path = path
	return b, nil
}

// WriteNew is keygen's durability sequence: O_EXCL 0600, write, Sync, Close,
// Chmod 0600, sync the directory. ErrIdentityExists on an existing path.
func WriteNew(path string, b *Bundle) error {
	data, err := marshalBundle(b)
	if err != nil {
		return err
	}
	if err := writeNew0600(path, data); err != nil {
		return err
	}
	b.Path = path
	return nil
}

// Replace writes path+".tmp" with WriteNew's sequence, then renames onto path
// and syncs the directory — split's manifest commit sequence. Never in place.
func Replace(path string, b *Bundle) error {
	data, err := marshalBundle(b)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := writeNew0600(tmp, data); err != nil {
		return err
	}
	rename := os.Rename
	if testReplaceRename != nil {
		rename = testReplaceRename
	}
	if err := rename(tmp, path); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return err
	}
	b.Path = path
	return nil
}

// testReplaceRename replaces os.Rename in Replace. Tests inject a failure
// between the tmp write and the commit.
var testReplaceRename func(oldpath, newpath string) error

func marshalBundle(b *Bundle) ([]byte, error) {
	if b == nil {
		return nil, ErrInvalidIdentity
	}
	data := b.Marshal()
	if len(data) > bundleMaxBytes {
		return nil, ErrBundleTooLarge
	}
	return data, nil
}

func parseBundle(data []byte) (*Bundle, error) {
	if int64(len(data)) > bundleMaxBytes {
		return nil, ErrBundleTooLarge
	}
	if !utf8.Valid(data) {
		return nil, ErrInvalidIdentity
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), bundleMaxBytes)

	sawHeader := false
	var macKeyID []byte
	var recipients []string
	seenRecip := make(map[string]struct{})
	var pin []byte
	var identities []string
	sawMAC, sawPin := false, false

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if !sawHeader {
			if line == "" {
				continue
			}
			if line != bundleHeader {
				return nil, ErrBundleVersion
			}
			sawHeader = true
			continue
		}
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			return nil, ErrBundleField
		}
		if strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, fieldPrefix) {
				continue
			}
			key, value, ok := parseEnvelopeField(line)
			if !ok {
				return nil, ErrBundleField
			}
			switch key {
			case "bundle":
				return nil, ErrBundleField
			case macKeyIDField:
				if sawMAC {
					return nil, ErrBundleField
				}
				id, err := parseMACKeyID(value)
				if err != nil {
					return nil, err
				}
				macKeyID = id
				sawMAC = true
			case recipientField:
				s := strings.TrimSpace(value)
				if s == "" {
					return nil, ErrBundleField
				}
				if _, dup := seenRecip[s]; dup {
					continue
				}
				seenRecip[s] = struct{}{}
				recipients = append(recipients, s)
			case pinField:
				if sawPin {
					return nil, ErrBundleField
				}
				p, err := decodePin(value)
				if err != nil {
					return nil, err
				}
				pin = p
				sawPin = true
			default:
				return nil, ErrBundleField
			}
			continue
		}
		if err := validateIdentityLine(line); err != nil {
			return nil, err
		}
		identities = append(identities, line)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, ErrBundleTooLarge
		}
		return nil, err
	}
	if !sawHeader {
		return nil, ErrBundleVersion
	}
	if !sawMAC || !sawPin {
		return nil, ErrBundleField
	}
	if len(recipients) == 0 {
		return nil, ErrBundleNoRecipient
	}
	if len(identities) == 0 {
		return nil, ErrInvalidIdentity
	}
	return &Bundle{
		MACKeyID:   macKeyID,
		Recipients: recipients,
		Pin:        pin,
		Identities: identities,
	}, nil
}

func parseEnvelopeField(line string) (key, value string, ok bool) {
	if !strings.HasPrefix(line, fieldPrefix) {
		return "", "", false
	}
	rest := line[len(fieldPrefix):]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return "", "", false
	}
	key = rest[:colon]
	if !validFieldKey(key) {
		return "", "", false
	}
	after := rest[colon+1:]
	if !strings.HasPrefix(after, " ") || strings.HasPrefix(after, "  ") {
		return "", "", false
	}
	return key, after[1:], true
}

func validFieldKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

func parseMACKeyID(value string) ([]byte, error) {
	if len(value) != hex.EncodedLen(MACKeyIDLen) {
		return nil, ErrBundleField
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, ErrBundleField
		}
	}
	id, err := hex.DecodeString(value)
	if err != nil || len(id) != MACKeyIDLen {
		return nil, ErrBundleField
	}
	return id, nil
}

func decodePin(value string) ([]byte, error) {
	p, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(p) == 0 {
		return nil, ErrBundleField
	}
	return p, nil
}

func normalizeIdentityLines(lines []string) ([]string, error) {
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.ContainsAny(line, "\n") {
			return nil, ErrInvalidIdentity
		}
		if err := validateIdentityLine(line); err != nil {
			return nil, err
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, ErrInvalidIdentity
	}
	return out, nil
}

func validateIdentityLine(line string) error {
	if line == "" || strings.HasPrefix(line, "#") {
		return ErrInvalidIdentity
	}
	if strings.HasPrefix(line, PluginPrefix) {
		if _, _, err := plugin.ParseIdentity(line); err != nil {
			return ErrInvalidIdentity
		}
		return nil
	}
	ids, err := age.ParseIdentities(strings.NewReader(line + "\n"))
	if err != nil || len(ids) != 1 {
		return ErrInvalidIdentity
	}
	return nil
}

func unwrapPin(set *Set, pin, wantID []byte) ([]byte, error) {
	if set == nil {
		return nil, ErrPinCorrupt
	}
	seed, err := set.DecryptBytes(pin)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPinCorrupt, err)
	}
	if len(seed) != seedLen {
		clear(seed)
		return nil, ErrPinCorrupt
	}
	got, err := derivePinMACKeyID(seed)
	if err != nil {
		clear(seed)
		return nil, err
	}
	defer clear(got)
	if !hmac.Equal(got, wantID) {
		clear(seed)
		return nil, ErrPinCorrupt
	}
	return seed, nil
}

func derivePinMACKey(seed []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, seed, []byte(macSalt), pinMACInfo, MACKeyLen)
}

func derivePinMACKeyID(seed []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, seed, []byte(macSalt), pinMACKeyIDInfo, MACKeyIDLen)
}
