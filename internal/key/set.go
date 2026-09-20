package key

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const bundleHeaderPrefix = "# envelope-bundle:"

// Set is one run's ordered identity list plus the pin, if a bundle carried one.
// Order is the decrypt order: native identities first (no process, no card, no
// prompt), then plugin identities in -identity order.
type Set struct {
	ids          []*Identity
	pin          *pinSource
	pinAmbiguous bool
	ui           *ClientUI
	term         TerminalSource
	nPaths       int
	bundle       bool
	interactions atomic.Int32

	macMu    sync.Mutex
	macKey   []byte
	macErr   error
	macReady bool
}

// pinSource is the card-free record of one bundle's pin: the public key id,
// the recorded recipients, and the pin ciphertext. The seed is never stored.
type pinSource struct {
	macKeyID   []byte
	recipients []string
	pin        []byte
}

type attemptState struct {
	mu        sync.Mutex
	attempted bool
	err       error
}

// testObserveSeed, when set, receives the unwrapped seed before the two HKDFs.
// Tests alias that buffer to prove it is cleared before KeyFor returns (I-4).
var testObserveSeed func([]byte)

// LoadSet reads each path, routing AGE-PLUGIN- lines to plugin.NewIdentity and
// the remainder to age.ParseIdentities in one call so its diagnostics stay
// intact. plugin.NewIdentity starts no process. A path whose first non-empty
// line is the bundle header is parsed as a bundle: LoadSet records that
// bundle's mac_key_id, recipients and pin ciphertext (card-free) and does
// not unwrap the pin.
func LoadSet(paths []string, term TerminalSource) (*Set, error) {
	s := &Set{
		term:   term,
		ui:     NewClientUI(term),
		nPaths: len(paths),
	}
	var natives, plugins []*Identity
	for _, path := range paths {
		n, p, err := s.loadPath(path)
		if err != nil {
			return nil, err
		}
		natives = append(natives, n...)
		plugins = append(plugins, p...)
	}
	s.ids = append(natives, plugins...)
	if len(s.ids) == 0 {
		return nil, ErrNotSingleIdentity
	}
	return s, nil
}

func (s *Set) loadPath(path string) (natives, plugins []*Identity, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if isBundle(data) {
		s.bundle = true
		b, err := parseBundle(data)
		if err != nil {
			return nil, nil, err
		}
		b.Path = path
		s.recordPin(b)
		return s.parseIdentityLines(path, b.Identities)
	}
	return s.parseIdentityData(path, data)
}

func (s *Set) parseIdentityLines(path string, lines []string) (natives, plugins []*Identity, err error) {
	var buf bytes.Buffer
	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	return s.parseIdentityData(path, buf.Bytes())
}

func (s *Set) parseIdentityData(path string, data []byte) (natives, plugins []*Identity, err error) {
	var rest bytes.Buffer
	var pluginLines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, PluginPrefix) {
			pluginLines = append(pluginLines, line)
			continue
		}
		rest.WriteString(line)
		rest.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}

	ui := &s.ui.ClientUI
	for _, line := range pluginLines {
		p, err := plugin.NewIdentity(line, ui)
		if err != nil {
			// plugin.ParseIdentity may quote the line; never wrap or return it.
			return nil, nil, ErrInvalidIdentity
		}
		id := &Identity{
			kind:       KindPlugin,
			pluginName: p.Name(),
			source:     path,
		}
		id.plugin = &pluginIdentity{inner: p, st: &id.attempt, n: &s.interactions}
		plugins = append(plugins, id)
	}

	if hasNonComment(rest.Bytes()) {
		ids, err := age.ParseIdentities(bytes.NewReader(rest.Bytes()))
		if err != nil {
			// age quotes the identity line; never wrap or return that error.
			return nil, nil, ErrInvalidIdentity
		}
		for _, id := range ids {
			n, err := nativeIdentity(id, path)
			if err != nil {
				return nil, nil, err
			}
			natives = append(natives, n)
		}
	}
	return natives, plugins, nil
}

func (s *Set) recordPin(b *Bundle) {
	rec := &pinSource{
		macKeyID:   append([]byte(nil), b.MACKeyID...),
		recipients: append([]string(nil), b.Recipients...),
		pin:        append([]byte(nil), b.Pin...),
	}
	if s.pin == nil {
		s.pin = rec
		return
	}
	if !hmac.Equal(s.pin.macKeyID, rec.macKeyID) {
		s.pinAmbiguous = true
	}
}

func nativeIdentity(id age.Identity, path string) (*Identity, error) {
	x25519, ok := id.(*age.X25519Identity)
	if !ok {
		return &Identity{native: id, kind: KindNative, source: path}, nil
	}
	n, err := newIdentity(x25519)
	if err != nil {
		return nil, err
	}
	n.source = path
	return n, nil
}

// IsBundle reports whether data's first non-empty line is an identity-bundle
// header. An unsupported version still matches, so the caller can return
// ErrBundleVersion instead of treating the file as a bare identity.
func IsBundle(data []byte) bool {
	return isBundle(data)
}

func isBundle(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		return strings.HasPrefix(strings.TrimSpace(line), bundleHeaderPrefix)
	}
	return false
}

func hasNonComment(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return true
	}
	return false
}

func (s *Set) Identities() []*Identity {
	out := make([]*Identity, len(s.ids))
	copy(out, s.ids)
	return out
}

func (s *Set) Interactive() bool {
	for _, id := range s.ids {
		if id.Interactive() {
			return true
		}
	}
	return false
}

func (s *Set) HasPin() bool { return s.pin != nil }

// RecordedRecipients is the bundle's public recipient set, or nil. Split
// encrypts to these strings when -recipient is omitted; comparing against
// them is how it warns on a disjoint -recipient set without a card.
func (s *Set) RecordedRecipients() []string {
	if s == nil || s.pin == nil {
		return nil
	}
	out := make([]string, len(s.pin.recipients))
	copy(out, s.pin.recipients)
	return out
}

func (s *Set) pinChoice() error {
	if s.pinAmbiguous {
		return ErrAmbiguousPin
	}
	if s.pin == nil {
		return ErrNoPin
	}
	return nil
}

// KeyIDFor returns the 16-byte public MAC key id this run's pin derives, or
// nil for version 1. It reads the bundle's recorded id and starts no plugin:
// the key-id check can only cause a rejection, never an acceptance, because
// only the MAC decides anything.
//
// At most one distinct pin per run, refused at the point of need, never at
// load, because a pure-v1 run with a hardware bundle loaded must still cost
// zero interactions. Bundles recording the same id are interchangeable and
// the first is used; different ids return ErrAmbiguousPin.
func (s *Set) KeyIDFor(version, macSource uint32) ([]byte, error) {
	if s == nil || len(s.ids) == 0 {
		return nil, ErrNotSingleIdentity
	}
	switch {
	case version == versionScalar && macSource == macSourceScalar:
		return nil, nil
	case version == versionPin && macSource == macSourcePin:
		if err := s.pinChoice(); err != nil {
			return nil, err
		}
		return copyMACKey(s.pin.macKeyID), nil
	default:
		return nil, errMACSourceUnsupported
	}
}

// KeyFor returns the HMAC key a manifest of this version and source must be
// verified under.
//
//	version 1, source 0: ADR-0003's HKDF over the X25519 scalar. No plugin.
//	version 2, source 1: unwraps the bundle's pin through the identity set —
//	                     one decrypt site (1 to p interactions), memoized per
//	                     Set for the whole run — derives mac_key and
//	                     mac_key_id, checks the derived id against the
//	                     recorded one (ErrPinCorrupt), and zeroes the seed
//	                     before returning.
//
// Any other pair is a distinct sentinel. Pin refusal is at the point of need,
// never at load, because a pure-v1 run with a hardware bundle loaded must
// still cost zero interactions. Memoization is per Set, not per process, so
// Zero drops the cached key. The seed exists in memory only between the
// unwrap and the two HKDF derivations and is cleared there (best-effort:
// clear cannot scrub copies already made by hkdf.Key or the garbage collector).
func (s *Set) KeyFor(version, macSource uint32) ([]byte, error) {
	if s == nil || len(s.ids) == 0 {
		return nil, ErrNotSingleIdentity
	}
	switch {
	case version == versionScalar && macSource == macSourceScalar:
		return s.scalarMACKey()
	case version == versionPin && macSource == macSourcePin:
		return s.pinMACKey()
	default:
		return nil, errMACSourceUnsupported
	}
}

func (s *Set) scalarMACKey() ([]byte, error) {
	for _, id := range s.ids {
		if id.hasScalar {
			return id.ManifestMACKey()
		}
	}
	return nil, ErrNoScalar
}

func (s *Set) pinMACKey() ([]byte, error) {
	if err := s.pinChoice(); err != nil {
		return nil, err
	}
	s.macMu.Lock()
	defer s.macMu.Unlock()
	if s.macReady {
		if s.macErr != nil {
			return nil, s.macErr
		}
		return copyMACKey(s.macKey), nil
	}
	key, err := s.unwrapPinMACKey()
	s.macReady = true
	s.macErr = err
	if err != nil {
		return nil, err
	}
	s.macKey = key
	return copyMACKey(key), nil
}

func (s *Set) unwrapPinMACKey() ([]byte, error) {
	seed, err := s.DecryptBytes(s.pin.pin)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if testObserveSeed != nil {
		testObserveSeed(seed)
	}
	if len(seed) != seedLen {
		return nil, ErrPinCorrupt
	}
	macKey, err := derivePinMACKey(seed)
	if err != nil {
		return nil, err
	}
	gotID, err := derivePinMACKeyID(seed)
	if err != nil {
		clear(macKey)
		return nil, err
	}
	defer clear(gotID)
	if !hmac.Equal(gotID, s.pin.macKeyID) {
		clear(macKey)
		return nil, ErrPinCorrupt
	}
	return macKey, nil
}

func copyMACKey(k []byte) []byte {
	out := make([]byte, len(k))
	copy(out, k)
	return out
}

// BareFileIdentity is the FR-YK-03 boolean: exactly one path, exactly one
// native X25519 identity, no bundle metadata. The caller still has to check
// there is no -recipient flag.
func (s *Set) BareFileIdentity() bool {
	if s == nil || s.nPaths != 1 || s.bundle || len(s.ids) != 1 {
		return false
	}
	id := s.ids[0]
	return id.kind == KindNative && id.hasScalar
}

// Zero best-effort clears in-memory scalars and drops the memoized pin MAC
// key. It cannot scrub copies already made by hkdf.Key or the garbage
// collector. Memoization is per Set, so Zero must drop it.
func (s *Set) Zero() {
	if s == nil {
		return
	}
	for _, id := range s.ids {
		id.Zero()
	}
	s.macMu.Lock()
	clear(s.macKey)
	s.macKey = nil
	s.macErr = nil
	s.macReady = false
	s.macMu.Unlock()
}
