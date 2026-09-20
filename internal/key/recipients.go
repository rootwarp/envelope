package key

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/key/bech32"
)

// RecipientSet is a resolved recipient set together with the exact strings
// it was resolved from. Recording the strings is what makes a split encrypt
// with no card and lets bind refuse a set it could not use.
type RecipientSet struct {
	strs    []string
	rs      []age.Recipient
	plugins []string // plugin names only; empty means the set is all-native
}

// NewRecipientSet builds a native set from one identity's recipient.
func NewRecipientSet(id *Identity) (*RecipientSet, error) {
	s, err := id.RecipientString()
	if err != nil {
		return nil, err
	}
	return ParseNativeRecipients([]string{s})
}

// ParseNativeRecipients resolves X25519 recipient strings, deduplicating on
// the trimmed string. Hybrid and plugin HRPs are classified by ParseRecipients.
func ParseNativeRecipients(strs []string) (*RecipientSet, error) {
	out := &RecipientSet{
		strs: make([]string, 0, len(strs)),
		rs:   make([]age.Recipient, 0, len(strs)),
	}
	seen := make(map[string]struct{}, len(strs))
	for _, raw := range strs {
		s := strings.TrimSpace(raw)
		if _, ok := seen[s]; ok {
			continue
		}
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, err
		}
		seen[s] = struct{}{}
		out.strs = append(out.strs, s)
		out.rs = append(out.rs, r)
	}
	return out, nil
}

// ParseRecipients classifies each string by bech32 HRP, in this order:
//
//  1. HRP "age" → native X25519
//  2. HRP "age1pq" → native hybrid (not plugin "pq": that name is valid)
//  3. HRP "age1<name>", <name> a valid plugin name → plugin <name>
//
// Dedup is on the trimmed string, not semantically: the same key under two
// encodings is not detected, and a duplicate stanza is wasteful, not unsafe.
// Plugin recipients are resolved from strings so encryption touches no card.
//
// There is no recipient string that denotes a passphrase. scrypt is reachable
// only through a flag age gives and Envelope does not, so rejecting scrypt at
// flag-parse time is "-recipient accepts only a bech32 age recipient".
// ScryptRecipient.WrapWithLabels returns a fresh random label per call
// (scrypt.go:91-109), which is why no passphrase path is ever added.
func ParseRecipients(strs []string, ui *ClientUI) (*RecipientSet, error) {
	out := &RecipientSet{
		strs: make([]string, 0, len(strs)),
		rs:   make([]age.Recipient, 0, len(strs)),
	}
	seen := make(map[string]struct{}, len(strs))
	for _, raw := range strs {
		s := strings.TrimSpace(raw)
		if _, ok := seen[s]; ok {
			continue
		}
		r, pluginName, err := parseRecipient(s, ui)
		if err != nil {
			return nil, err
		}
		seen[s] = struct{}{}
		out.strs = append(out.strs, s)
		out.rs = append(out.rs, r)
		if pluginName != "" {
			out.plugins = append(out.plugins, pluginName)
		}
	}
	return out, nil
}

func (rs *RecipientSet) Strings() []string {
	out := make([]string, len(rs.strs))
	copy(out, rs.strs)
	return out
}

func (rs *RecipientSet) Len() int {
	return len(rs.rs)
}

// SolePlugin reports the plugin name when the set is exactly one plugin
// recipient. False for (plugin, plugin), (plugin, native) and (native).
func (rs *RecipientSet) SolePlugin() (string, bool) {
	if rs == nil || len(rs.rs) != 1 || len(rs.plugins) != 1 {
		return "", false
	}
	return rs.plugins[0], true
}

func (rs *RecipientSet) EncryptBytes(plaintext []byte) ([]byte, error) {
	return crypt.EncryptBytes(plaintext, rs.rs...)
}

func (rs *RecipientSet) Encrypt(dst io.Writer, src io.Reader) (int64, error) {
	return crypt.Encrypt(dst, src, rs.rs...)
}

// ErrBadRecipient is returned by ParseRecipients for a string that is not a
// bech32 age recipient. The error quotes the string: recipients are public.
var ErrBadRecipient = errors.New("not an age recipient")

func errBadRecipient(s string) error {
	return fmt.Errorf("%w: %q", ErrBadRecipient, s)
}

func parseRecipient(s string, ui *ClientUI) (age.Recipient, string, error) {
	hrp, _, err := bech32.Decode(s)
	if err != nil {
		return nil, "", errBadRecipient(s)
	}
	switch hrp {
	case "age":
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, "", errBadRecipient(s)
		}
		return r, "", nil
	case "age1pq":
		r, err := age.ParseHybridRecipient(s)
		if err != nil {
			return nil, "", errBadRecipient(s)
		}
		return r, "", nil
	}
	var pui *plugin.ClientUI
	if ui != nil {
		pui = &ui.ClientUI
	}
	r, err := plugin.NewRecipient(s, pui)
	if err != nil {
		return nil, "", errBadRecipient(s)
	}
	return r, r.Name(), nil
}
