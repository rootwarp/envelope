package key

import (
	"io"
	"strings"

	"filippo.io/age"

	"github.com/rootwarp/envelope/internal/crypt"
)

// RecipientSet is a resolved recipient set together with the exact strings
// it was resolved from. Recording the strings is what makes a split encrypt
// with no card and lets bind refuse a set it could not use.
type RecipientSet struct {
	strs []string
	rs   []age.Recipient
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
// the trimmed string. Plugin HRPs are classified later.
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

func (rs *RecipientSet) Strings() []string {
	out := make([]string, len(rs.strs))
	copy(out, rs.strs)
	return out
}

func (rs *RecipientSet) Len() int {
	return len(rs.rs)
}

func (rs *RecipientSet) EncryptBytes(plaintext []byte) ([]byte, error) {
	return crypt.EncryptBytes(plaintext, rs.rs...)
}

func (rs *RecipientSet) Encrypt(dst io.Writer, src io.Reader) (int64, error) {
	return crypt.Encrypt(dst, src, rs.rs...)
}
