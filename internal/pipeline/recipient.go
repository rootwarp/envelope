package pipeline

import (
	"errors"
	"fmt"
	"os"

	"github.com/rootwarp/envelope/internal/key"
)

type RecipientOptions struct {
	IdentityPath string
	Terminal     Terminal
}

// ErrNoLocalRecipient is a plugin identity with no bundle: the stub carries
// no public key, so no local computation recovers the recipient.
var ErrNoLocalRecipient = key.ErrNoLocalRecipient

func errNoLocalRecipient() error {
	return fmt.Errorf("%w: record it with envelope bind, or get it from the plugin's own listing", ErrNoLocalRecipient)
}

// Recipient returns the public recipient strings for -identity.
//
// The stub carries no public key, so a bundle's recorded set is the only
// local source; a bare plugin identity must not be asked for a recipient.
func Recipient(opts RecipientOptions) ([]string, error) {
	data, err := os.ReadFile(opts.IdentityPath)
	if err != nil {
		return nil, err
	}
	if key.IsBundle(data) {
		b, err := key.ReadBundle(opts.IdentityPath)
		if err != nil {
			return nil, err
		}
		return append([]string(nil), b.Recipients...), nil
	}

	id, err := key.Load(opts.IdentityPath)
	if err == nil {
		defer id.Zero()
		s, err := id.RecipientString()
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
	if !errors.Is(err, key.ErrInvalidIdentity) {
		return nil, err
	}

	// Load rejects AGE-PLUGIN- lines as invalid; LoadSet parses them without
	// starting a plugin process.
	set, lerr := key.LoadSet([]string{opts.IdentityPath}, terminalSource(opts.Terminal))
	if lerr != nil {
		return nil, err
	}
	defer set.Zero()
	for _, ident := range set.Identities() {
		if ident.Kind() == key.KindPlugin {
			return nil, errNoLocalRecipient()
		}
	}
	return nil, err
}
