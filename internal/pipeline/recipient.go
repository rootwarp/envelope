package pipeline

import (
	"context"
	"errors"
	"fmt"

	"github.com/rootwarp/envelope/internal/key"
)

type RecipientOptions struct {
	IdentityPath string
	Terminal     Terminal
	deps         deps
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
	sess := newSession(context.Background(), opts.Terminal, opts.deps, nil)
	defer sess.Close()
	f, err := key.ReadIdentityFile(opts.IdentityPath)
	defer f.Zero()
	if err != nil {
		return nil, err
	}
	if f.IsBundle() {
		b, err := f.Bundle()
		if err != nil {
			return nil, err
		}
		return append([]string(nil), b.Recipients...), nil
	}

	id, err := f.Single()
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

	// Single rejects AGE-PLUGIN- lines as invalid; LoadFiles parses them
	// without starting a plugin process. A LoadFiles failure still returns
	// Single's error, which is the error Load would have reported.
	set, lerr := sess.loadFiles([]*key.IdentityFile{f})
	if lerr != nil {
		return nil, err
	}
	for _, ident := range set.Identities() {
		if ident.Kind() == key.KindPlugin {
			return nil, errNoLocalRecipient()
		}
	}
	return nil, err
}
