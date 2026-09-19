package pipeline

import (
	"errors"
	"fmt"

	"github.com/rootwarp/envelope/internal/key"
)

type RecipientOptions struct{ IdentityPath string }

func Recipient(opts RecipientOptions) (string, error) {
	id, err := key.Load(opts.IdentityPath)
	if err != nil {
		return "", err
	}
	defer id.Zero()
	s, ok := id.Recipient().(fmt.Stringer)
	if !ok {
		return "", errors.New("identity has no printable recipient")
	}
	return s.String(), nil
}
