package pipeline

import (
	"github.com/rootwarp/envelope/internal/key"
)

type RecipientOptions struct {
	IdentityPath string
	Terminal     Terminal
}

func Recipient(opts RecipientOptions) (string, error) {
	id, err := key.Load(opts.IdentityPath)
	if err != nil {
		return "", err
	}
	defer id.Zero()
	return id.RecipientString()
}
