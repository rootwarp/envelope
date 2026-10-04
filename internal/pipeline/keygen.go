package pipeline

import (
	"io"

	"github.com/rootwarp/envelope/internal/key"
)

type KeygenOptions struct {
	IdentityPath string
	Terminal     Terminal
}

func Keygen(opts KeygenOptions, status io.Writer) error {
	// keygen prints nothing on success; do not add a status line.
	id, err := key.Create(opts.IdentityPath)
	if err != nil {
		return err
	}
	id.Zero()
	return nil
}
