package pipeline

import (
	"io"

	"github.com/rootwarp/envelope/internal/key"
)

type KeygenOptions struct {
	IdentityPath string
}

func Keygen(opts KeygenOptions, status io.Writer) error {
	// FR-27: silent by default; do not invent a status line.
	id, err := key.Create(opts.IdentityPath)
	if err != nil {
		return err
	}
	id.Zero()
	return nil
}
