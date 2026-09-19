//go:build envelope_signaltest

package pipeline

import (
	"context"
	"io"
)

// Compiled only into the binary cmd/envelope's signal tests build. It holds a
// restore after its first plaintext write until ctx is cancelled, so a signal
// sent once .partial exists always lands mid-copy (PRD E1, O17).
// Never run go test -tags envelope_signaltest ./...: every in-process restore
// would park until go test's own timeout.
func init() {
	testWrapDst = func(ctx context.Context, w io.Writer) io.Writer { return &holdAfterFirstWrite{ctx: ctx, w: w} }
}

type holdAfterFirstWrite struct {
	ctx   context.Context
	w     io.Writer
	wrote bool
}

func (h *holdAfterFirstWrite) Write(p []byte) (int, error) {
	n, err := h.w.Write(p)
	if !h.wrote {
		h.wrote = true
		<-h.ctx.Done() // no timeout: the test's 30 s exit deadline bounds it and fails loudly
	}
	return n, err
}
