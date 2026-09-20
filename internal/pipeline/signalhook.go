//go:build envelope_signaltest

package pipeline

import (
	"context"
	"errors"
	"io"
	"os"
)

// Compiled only into the binary cmd/envelope's signal tests build.
//
// Two park points, both waiting on ctx (the process signal.NotifyContext):
//   - after restore's first plaintext write, so a signal sent once .partial
//     exists always lands mid-copy (PRD E1, O17);
//   - inside a plugin PIN prompt (the fake's RequestValue → Terminal.ReadLine),
//     so a signal sent while the plugin is waiting always lands in that window.
//
// Measured, and why the park cannot be a context on Unwrap: Unwrap polls no
// context; conn.Close (close pipes, signal the child, Wait) runs only after
// the plugin answers; the child's pgid equals ours, so a terminal Ctrl-C
// reaches the plugin directly. Detaching the child would break that path.
// A programmatic cancel does not unblock a blocked plugin read.
//
// Never run go test -tags envelope_signaltest ./...: every in-process restore
// and every plugin PIN prompt would park until go test's own timeout.
func init() {
	testWrapDst = func(ctx context.Context, w io.Writer) io.Writer { return &holdAfterFirstWrite{ctx: ctx, w: w} }
	testCaptureCtx = func(ctx context.Context) { parkedCtx = ctx }
	testOpenTerminal = func() (Terminal, error) { return holdPrompt{}, nil }
}

var parkedCtx context.Context

const signalTestReadyEnv = "ENVELOPE_SIGNALTEST_READY"

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

// holdPrompt is the injected terminal for a plugin identity. ReadLine is the
// client side of the fake's RequestValue: it holds until ctx is cancelled so
// SIGINT always lands inside the prompt. Production RequestValue polls no
// context; this park exists only in the signal-test binary.
type holdPrompt struct{}

func (holdPrompt) Notify(string) {}
func (holdPrompt) Close() error  { return nil }

func (holdPrompt) ReadLine(string, bool) (string, error) {
	if p := os.Getenv(signalTestReadyEnv); p != "" {
		_ = os.WriteFile(p, []byte("1"), 0o600)
	}
	ctx := parkedCtx
	if ctx == nil {
		return "", errSignalTestNoContext
	}
	<-ctx.Done()
	return "", ctx.Err()
}

var errSignalTestNoContext = errors.New("signaltest: missing context")
