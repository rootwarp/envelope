package key

import (
	"errors"

	"github.com/rootwarp/envelope/internal/key/tty"
)

// Terminal is the operator-facing I/O an interactive identity needs. Nothing
// here may ever write to stdout: by the phase-2 contract stdout carries only
// what the operator asked for.
type Terminal interface {
	Notify(line string)
	ReadLine(prompt string, secret bool) (string, error)
	Close() error
}

// TerminalSource opens the terminal on demand. A nil source, or one that
// returns ErrNoTerminal, makes every interactive identity fail closed before
// its plugin starts.
type TerminalSource func() (Terminal, error)

// ErrNoTerminal is returned when /dev/tty cannot be opened. The failed open
// is the non-TTY detection.
var ErrNoTerminal = errors.New("this identity needs a terminal to prompt on")

var _ Terminal = (*tty.Terminal)(nil)

// Replaced in tests: native load/decrypt must never open /dev/tty.
var openTTY = func() (Terminal, error) {
	t, err := tty.Open()
	if err != nil {
		return nil, err
	}
	return t, nil
}

// OpenTerminal opens /dev/tty O_RDWR. ErrNoTerminal when it cannot be opened.
func OpenTerminal() (Terminal, error) {
	t, err := openTTY()
	if err != nil {
		return nil, ErrNoTerminal
	}
	return t, nil
}
