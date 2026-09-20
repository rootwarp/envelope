// Package tty opens /dev/tty for interactive identity prompts.
//
// A failed open is the non-TTY detection: there is no separate isatty probe
// and no fallback to stdin, which may be the payload. Nothing here may write
// to stdout. Terminal state is restored on every exit path, including the
// signal path, which is why golang.org/x/term is a dependency rather than a
// hand-rolled termios wrapper.
package tty

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/term"
)

var errUnavailable = errors.New("terminal is not available")

// Replaced in tests so restore can be asserted without a real terminal.
var (
	getState     = term.GetState
	restoreState = term.Restore
	readPassword = term.ReadPassword
	readLine     = readDevLine
	watchSignal  = restoreOnSignal
	signalNotify = signal.Notify
	signalStop   = signal.Stop
)

// Terminal is a /dev/tty handle. Prompts are written to the same handle they
// are read from so they survive stdout redirection.
type Terminal struct {
	mu sync.Mutex
	f  *os.File
}

func (t *Terminal) Notify(line string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	f := t.f
	t.mu.Unlock()
	if f == nil {
		return
	}
	_, _ = io.WriteString(f, line+"\n")
}

func (t *Terminal) ReadLine(prompt string, secret bool) (string, error) {
	if t == nil {
		return "", errUnavailable
	}
	t.mu.Lock()
	f := t.f
	t.mu.Unlock()
	if f == nil {
		return "", errUnavailable
	}
	fd := int(f.Fd())
	st, err := getState(fd)
	if err != nil {
		return "", err
	}
	var once sync.Once
	doRestore := func() {
		once.Do(func() { _ = restoreState(fd, st) })
	}
	defer doRestore()
	stop := watchSignal(doRestore, t.abort)
	defer stop()

	if _, err := io.WriteString(f, prompt); err != nil {
		return "", err
	}
	if secret {
		b, err := readPassword(fd)
		_, _ = io.WriteString(f, "\n")
		if err != nil {
			clear(b)
			return "", err
		}
		s := string(b)
		clear(b)
		return s, nil
	}
	return readLine(f)
}

func (t *Terminal) Close() error {
	if t == nil {
		return nil
	}
	return t.closeFile()
}

func (t *Terminal) abort() { _ = t.closeFile() }

func (t *Terminal) closeFile() error {
	t.mu.Lock()
	f := t.f
	t.f = nil
	t.mu.Unlock()
	if f == nil {
		return nil
	}
	return f.Close()
}

func readDevLine(f *os.File) (string, error) {
	line, err := bufio.NewReader(f).ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return line, nil
		}
		return "", err
	}
	return line, nil
}

// restoreOnSignal restores termios on SIGINT/SIGTERM, drops this Notify so a
// second Ctrl-C is not swallowed here, then closes the tty to unblock the
// read. It does not os.Exit: Envelope's existing handler still owns cancellation.
func restoreOnSignal(restore, abort func()) func() {
	ch := make(chan os.Signal, 1)
	signalNotify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			signalStop(ch)
			close(done)
		})
	}
	go func() {
		select {
		case <-ch:
			restore()
			stop()
			if abort != nil {
				abort()
			}
		case <-done:
		}
	}()
	return stop
}
