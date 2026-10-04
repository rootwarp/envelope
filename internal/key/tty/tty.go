// Package tty opens /dev/tty for interactive identity prompts.
//
// A failed open is the non-TTY detection: there is no separate isatty probe
// and no fallback to stdin, which may be the payload. Nothing here may write
// to stdout. Terminal state is restored on every exit path, including the
// signal path, which is why golang.org/x/term is a dependency rather than a
// hand-rolled termios wrapper. An interrupted prompt returns without waiting
// for its read: nothing wakes a blocked tty read on Linux, so the read runs on
// a goroutine of its own and dies with the process.
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

var (
	errUnavailable = errors.New("terminal is not available")
	errInterrupted = errors.New("prompt interrupted")
)

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
	aborted := make(chan struct{})
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			close(aborted)
			t.abort()
		})
	}
	stop := watchSignal(doRestore, abort)
	defer stop()

	if _, err := io.WriteString(f, prompt); err != nil {
		return "", err
	}
	// Closing f wakes no blocked read on Linux (tty or socket), and while a
	// Read holds f, f.Close defers the close(2) on every OS. So the read gets
	// its own descriptor — abort may close f, and a late read can never land
	// on a reused fd number — and ReadLine returns on abort, not on the read.
	rfd, err := dupFD(fd)
	if err != nil {
		return "", err
	}
	got := make(chan readResult)
	go func() {
		r := readOwned(rfd, f.Name(), secret)
		select {
		case got <- r:
		case <-aborted:
			// Nobody is receiving: a value typed after the abort is dropped.
			clear(r.b)
		}
	}()
	select {
	case r := <-got:
		if secret {
			_, _ = io.WriteString(f, "\n")
		}
		if r.err != nil {
			clear(r.b)
			return "", r.err
		}
		s := string(r.b)
		clear(r.b)
		return s, nil
	case <-aborted:
		return "", errInterrupted
	}
}

type readResult struct {
	b   []byte
	err error
}

// readOwned reads one line from fd, which it owns and closes.
func readOwned(fd int, name string, secret bool) readResult {
	if secret {
		defer func() { _ = closeFD(fd) }()
		b, err := readPassword(fd)
		return readResult{b, err}
	}
	rf := os.NewFile(uintptr(fd), name)
	defer rf.Close()
	line, err := readLine(rf)
	return readResult{[]byte(line), err}
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
// second Ctrl-C is not swallowed here, then aborts the prompt, which returns
// ReadLine and closes the tty. It does not os.Exit: Envelope's existing
// handler still owns cancellation.
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
