// Package tty opens /dev/tty for interactive identity prompts.
//
// A failed open is the non-TTY detection: there is no separate isatty probe
// and no fallback to stdin, which may be the payload. Nothing here may write
// to stdout. Terminal state is saved and restored by golang.org/x/term on
// every exit path, including the signal path. An interrupted prompt returns
// without waiting for its read: nothing wakes a blocked tty read on Linux, so
// the read runs on a goroutine of its own and dies with the process. That is
// why echo-off is local rather than x/term's ReadPassword: there it is bundled
// with the read, whose deferred restore never runs if the read never returns,
// so a late echo-off could outlive the restore and strand the shell. Here it is
// ordered against the restore under one lock.
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
	noEcho       = disableEcho
	readPassword = readSecretFD
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
	// The read gets its own descriptor, taken before anything can abort:
	// abort closes f, which frees fd's number. Closing f wakes no blocked read
	// on Linux (tty or socket), and while a Read holds f, f.Close defers the
	// close(2) on every OS, so ReadLine returns on abort, not on the read.
	rfd, err := dupFD(fd)
	if err != nil {
		return "", err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = closeFD(rfd)
		}
	}()

	// Once restore has run, echo is never turned off again.
	var mu sync.Mutex
	restored := false
	doRestore := func() {
		mu.Lock()
		defer mu.Unlock()
		if !restored {
			restored = true
			_ = restoreState(fd, st)
		}
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
		select {
		case <-aborted:
			// abort closed f under the write.
			return "", errInterrupted
		default:
		}
		return "", err
	}
	if secret {
		mu.Lock()
		err := errInterrupted
		if !restored {
			err = noEcho(fd)
		}
		mu.Unlock()
		if err != nil {
			return "", err
		}
	}
	got := make(chan readResult)
	handedOff = true
	read := readOwned(readPassword, readLine, f.Name(), secret)
	go func() {
		r := read(rfd)
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

// readOwned binds the read functions on the caller's goroutine, so a reader
// that outlives ReadLine never touches the package hooks. The returned func
// reads one line from fd, which it owns and closes.
func readOwned(secretRead func(int) ([]byte, error), plainRead func(*os.File) (string, error), name string, secret bool) func(fd int) readResult {
	if secret {
		return func(fd int) readResult {
			defer func() { _ = closeFD(fd) }()
			b, err := secretRead(fd)
			return readResult{b, err}
		}
	}
	return func(fd int) readResult {
		rf := os.NewFile(uintptr(fd), name)
		defer rf.Close()
		line, err := plainRead(rf)
		return readResult{[]byte(line), err}
	}
}

// readSecretLine is x/term's readPasswordLine for a unix tty: \r is dropped,
// \b deletes, \n ends the line, and EOF ends a non-empty one. Bytes it lets go
// of — deleted, or left behind when the buffer grows — are cleared.
func readSecretLine(r io.Reader) ([]byte, error) {
	var c [1]byte
	ret := make([]byte, 0, 64)
	for {
		n, err := r.Read(c[:])
		if n > 0 {
			switch c[0] {
			case '\b':
				if len(ret) > 0 {
					ret[len(ret)-1] = 0
					ret = ret[:len(ret)-1]
				}
			case '\n':
				return ret, nil
			case '\r':
			default:
				if len(ret) == cap(ret) {
					grown := make([]byte, len(ret), 2*cap(ret))
					copy(grown, ret)
					clear(ret)
					ret = grown
				}
				ret = append(ret, c[0])
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(ret) > 0 {
				return ret, nil
			}
			clear(ret)
			return nil, err
		}
	}
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
