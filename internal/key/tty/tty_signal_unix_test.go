//go:build unix

package tty

import (
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func TestReadLineSignalRestoresAbortsAndStops(t *testing.T) {
	origGet, origRestore, origRead, origWatch, origStop := getState, restoreState, readPassword, watchSignal, signalStop
	t.Cleanup(func() {
		getState, restoreState, readPassword, watchSignal, signalStop = origGet, origRestore, origRead, origWatch, origStop
	})

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "tty")
	peer := os.NewFile(uintptr(fds[1]), "peer")
	t.Cleanup(func() {
		peer.Close()
		f.Close()
	})

	var restored atomic.Int32
	st := &term.State{}
	getState = func(int) (*term.State, error) { return st, nil }
	restoreState = func(_ int, got *term.State) error {
		if got != st {
			t.Error("restore received a different state than save")
		}
		restored.Add(1)
		return nil
	}

	var stopWhileOpen atomic.Bool
	signalStop = func(c chan<- os.Signal) {
		if fdIsOpen(fds[0]) {
			stopWhileOpen.Store(true)
		}
		origStop(c)
	}

	entered := make(chan struct{})
	hidden := "s3cret-value"
	readPassword = func(fd int) ([]byte, error) {
		close(entered)
		buf := make([]byte, len(hidden))
		copy(buf, hidden)
		_, err := syscall.Read(fd, buf)
		clear(buf)
		return nil, err
	}

	tm := &Terminal{f: f}
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := tm.ReadLine("PIN: ", true)
		ch <- result{line, err}
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadLine did not enter the blocked read")
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}

	var got result
	select {
	case got = <-ch:
	case <-time.After(2 * time.Second):
		_ = tm.Close()
		t.Fatal("ReadLine stayed blocked after SIGINT")
	}
	if got.err == nil {
		t.Fatal("ReadLine returned success after SIGINT")
	}
	if got.line != "" {
		t.Fatal("ReadLine returned a secret after SIGINT")
	}
	if strings.Contains(got.err.Error(), hidden) {
		t.Fatal("secret appeared in an error")
	}
	if restored.Load() == 0 {
		t.Fatal("terminal state was not restored")
	}
	if !stopWhileOpen.Load() {
		t.Fatal("Notify still owned SIGINT when the tty was closed")
	}

	probe := make(chan os.Signal, 1)
	signal.Notify(probe, os.Interrupt)
	t.Cleanup(func() { signal.Stop(probe) })
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probe:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGINT was not delivered after this Notify stopped")
	}
	if restored.Load() != 1 {
		t.Fatal("restore ran again; this Notify still owned SIGINT")
	}
}

func fdIsOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}
