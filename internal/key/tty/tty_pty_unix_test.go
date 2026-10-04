//go:build darwin || linux

package tty

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Real termios on a pty, nothing stubbed: the echo-off is local, so only a
// real line discipline proves it never outlives the prompt.

func TestPTYSecretReadHidesAndRestoresEcho(t *testing.T) {
	m, path := openPTY(t)
	probe := openSlave(t, path)
	if !echoOn(t, probe) {
		t.Fatal("pty starts with ECHO off")
	}
	tm := &Terminal{f: openSlave(t, path)}
	ch := readLineAsync(tm)

	readUntil(t, m, "PIN: ")
	waitEcho(t, probe, false)
	if _, err := m.WriteString("1234\n"); err != nil {
		t.Fatal(err)
	}
	var got lineResult
	select {
	case got = <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadLine did not return the line")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.line != "1234" {
		t.Fatalf("ReadLine = %q, want the typed line", got.line)
	}
	if !echoOn(t, probe) {
		t.Fatal("ECHO left off after a completed read")
	}
	if strings.Contains(readUntil(t, m, "\n"), "1234") {
		t.Fatal("the secret was echoed")
	}
}

func TestPTYInterruptRestoresEcho(t *testing.T) {
	m, path := openPTY(t)
	probe := openSlave(t, path)
	tm := &Terminal{f: openSlave(t, path)}
	ch := readLineAsync(tm)

	readUntil(t, m, "PIN: ")
	waitEcho(t, probe, false)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	var got lineResult
	select {
	case got = <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadLine stayed blocked after SIGINT")
	}
	if !errors.Is(got.err, errInterrupted) {
		t.Fatalf("err = %v, want errInterrupted", got.err)
	}
	if !echoOn(t, probe) {
		t.Fatal("ECHO left off after an interrupt")
	}

	// A line typed after the interrupt reaches only the dropped reader, which
	// must not touch termios on its way out.
	if _, err := m.WriteString("late\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if !echoOn(t, probe) {
		t.Fatal("ECHO turned off after the interrupt")
	}
}

type lineResult struct {
	line string
	err  error
}

func readLineAsync(tm *Terminal) <-chan lineResult {
	ch := make(chan lineResult, 1)
	go func() {
		line, err := tm.ReadLine("PIN: ", true)
		ch <- lineResult{line, err}
	}()
	return ch
}

// ptyControl runs op on the master's fd without Fd, which would put the
// master in blocking mode and break its read deadlines.
func ptyControl(t *testing.T, m *os.File, op func(fd int) error) {
	t.Helper()
	rc, err := m.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) { opErr = op(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if opErr != nil {
		t.Fatal(opErr)
	}
}

func openSlave(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func echoOn(t *testing.T, f *os.File) bool {
	t.Helper()
	tios, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	if err != nil {
		t.Fatal(err)
	}
	return tios.Lflag&unix.ECHO != 0
}

func waitEcho(t *testing.T, probe *os.File, on bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for echoOn(t, probe) != on {
		if time.Now().After(deadline) {
			t.Fatalf("ECHO never became %v", on)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// readUntil reads the master until want appears and returns all it read.
func readUntil(t *testing.T, m *os.File, want string) string {
	t.Helper()
	var buf bytes.Buffer
	b := make([]byte, 256)
	if err := m.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(buf.String(), want) {
		n, err := m.Read(b)
		buf.Write(b[:n])
		if err != nil {
			t.Fatalf("reading the pty for %q: %v (read %q)", want, err, buf.String())
		}
	}
	return buf.String()
}
