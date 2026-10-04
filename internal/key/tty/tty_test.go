package tty

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

func TestRestoreOnSuccessAndError(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		assertRestore(t, nil)
	})
	t.Run("error", func(t *testing.T) {
		assertRestore(t, errors.New("injected failure"))
	})
}

func assertRestore(t *testing.T, readErr error) {
	t.Helper()
	origGet, origRestore, origEcho, origRead, origWatch := getState, restoreState, noEcho, readPassword, watchSignal
	t.Cleanup(func() {
		getState, restoreState, noEcho, readPassword, watchSignal = origGet, origRestore, origEcho, origRead, origWatch
	})
	noEcho = func(int) error { return nil }

	saved := 0
	restored := 0
	st := &term.State{}
	getState = func(int) (*term.State, error) {
		saved++
		return st, nil
	}
	restoreState = func(_ int, got *term.State) error {
		if got != st {
			t.Error("restore received a different state than save")
		}
		restored++
		return nil
	}
	watchSignal = func(func(), func()) func() { return func() {} }
	hidden := "s3cret-value"
	readPassword = func(int) ([]byte, error) {
		if readErr != nil {
			return []byte(hidden), readErr
		}
		return []byte(hidden), nil
	}

	tm := &Terminal{f: dummyFile(t)}
	got, err := tm.ReadLine("PIN: ", true)
	if readErr != nil {
		if !errors.Is(err, readErr) {
			t.Fatalf("errors.Is(., injected) = false")
		}
		if got != "" {
			t.Fatal("error path returned a line")
		}
		if err != nil && strings.Contains(err.Error(), hidden) {
			t.Fatal("secret appeared in an error")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		if got != hidden {
			t.Fatal("ReadLine did not return the secret")
		}
	}
	if saved == 0 {
		t.Fatal("terminal state was not saved")
	}
	if restored == 0 {
		t.Fatal("terminal state was not restored")
	}
}

func TestSecretNotWritten(t *testing.T) {
	origGet, origRestore, origEcho, origRead, origWatch := getState, restoreState, noEcho, readPassword, watchSignal
	t.Cleanup(func() {
		getState, restoreState, noEcho, readPassword, watchSignal = origGet, origRestore, origEcho, origRead, origWatch
	})
	noEcho = func(int) error { return nil }
	getState = func(int) (*term.State, error) { return &term.State{}, nil }
	restoreState = func(int, *term.State) error { return nil }
	watchSignal = func(func(), func()) func() { return func() {} }
	hidden := "s3cret-value"
	readPassword = func(int) ([]byte, error) { return []byte(hidden), nil }

	f := dummyFile(t)
	tm := &Terminal{f: f}
	got, err := tm.ReadLine("PIN: ", true)
	if err != nil {
		t.Fatal(err)
	}
	if got != hidden {
		t.Fatal("ReadLine did not return the secret")
	}
	tm.Notify("waiting")
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), hidden) {
		t.Fatal("secret appeared in a captured writer")
	}
}

// A restore that has run (the signal path) forbids a later echo-off: the
// signal lands after the prompt write and before echo is turned off.
func TestRestoreBeforeEchoOffSkipsIt(t *testing.T) {
	origGet, origRestore, origEcho, origRead, origWatch := getState, restoreState, noEcho, readPassword, watchSignal
	t.Cleanup(func() {
		getState, restoreState, noEcho, readPassword, watchSignal = origGet, origRestore, origEcho, origRead, origWatch
	})
	getState = func(int) (*term.State, error) { return &term.State{}, nil }
	restored := 0
	restoreState = func(int, *term.State) error {
		restored++
		return nil
	}
	echoOff := false
	noEcho = func(int) error {
		echoOff = true
		return nil
	}
	readPassword = func(int) ([]byte, error) {
		t.Error("read started after the restore")
		return nil, io.EOF
	}
	watchSignal = func(restore, _ func()) func() {
		restore()
		return func() {}
	}

	tm := &Terminal{f: dummyFile(t)}
	_, err := tm.ReadLine("PIN: ", true)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("err = %v, want errInterrupted", err)
	}
	if echoOff {
		t.Fatal("echo was turned off after the restore")
	}
	if restored != 1 {
		t.Fatalf("restored %d times, want 1", restored)
	}
}

// A signal that closes the tty under the prompt write is an interrupt, not a
// write error.
func TestAbortBeforePromptIsInterrupted(t *testing.T) {
	origGet, origRestore, origEcho, origWatch := getState, restoreState, noEcho, watchSignal
	t.Cleanup(func() {
		getState, restoreState, noEcho, watchSignal = origGet, origRestore, origEcho, origWatch
	})
	getState = func(int) (*term.State, error) { return &term.State{}, nil }
	restoreState = func(int, *term.State) error { return nil }
	noEcho = func(int) error {
		t.Error("echo turned off after an abort")
		return nil
	}
	watchSignal = func(restore, abort func()) func() {
		restore()
		abort()
		return func() {}
	}

	tm := &Terminal{f: dummyFile(t)}
	if _, err := tm.ReadLine("PIN: ", true); !errors.Is(err, errInterrupted) {
		t.Fatalf("err = %v, want errInterrupted", err)
	}
}

func TestReadSecretLine(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		err            error
	}{
		{"line", "1234\n", "1234", nil},
		{"crlf", "1234\r\n", "1234", nil},
		{"backspace", "12x\b34\n", "1234", nil},
		{"backspace past start", "\b\b12\n", "12", nil},
		{"grows", strings.Repeat("7", 200) + "\n", strings.Repeat("7", 200), nil},
		{"eof ends a partial line", "1234", "1234", nil},
		{"eof on empty", "", "", io.EOF},
		{"only the first line", "12\n34\n", "12", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readSecretLine(strings.NewReader(tc.in))
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func dummyFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
