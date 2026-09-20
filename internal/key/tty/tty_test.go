package tty

import (
	"errors"
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
	origGet, origRestore, origRead, origWatch := getState, restoreState, readPassword, watchSignal
	t.Cleanup(func() {
		getState, restoreState, readPassword, watchSignal = origGet, origRestore, origRead, origWatch
	})

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
	origGet, origRestore, origRead, origWatch := getState, restoreState, readPassword, watchSignal
	t.Cleanup(func() {
		getState, restoreState, readPassword, watchSignal = origGet, origRestore, origRead, origWatch
	})
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

func dummyFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
