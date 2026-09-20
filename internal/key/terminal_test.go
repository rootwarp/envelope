package key

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenTerminalNoControllingTerminal(t *testing.T) {
	type result struct {
		term Terminal
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		tm, err := OpenTerminal()
		ch <- result{tm, err}
	}()
	select {
	case got := <-ch:
		if got.term != nil {
			t.Cleanup(func() { _ = got.term.Close() })
		}
		if got.err == nil {
			t.Skip("controlling terminal present")
		}
		if !errors.Is(got.err, ErrNoTerminal) {
			t.Fatalf("OpenTerminal: errors.Is(., ErrNoTerminal) = false")
		}
		if got.term != nil {
			t.Fatal("OpenTerminal returned a terminal")
		}
	case <-time.After(time.Second):
		t.Fatal("OpenTerminal blocked")
	}
}

func TestOpenTerminalMapsOpenError(t *testing.T) {
	orig := openTTY
	t.Cleanup(func() { openTTY = orig })
	openTTY = func() (Terminal, error) {
		return nil, errors.New("injected")
	}

	start := time.Now()
	got, err := OpenTerminal()
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("OpenTerminal blocked")
	}
	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("OpenTerminal: errors.Is(., ErrNoTerminal) = false")
	}
	if got != nil {
		t.Fatal("OpenTerminal returned a terminal")
	}
}

func TestSecretReadLineNotRecorded(t *testing.T) {
	hidden := "s3cret-value"
	rec := &recordingTerminal{replies: []string{hidden}}
	got, err := rec.ReadLine("PIN: ", true)
	if err != nil {
		t.Fatal(err)
	}
	if got != hidden {
		t.Fatal("ReadLine did not return the secret")
	}
	rec.Notify("waiting")
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertSecretNotLeaked(t, rec, hidden)

	rec = &recordingTerminal{err: errors.New("read failed")}
	_, err = rec.ReadLine("PIN: ", true)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), hidden) {
		t.Fatal("secret appeared in an error")
	}
	assertSecretNotLeaked(t, rec, hidden)
}

func TestTerminalSourceLazyOnNativeIdentity(t *testing.T) {
	orig := openTTY
	t.Cleanup(func() { openTTY = orig })
	openTTY = func() (Terminal, error) {
		panic("terminal opened")
	}
	src := TerminalSource(func() (Terminal, error) {
		panic("TerminalSource invoked")
	})

	path := filepath.Join(t.TempDir(), "identity.txt")
	id, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(loaded.Zero)

	plain := []byte("native-only")
	ct, err := loaded.EncryptBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loaded.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, plain)
	_ = src
}

type recordingTerminal struct {
	notifies []string
	replies  []string
	err      error
	out      bytes.Buffer
}

func (r *recordingTerminal) Notify(line string) {
	r.notifies = append(r.notifies, line)
	r.out.WriteString(line + "\n")
}

func (r *recordingTerminal) ReadLine(prompt string, secret bool) (string, error) {
	r.out.WriteString(prompt)
	if r.err != nil {
		return "", r.err
	}
	if len(r.replies) == 0 {
		return "", errors.New("no reply")
	}
	line := r.replies[0]
	r.replies = r.replies[1:]
	if !secret {
		r.out.WriteString(line + "\n")
	}
	return line, nil
}

func (r *recordingTerminal) Close() error { return nil }

func assertSecretNotLeaked(t *testing.T, rec *recordingTerminal, hidden string) {
	t.Helper()
	if strings.Contains(rec.out.String(), hidden) {
		t.Fatal("secret appeared in a captured writer")
	}
	for _, line := range rec.notifies {
		if strings.Contains(line, hidden) {
			t.Fatal("secret appeared in a Notify line")
		}
	}
}

var _ Terminal = (*recordingTerminal)(nil)
