package pipeline

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/rootwarp/envelope/internal/key"
)

func TestZeroDepsIsProductionOpener(t *testing.T) {
	type result struct {
		err error
	}
	s := newSession(context.Background(), nil, deps{}, io.Discard)
	ch := make(chan result, 1)
	go func() {
		ch <- result{s.requireTerminal()}
	}()
	select {
	case got := <-ch:
		t.Cleanup(func() { _ = s.Close() })
		if got.err == nil {
			if !s.owned || s.term == nil {
				t.Fatal("production opener returned no handle")
			}
			t.Skip("controlling terminal present")
		}
		if !errors.Is(got.err, key.ErrNoTerminal) {
			t.Fatalf("errors.Is(., ErrNoTerminal) = false: %v", got.err)
		}
		if s.term != nil {
			t.Fatal("failed open left a terminal")
		}
	case <-time.After(time.Second):
		t.Fatal("production opener blocked")
	}
}

func TestSessionCloseIdempotentNeverClosesBorrowed(t *testing.T) {
	borrowed := &borrowedTerm{t: t}
	s := newSession(context.Background(), borrowed, deps{
		openTerminal: func() (Terminal, error) {
			t.Fatal("opener called for a borrowed terminal")
			return nil, key.ErrNoTerminal
		},
	}, io.Discard)
	if _, err := s.source()(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireTerminalResolvesOneHandle(t *testing.T) {
	var none *session
	if err := none.requireTerminal(); !errors.Is(err, key.ErrNoTerminal) {
		t.Fatalf("nil session: %v", err)
	}

	var opened []*runTerm
	s := newSession(context.Background(), nil, deps{openTerminal: func() (Terminal, error) {
		tm := &runTerm{}
		opened = append(opened, tm)
		return tm, nil
	}}, io.Discard)
	if err := s.requireTerminal(); err != nil {
		t.Fatal(err)
	}
	if err := s.requireTerminal(); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 {
		t.Fatalf("opens = %d, want the one handle", len(opened))
	}
	opened[0].mu.Lock()
	closes := opened[0].closes
	opened[0].mu.Unlock()
	if closes != 0 {
		t.Fatalf("requireTerminal closed the handle %d times", closes)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	opened[0].mu.Lock()
	closes = opened[0].closes
	opened[0].mu.Unlock()
	if closes != 1 {
		t.Fatalf("Close closed the handle %d times, want once", closes)
	}
}

func TestSetClosesTerminalItOpened(t *testing.T) {
	// A terminal the run opened is closed by the run's cleanup, once.
	// The next run opens a fresh handle. A second cleanup closes nothing further.
	var opened []*runTerm
	open := func() (Terminal, error) {
		tm := &runTerm{}
		opened = append(opened, tm)
		return tm, nil
	}
	s := newSession(context.Background(), nil, deps{openTerminal: open}, io.Discard)
	term, err := s.source()()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := term.ReadLine("PIN: ", true); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 {
		t.Fatalf("run opened %d terminals, want the one it prompts on", len(opened))
	}
	assertRunHandles(t, opened[:1])

	s2 := newSession(context.Background(), nil, deps{openTerminal: open}, io.Discard)
	term, err = s2.source()()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := term.ReadLine("PIN: ", true); err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 2 || opened[0] == opened[1] {
		t.Fatalf("reuse after cleanup opened %d handles, want a fresh one", len(opened))
	}
	assertRunHandles(t, opened[:1])
	assertRunHandles(t, opened[1:])
}
