package pipeline

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestBorrowedTerminalSurvivesPreflight(t *testing.T) {
	skipWindows(t)
	fakeplugin.Install(t, "envtest")
	term := &borrowedTerm{t: t}
	bundle := mustPINBundle(t, term)
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("review-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       t.TempDir(),
		K:            3,
		N:            5,
		Terminal:     term,
	}, io.Discard)
	if err != nil {
		t.Fatalf("preflight invalidated injected terminal: %v", err)
	}
}

func TestBorrowedTerminalSurvivesEveryPreflight(t *testing.T) {
	skipWindows(t)
	fakeplugin.Install(t, "envtest")
	term := &borrowedTerm{t: t}
	bundle := mustPINBundle(t, term)

	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("review-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	shards := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
		Terminal:     term,
	}, io.Discard); err != nil {
		t.Fatalf("split: %v", err)
	}

	out := filepath.Join(t.TempDir(), "out.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{bundle},
		InDirs:        []string{shards},
		OutPath:       out,
		Terminal:      term,
	}, io.Discard); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if _, err := Verify(context.Background(), VerifyOptions{
		IdentityPaths: []string{bundle},
		InDirs:        []string{shards},
		Terminal:      term,
	}, io.Discard); err != nil {
		t.Fatalf("verify: %v", err)
	}

	_, rec := mustNativeID(t)
	if _, err := Bind(context.Background(), BindOptions{
		Mode:       BindAddRecipient,
		Recipients: []string{rec},
		BundlePath: bundle,
		Terminal:   term,
	}, io.Discard); err != nil {
		t.Fatalf("bind -add-recipient: %v", err)
	}
}

func TestHandlesTheRunOpenedAreClosedExactlyOnce(t *testing.T) {
	skipWindows(t)
	fakeplugin.Install(t, "envtest")

	// The property, not a count: every handle the run opened is closed exactly
	// once, the prompting path opens exactly one, and none is used after close.
	// Split may also open a handle when a plugin messages during Wrap.
	t.Run("split", func(t *testing.T) {
		bundle := mustPINBundle(t, answerTerm{})
		in := filepath.Join(t.TempDir(), "in.bin")
		if err := os.WriteFile(in, []byte("owned-split"), 0o600); err != nil {
			t.Fatal(err)
		}
		d, snap := countingDeps(t)
		if _, err := Split(context.Background(), SplitOptions{
			IdentityPath: bundle,
			InPath:       in,
			OutDir:       t.TempDir(),
			K:            3,
			N:            5,
			deps:         d,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		assertRunHandles(t, snap())
	})

	t.Run("restore", func(t *testing.T) {
		bundle, shards := mustPINShards(t, answerTerm{})
		d, snap := countingDeps(t)
		if _, err := Restore(context.Background(), RestoreOptions{
			IdentityPaths: []string{bundle},
			InDirs:        []string{shards},
			OutPath:       filepath.Join(t.TempDir(), "out.bin"),
			deps:          d,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		assertRunHandles(t, snap())
	})

	t.Run("verify", func(t *testing.T) {
		bundle, shards := mustPINShards(t, answerTerm{})
		d, snap := countingDeps(t)
		if _, err := Verify(context.Background(), VerifyOptions{
			IdentityPaths: []string{bundle},
			InDirs:        []string{shards},
			deps:          d,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		assertRunHandles(t, snap())
	})

	t.Run("bind-add-recipient", func(t *testing.T) {
		bundle := mustPINBundle(t, answerTerm{})
		_, rec := mustNativeID(t)
		d, snap := countingDeps(t)
		if _, err := Bind(context.Background(), BindOptions{
			Mode:       BindAddRecipient,
			Recipients: []string{rec},
			BundlePath: bundle,
			deps:       d,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		assertRunHandles(t, snap())
	})
}

func mustPINBundle(t *testing.T, term Terminal) string {
	t.Helper()
	name := "envtest"
	stub := writePluginStub(t, name, fakeplugin.ModePIN)
	rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{stub},
		Recipients:    []string{rec},
		OutPath:       bundle,
		Terminal:      term,
	}, io.Discard); err != nil {
		t.Fatalf("bind create: %v", err)
	}
	return bundle
}

func mustPINShards(t *testing.T, term Terminal) (bundle, shards string) {
	t.Helper()
	bundle = mustPINBundle(t, term)
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("owned-shards"), 0o600); err != nil {
		t.Fatal(err)
	}
	shards = t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
		Terminal:     term,
	}, io.Discard); err != nil {
		t.Fatalf("fixture split: %v", err)
	}
	return bundle, shards
}

// borrowedTerm is an injected terminal. Close fails the test: the pipeline
// must prompt on it and never close it.
type borrowedTerm struct {
	t      *testing.T
	mu     sync.Mutex
	closed bool
}

func (b *borrowedTerm) Notify(string) {}

func (b *borrowedTerm) ReadLine(string, bool) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return "", errors.New("terminal closed")
	}
	return fakeplugin.PIN, nil
}

func (b *borrowedTerm) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.t.Errorf("pipeline closed a borrowed terminal")
	return nil
}

type answerTerm struct{}

func (answerTerm) Notify(string)                         {}
func (answerTerm) ReadLine(string, bool) (string, error) { return fakeplugin.PIN, nil }
func (answerTerm) Close() error                          { return nil }

// runTerm counts one handle the run itself opened.
type runTerm struct {
	mu        sync.Mutex
	closes    int
	reads     int
	notes     int
	usedAfter bool
}

func (r *runTerm) Notify(string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closes > 0 {
		r.usedAfter = true
		return
	}
	r.notes++
}

func (r *runTerm) ReadLine(string, bool) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closes > 0 {
		r.usedAfter = true
		return "", errors.New("terminal closed")
	}
	r.reads++
	return fakeplugin.PIN, nil
}

func (r *runTerm) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closes++
	return nil
}

func countingDeps(t *testing.T) (deps, func() []*runTerm) {
	t.Helper()
	var mu sync.Mutex
	var opened []*runTerm
	d := deps{openTerminal: func() (Terminal, error) {
		tm := &runTerm{}
		mu.Lock()
		opened = append(opened, tm)
		mu.Unlock()
		return tm, nil
	}}
	return d, func() []*runTerm {
		mu.Lock()
		defer mu.Unlock()
		out := make([]*runTerm, len(opened))
		copy(out, opened)
		return out
	}
}

func assertRunHandles(t *testing.T, handles []*runTerm) {
	t.Helper()
	if len(handles) == 0 {
		t.Fatal("prompting run opened no terminal")
	}
	prompted := 0
	for i, h := range handles {
		h.mu.Lock()
		closes, reads, notes, after := h.closes, h.reads, h.notes, h.usedAfter
		h.mu.Unlock()
		if closes != 1 {
			t.Errorf("handle %d: a terminal the run opened was closed %d times, want exactly once", i, closes)
		}
		if after {
			t.Errorf("handle %d: used after close", i)
		}
		if reads > 0 {
			prompted++
		} else if notes == 0 {
			// A handle opened and never used is a probe the run threw away,
			// not the one it prompts on and not a Wrap message.
			t.Errorf("handle %d: opened and never used", i)
		}
	}
	if prompted != 1 {
		t.Errorf("prompting path opened %d handles, want exactly one", prompted)
	}
}
