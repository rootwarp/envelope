package key

import (
	"errors"
	"sync"
	"testing"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestSetClosesTerminalItOpened(t *testing.T) {
	var none *Set
	if err := none.ResolveTerminal(); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("nil set: %v", err)
	}
	none.Zero()
	none.Zero()
	(&Set{}).Zero()
	if err := (*ClientUI)(nil).Close(); err != nil {
		t.Fatalf("nil UI close: %v", err)
	}

	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	var mu sync.Mutex
	var opened []*ownedTerm
	src := func() (Terminal, error) {
		tm := &ownedTerm{}
		mu.Lock()
		opened = append(opened, tm)
		mu.Unlock()
		return tm, nil
	}
	path := writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModePIN)+"\n")
	set, err := LoadSet([]string{path}, src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)

	got, err := set.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != uiPlain {
		t.Fatalf("plaintext = %q", got)
	}

	// The run's cleanup, twice: the second call must not close again.
	set.Zero()
	set.Zero()
	snapshot := copyOwned(t, &mu, opened)
	if len(snapshot) != 1 {
		t.Fatalf("run opened %d terminals, want the one it prompts on", len(snapshot))
	}
	assertOwnedClosedOnce(t, snapshot[0])

	got, err = set.DecryptBytes(ct)
	if err != nil {
		t.Fatalf("reuse after cleanup: %v", err)
	}
	if string(got) != uiPlain {
		t.Fatalf("plaintext after reuse = %q", got)
	}
	snapshot = copyOwned(t, &mu, opened)
	if len(snapshot) != 2 || snapshot[0] == snapshot[1] {
		t.Fatalf("reuse after cleanup opened %d handles, want a fresh one", len(snapshot))
	}
	assertOwnedClosedOnce(t, snapshot[0])

	set.Zero()
	assertOwnedClosedOnce(t, snapshot[0])
	assertOwnedClosedOnce(t, snapshot[1])
}

func copyOwned(t *testing.T, mu *sync.Mutex, opened []*ownedTerm) []*ownedTerm {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	out := make([]*ownedTerm, len(opened))
	copy(out, opened)
	return out
}

func assertOwnedClosedOnce(t *testing.T, h *ownedTerm) {
	t.Helper()
	h.mu.Lock()
	closes, after := h.closes, h.usedAfter
	h.mu.Unlock()
	if closes != 1 {
		t.Errorf("a terminal the run opened is closed by the run's cleanup: closes=%d, want 1", closes)
	}
	if after {
		t.Error("a terminal the run opened was used after it was closed")
	}
}

// ownedTerm is production-shaped: each open is a new handle, and a use after
// close is visible.
type ownedTerm struct {
	mu        sync.Mutex
	closes    int
	usedAfter bool
}

func (o *ownedTerm) Notify(string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closes > 0 {
		o.usedAfter = true
	}
}

func (o *ownedTerm) ReadLine(string, bool) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closes > 0 {
		o.usedAfter = true
		return "", errors.New("terminal closed")
	}
	return fakeplugin.PIN, nil
}

func (o *ownedTerm) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closes++
	return nil
}
