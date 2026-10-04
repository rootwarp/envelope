package key

import (
	"context"
	"errors"
	"testing"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

type cancelWalkTerm struct {
	cancel  context.CancelFunc
	prompts int
}

func (t *cancelWalkTerm) Notify(string) {}

func (t *cancelWalkTerm) ReadLine(string, bool) (string, error) {
	t.prompts++
	if t.prompts == 1 {
		t.cancel()
		return "", context.Canceled
	}
	return fakeplugin.PIN, nil
}

func (t *cancelWalkTerm) Close() error { return nil }

func (t *cancelWalkTerm) source() TerminalSource {
	return func() (Terminal, error) { return t, nil }
}

func TestCancelledPromptStopsPluginWalk(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	term := &cancelWalkTerm{cancel: cancel}
	paths := []string{
		writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModePIN)+"\n"),
		writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModePIN)+"\n"),
	}
	set, err := LoadSet(paths, term.source(), WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)

	before := len(fakeplugin.Invocations(t))
	_, err = set.DecryptBytes(ct)
	if err == nil {
		t.Fatal("err = nil, want cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(., context.Canceled) = false: %v", err)
	}
	if term.prompts != 1 {
		t.Fatalf("prompts = %d, want 1", term.prompts)
	}
	if set.Interactions() != 1 {
		t.Fatalf("Interactions = %d, want 1", set.Interactions())
	}
	if got := len(fakeplugin.Invocations(t)) - before; got != 1 {
		t.Fatalf("plugin invocations = %d, want 1", got)
	}
}

func TestCancelledSetStartsNoPluginAtAnySite(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	paths := []string{
		writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModeOK)+"\n"),
		writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModeOK)+"\n"),
	}
	set, err := LoadSet(paths, (&uiTerm{}).source(), WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)

	before := len(fakeplugin.Invocations(t))
	if _, err := set.DecryptBytes(ct); err != nil {
		t.Fatal(err)
	}
	if set.Interactions() != 1 {
		t.Fatalf("Interactions after first = %d, want 1", set.Interactions())
	}
	if got := len(fakeplugin.Invocations(t)) - before; got != 1 {
		t.Fatalf("plugin invocations after first = %d, want 1", got)
	}

	cancel()
	_, err = set.DecryptBytes(ct)
	if err == nil {
		t.Fatal("err = nil, want cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(., context.Canceled) = false: %v", err)
	}
	if set.Interactions() != 1 {
		t.Fatalf("Interactions after second = %d, want 1", set.Interactions())
	}
	if got := len(fakeplugin.Invocations(t)) - before; got != 1 {
		t.Fatalf("plugin invocations after second = %d, want 1", got)
	}
}
