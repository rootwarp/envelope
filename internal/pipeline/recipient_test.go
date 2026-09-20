package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestRecipientFileIdentity(t *testing.T) {
	path, rec := mustNativeID(t)
	got, err := Recipient(RecipientOptions{IdentityPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != rec {
		t.Fatalf("got %q, want [%s]", got, rec)
	}
	assertNoIdentityBased(t, strings.Join(got, "\n"))
}

func TestRecipientBundleOrder(t *testing.T) {
	pathA, recA := mustNativeID(t)
	_, recB := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{pathA},
		Recipients:    []string{recA, recB},
		OutPath:       out,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := Recipient(RecipientOptions{IdentityPath: out})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != recA || got[1] != recB {
		t.Fatalf("got %q, want [%s %s]", got, recA, recB)
	}
	assertNoIdentityBased(t, strings.Join(got, "\n"))
}

func TestRecipientBundlePluginZeroInteractions(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
	pluginRec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	_, nativeRec := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{stub},
		Recipients:    []string{pluginRec, nativeRec},
		OutPath:       out,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	before := len(fakeplugin.Invocations(t))
	got, err := Recipient(RecipientOptions{IdentityPath: out, Terminal: stubTerm{}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
		t.Fatalf("plugin processes = %d, want 0", n)
	}
	if len(got) != 2 || got[0] != pluginRec || got[1] != nativeRec {
		t.Fatalf("got %q, want plugin then native", got)
	}
	assertNoIdentityBased(t, strings.Join(got, "\n"))
}

func TestRecipientPluginStub(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
	before := len(fakeplugin.Invocations(t))
	got, err := Recipient(RecipientOptions{IdentityPath: stub, Terminal: stubTerm{}})
	if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
		t.Fatalf("plugin processes = %d, want 0", n)
	}
	if !errors.Is(err, ErrNoLocalRecipient) {
		t.Fatalf("errors.Is(., ErrNoLocalRecipient) = false: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "envelope bind") {
		t.Fatalf("error %v does not name envelope bind", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want empty", got)
	}
	assertNoIdentityBased(t, err.Error())
}

func TestRecipientIncompleteBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.txt")
	if err := os.WriteFile(path, []byte("# envelope-bundle: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Recipient(RecipientOptions{IdentityPath: path})
	if !errors.Is(err, key.ErrBundleField) {
		t.Fatalf("errors.Is(., ErrBundleField) = false: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestRecipientNoStringerAssertion(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "recipient.go"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("fmt.Stringer")) {
		t.Fatal("fmt.Stringer assertion would print a plugin identity's local recipient")
	}
}

func assertNoIdentityBased(t *testing.T, ss ...string) {
	t.Helper()
	needle := "<identity-based" + " recipient>"
	for _, s := range ss {
		if strings.Contains(s, needle) {
			t.Fatal("output contains the plugin identity recipient literal")
		}
	}
}
