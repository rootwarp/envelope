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

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows support is TODO")
	}
}

type stubTerm struct{}

func (stubTerm) Notify(string)                         {}
func (stubTerm) ReadLine(string, bool) (string, error) { return "", errors.New("no pin") }
func (stubTerm) Close() error                          { return nil }

func writePluginIdentity(t *testing.T, name string, mode fakeplugin.Mode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin.txt")
	if err := os.WriteFile(path, []byte(fakeplugin.Identity(name, mode)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWrongIdentityNamesNativeSource(t *testing.T) {
	skipWindows(t)
	restore, _ := splitFixture(t)
	wrong := filepath.Join(t.TempDir(), "paper.txt")
	if _, err := key.Create(wrong); err != nil {
		t.Fatal(err)
	}
	name := "envtest"
	fakeplugin.Install(t, name)
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModeOK)
	// argv order is plugin then native; LoadSet hoists the native.
	restore.IdentityPaths = []string{pluginPath, wrong}
	restore.OutPath = filepath.Join(t.TempDir(), "out.bin")

	testOpenTerminal = func() (Terminal, error) {
		return nil, key.ErrNoTerminal
	}
	t.Cleanup(func() { testOpenTerminal = nil })

	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, crypt.ErrWrongIdentity) {
		t.Fatalf("errors.Is(., ErrWrongIdentity) = false: %v", err)
	}
	got := err.Error()
	if !strings.Contains(got, wrong) {
		t.Fatalf("err %q does not name native path %s", got, wrong)
	}
	if strings.Contains(got, pluginPath) {
		t.Fatalf("err %q names plugin path %s", got, pluginPath)
	}
	assertNoOutOrPartial(t, restore.OutPath)
	if n := len(fakeplugin.Invocations(t)); n != 0 {
		t.Fatalf("plugin invocations = %d, want 0", n)
	}
}

func TestRestoreTwoIdentityPaths(t *testing.T) {
	restore, _ := splitFixture(t)
	other := filepath.Join(t.TempDir(), "other.txt")
	if _, err := key.Create(other); err != nil {
		t.Fatal(err)
	}
	// First path is the owner; YK-08 will try later identities on decrypt.
	restore.IdentityPaths = []string{restore.IdentityPaths[0], other}
	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("restored empty file")
	}
}

func TestInteractiveWithoutTerminalRefused(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	restore, _ := splitFixture(t)
	restore.IdentityPaths = []string{writePluginIdentity(t, name, fakeplugin.ModePIN)}
	restore.OutPath = filepath.Join(t.TempDir(), "out.bin")

	opened := false
	testOpenTerminal = func() (Terminal, error) {
		opened = true
		return nil, key.ErrNoTerminal
	}
	t.Cleanup(func() { testOpenTerminal = nil })

	_, err := Restore(context.Background(), restore, io.Discard)
	if !errors.Is(err, ErrNoPinTerminal) {
		t.Fatalf("errors.Is(., ErrNoPinTerminal) = false: %v", err)
	}
	if err.Error() != ErrNoPinTerminal.Error() {
		t.Fatalf("Error() = %q, want %q", err.Error(), ErrNoPinTerminal.Error())
	}
	if !opened {
		t.Fatal("did not probe the terminal")
	}
	assertNoOutOrPartial(t, restore.OutPath)
	if n := len(fakeplugin.Invocations(t)); n != 0 {
		t.Fatalf("plugin invocations = %d, want 0", n)
	}
}

func TestVerifyInteractiveWithoutTerminalRefused(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	restore, _ := splitFixture(t)
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModePIN)

	testOpenTerminal = func() (Terminal, error) {
		return nil, key.ErrNoTerminal
	}
	t.Cleanup(func() { testOpenTerminal = nil })

	rep, err := Verify(context.Background(), VerifyOptions{
		IdentityPaths: []string{pluginPath},
		InDirs:        restore.InDirs,
	}, io.Discard)
	if rep != nil {
		t.Fatal("report is not nil")
	}
	if !errors.Is(err, ErrNoPinTerminal) {
		t.Fatalf("errors.Is(., ErrNoPinTerminal) = false: %v", err)
	}
	if n := len(fakeplugin.Invocations(t)); n != 0 {
		t.Fatalf("plugin invocations = %d, want 0", n)
	}
}

func TestNativeWithPluginDoesNotOpenTerminal(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	restore, _ := splitFixture(t)
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModePIN)
	restore.IdentityPaths = []string{restore.IdentityPaths[0], pluginPath}

	testOpenTerminal = func() (Terminal, error) {
		t.Fatal("terminal opened for a native-first set")
		return nil, key.ErrNoTerminal
	}
	t.Cleanup(func() { testOpenTerminal = nil })

	if _, err := Restore(context.Background(), restore, io.Discard); err != nil {
		t.Fatal(err)
	}
	if n := len(fakeplugin.Invocations(t)); n != 0 {
		t.Fatalf("plugin invocations = %d, want 0", n)
	}
}

func TestResolvedPluginPathOnceAbsolute(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	dir := fakeplugin.Install(t, name)
	restore, _ := splitFixture(t)
	restore.IdentityPaths = []string{writePluginIdentity(t, name, fakeplugin.ModeOK)}
	restore.OutPath = filepath.Join(t.TempDir(), "out.bin")
	restore.Terminal = stubTerm{}

	var status bytes.Buffer
	_, err := Restore(context.Background(), restore, &status)
	if !errors.Is(err, key.ErrNoScalar) {
		t.Fatalf("errors.Is(., ErrNoScalar) = false: %v", err)
	}
	assertNoOutOrPartial(t, restore.OutPath)
	if n := len(fakeplugin.Invocations(t)); n != 0 {
		t.Fatalf("plugin invocations = %d, want 0 (LookPath is not a launch)", n)
	}

	want := filepath.Join(dir, "age-plugin-"+name)
	if !filepath.IsAbs(want) {
		t.Fatalf("Install path is relative: %q", want)
	}
	got := status.String()
	if strings.Count(got, want) != 1 {
		t.Fatalf("status %q: want the absolute plugin path once", got)
	}
	if !strings.Contains(got, "using "+want) {
		t.Fatalf("status %q missing %q", got, "using "+want)
	}
}
