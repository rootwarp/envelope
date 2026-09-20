package main

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestRecipientBundle(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "id.txt")
	mustRun(t, "keygen", "-out", id)
	recA := mustRecipient(t, id)
	id2 := filepath.Join(dir, "id2.txt")
	mustRun(t, "keygen", "-out", id2)
	recB := mustRecipient(t, id2)
	bundle := filepath.Join(dir, "bundle.txt")
	mustRun(t, "bind", "-identity", id, "-recipient", recA, "-recipient", recB, "-out", bundle)

	var stdout, stderr bytes.Buffer
	code := run([]string{"recipient", "-identity", bundle}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitOK, stderr.Len())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr has %d bytes, want 0", stderr.Len())
	}
	want := recA + "\n" + recB + "\n"
	if stdout.String() != want {
		t.Fatalf("stdout %q, want %q", stdout.String(), want)
	}
	assertNoIdentityBasedOutput(t, stdout.String(), stderr.String())
}

func TestRecipientPluginStub(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginIdentity(t, name, fakeplugin.ModeOK)
	before := len(fakeplugin.Invocations(t))

	var stdout, stderr bytes.Buffer
	code := run([]string{"recipient", "-identity", stub}, &stdout, &stderr)
	if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
		t.Fatalf("plugin processes = %d, want 0", n)
	}
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitFailure, stderr.Len())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
	got := stderr.String()
	if !strings.Contains(got, key.ErrNoLocalRecipient.Error()) {
		t.Fatalf("stderr missing %q (len=%d)", key.ErrNoLocalRecipient.Error(), stderr.Len())
	}
	if !strings.Contains(got, "envelope bind") {
		t.Fatalf("stderr does not name envelope bind (len=%d)", stderr.Len())
	}
	if strings.Contains(got, "--list-all") {
		t.Fatal("stderr names --list-all; that belongs in docs/")
	}
	assertNoIdentityBasedOutput(t, stdout.String(), got)
}

func TestRecipientIdentityNotRepeatable(t *testing.T) {
	root := newApp(io.Discard, io.Discard)
	var rec *cli.Command
	for _, c := range root.Commands {
		if c.Name == "recipient" {
			rec = c
			break
		}
	}
	if rec == nil {
		t.Fatal("recipient command missing")
	}
	found := false
	for _, f := range rec.Flags {
		for _, n := range f.Names() {
			if n != "identity" {
				continue
			}
			found = true
			if _, ok := f.(*cli.StringSliceFlag); ok {
				t.Fatal("recipient -identity is repeatable")
			}
			if _, ok := f.(*cli.StringFlag); !ok {
				t.Fatalf("recipient -identity type %T, want StringFlag", f)
			}
		}
	}
	if !found {
		t.Fatal("recipient has no -identity")
	}
}

func TestRecipientMatrixNoIdentityBased(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "id.txt")
	mustRun(t, "keygen", "-out", id)
	rec := mustRecipient(t, id)
	bundle := mustBindCreate(t, id, rec)

	cases := []struct {
		name string
		path string
		code int
	}{
		{name: "file", path: id, code: exitOK},
		{name: "bundle", path: bundle, code: exitOK},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{"recipient", "-identity", tt.path}, &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit = %d, want %d (stderr len=%d)", code, tt.code, stderr.Len())
			}
			assertNoIdentityBasedOutput(t, stdout.String(), stderr.String())
		})
	}
}

func assertNoIdentityBasedOutput(t *testing.T, streams ...string) {
	t.Helper()
	needle := "<identity-based" + " recipient>"
	for _, s := range streams {
		if strings.Contains(s, needle) {
			t.Fatal("output contains the plugin identity recipient literal")
		}
	}
}
