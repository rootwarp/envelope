package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestSplitPassphraseRecipientUsage(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	out := filepath.Join(dir, "shards")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)

	var stdout, stderr bytes.Buffer
	code := run([]string{"split", "-identity", id, "-in", in, "-out", out, "-recipient", "correct horse battery staple"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit=%d want %d\nstderr=%q", code, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
	if !strings.Contains(stderr.String(), "-recipient") {
		t.Fatalf("stderr %q does not name -recipient", stderr.String())
	}
	assertContractOnStderr(t, stderr.String(), usageSplit)
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrote shards for a passphrase recipient")
	}
}

func TestSplitNonRecipientUsage(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	out := filepath.Join(dir, "shards")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)

	bad := "not-a-recipient"
	var stdout, stderr bytes.Buffer
	code := run([]string{"split", "-identity", id, "-in", in, "-out", out, "-recipient", bad}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit=%d want %d\nstderr=%q", code, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
	if !strings.Contains(stderr.String(), `"`+bad+`"`) {
		t.Fatalf("stderr %q does not quote %q", stderr.String(), bad)
	}
	assertContractOnStderr(t, stderr.String(), usageSplit)
}

func TestSplitBindRestoreCmp(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	testTerminal = stubTerm{}
	t.Cleanup(func() { testTerminal = nil })

	dir := t.TempDir()
	stub := filepath.Join(dir, "stub.txt")
	if err := os.WriteFile(stub, []byte(fakeplugin.Identity(name, fakeplugin.ModeOK)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	bundle := filepath.Join(dir, "bundle.txt")
	mustRun(t, "bind", "-identity", stub, "-recipient", rec, "-out", bundle)

	in := filepath.Join(dir, "in.bin")
	writeOpaque(t, in, 1<<20)
	want, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	shards := filepath.Join(dir, "shards")
	mustRun(t, "split", "-identity", bundle, "-in", in, "-out", shards, "-k", "3", "-n", "5")
	for _, name := range []string{"shard-03", "shard-04"} {
		if err := os.Remove(filepath.Join(shards, name)); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "restore", "-identity", bundle, "-in", shards, "-out", out)
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("restored bytes differ")
	}
}
