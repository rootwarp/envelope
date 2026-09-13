package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// FR-25 acceptance suite. Discoverable with:
//
//	go test ./... -run TestAcceptance_
//
//	 1  TestAcceptance_RoundTrip1MiB           internal/pipeline
//	 2  TestAcceptance_TwoShardsDeleted        internal/pipeline
//	 3  TestAcceptance_OneCorruptShard         internal/pipeline
//	 4  TestAcceptance_TooManyLosses           cmd/envelope       (this file, via run)
//	 5  TestAcceptance_WrongIdentity           cmd/envelope       (this file, via run)
//	 6  TestAcceptance_TamperedMAC             internal/pipeline
//	 7  TestAcceptance_IdentityMode0600        internal/key
//	 8  TestAcceptance_RestoreDestMode0600     internal/pipeline
//	 9  TestAcceptance_ForgottenClose          internal/pipeline
//	10  TestAcceptance_SplitNonEmptyOut        cmd/envelope       (this file, via run)
//	11  TestAcceptance_PreexistingIdentity     internal/key       (pair with LeftoverPartial)
//	    TestAcceptance_LeftoverPartial         internal/pipeline  (pair with PreexistingIdentity)
//	12  TestAcceptance_SIGINTMidRestore        cmd/envelope       (this file)
//
// Items 6, 9, 11 and 12 each have two contributing tests; the TestAcceptance_
// comment names both and says why. Item 11 is two refusals sharing one bullet
// and cannot be a single test.

func TestAcceptance_TooManyLosses(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 4096)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
	for _, name := range []string{"shard-00", "shard-01", "shard-02"} {
		if err := os.Remove(filepath.Join(shards, name)); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	assertAbsent(t, out)
	assertAbsent(t, out+".partial")
}

func TestAcceptance_WrongIdentity(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	other := filepath.Join(dir, "other.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	mustRun(t, "keygen", "-out", other)
	writeOpaque(t, in, 4096)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", other, "-in", shards, "-out", out}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	assertAbsent(t, out)
	assertAbsent(t, out+".partial")
}

func TestAcceptance_SplitNonEmptyOut(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)
	if err := os.MkdirAll(shards, 0o700); err != nil {
		t.Fatal(err)
	}
	occupant := filepath.Join(shards, "occupant")
	want := make([]byte, 32)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(occupant, want, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"split", "-identity", id, "-in", in, "-out", shards}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}

	entries, err := os.ReadDir(shards)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	if len(names) != 1 || names[0] != "occupant" {
		t.Fatalf("out dir listing = %v, want [occupant]", names)
	}
	got, err := os.ReadFile(occupant)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("occupant bytes changed")
	}
}

// TestAcceptance_SIGINTMidRestore is FR-25 item 12.
//
// Contributing tests: TestContextCancelMidCopy (M5b.2, ctxReader cancel — the
// primary cleanup-path gate, no signal) and TestSIGINTMidRestore (M6.2, a real
// SIGINT to a child process). Two exist because the mechanism is cancellation
// of the in-flight copy, already proved without a signal, while FR-34's AC
// names a real SIGINT (plan R9). In-process run() cannot take a SIGINT without
// signaling the test itself, so this named case uses the child-process path.
func TestAcceptance_SIGINTMidRestore(t *testing.T) {
	testSignalMidRestore(t, os.Interrupt)
}
