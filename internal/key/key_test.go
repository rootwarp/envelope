package key

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestCreateRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	want := make([]byte, 32)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Create(path)
	if !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("Create existing: errors.Is(., ErrIdentityExists) = false")
	}
	if errors.Is(err, ErrNotSingleIdentity) || errors.Is(err, ErrNotX25519) || errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("Create existing: error matched a different sentinel")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestLoadRejectsTwoIdentities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	before := []byte(a.String() + "\n" + b.String() + "\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrNotSingleIdentity)
}

func TestLoadRejectsZeroIdentities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	before := []byte("# comment only\n\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrNotSingleIdentity)
}

func TestLoadRejectsNonX25519(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	h, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	before := []byte(h.String() + "\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrNotX25519)
}

func TestLoadRejectsLeadingSpace(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	assertLoadRejectsInvalid(t, []byte(" "+id.String()+"\n"))
}

func TestLoadRejectsBOM(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(id.String() + "\n")
	before := append([]byte{0xEF, 0xBB, 0xBF}, line...)
	assertLoadRejectsInvalid(t, before)
}

func TestLoadRejectsLowercased(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	assertLoadRejectsInvalid(t, []byte(strings.ToLower(id.String())+"\n"))
}

func TestCreatedIdentityAcceptedByAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := Create(path); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("ParseIdentities count = %d, want 1", len(ids))
	}
	if _, ok := ids[0].(*age.X25519Identity); !ok {
		t.Fatalf("ParseIdentities type = %T, want *age.X25519Identity", ids[0])
	}

	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func assertLoadRejectsInvalid(t *testing.T, before []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrInvalidIdentity)
}

func assertLoadRejects(t *testing.T, dir, path string, before []byte, want error) {
	t.Helper()
	_, err := Load(path)
	if !errors.Is(err, want) {
		t.Fatalf("errors.Is(., %v) = false", want)
	}
	for _, other := range []error{ErrIdentityExists, ErrNotSingleIdentity, ErrNotX25519, ErrInvalidIdentity} {
		if other != want && errors.Is(err, other) {
			t.Fatalf("error also matched %v", other)
		}
	}
	assertNoIdentityPrefix(t, err)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, before)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("dir entries = %d, want 1 (no extra output)", len(entries))
	}
}

func assertNoIdentityPrefix(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	// Split at runtime so tracked files never contain the contiguous FR-24 needle.
	prefix := "AGE-SECRET-KEY-" + "1"
	msg := err.Error()
	if strings.Contains(msg, prefix) || strings.Contains(msg, strings.ToLower(prefix)) {
		t.Fatal("error string contains identity prefix")
	}
}

func assertSameBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	off := -1
	for i := 0; i < min(len(got), len(want)); i++ {
		if got[i] != want[i] {
			off = i
			break
		}
	}
	t.Errorf("payload mismatch: len got=%d want=%d, first diff at %d, sha256 got=%x want=%x",
		len(got), len(want), off, sha256.Sum256(got), sha256.Sum256(want))
}
