package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/rootwarp/envelope/internal/key"
)

var recipientLine = regexp.MustCompile(`^age1[02-9ac-hj-np-z]{58}\n$`)

// FR-P2-12
func TestRecipient(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	mustRun(t, "keygen", "-out", id)

	var stdout, stderr bytes.Buffer
	code := run([]string{"recipient", "-identity", id}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitOK, stderr.Len())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr has %d bytes, want 0", stderr.Len())
	}
	got := stdout.String()
	if !recipientLine.MatchString(got) {
		t.Fatalf("stdout does not match recipient pattern (len=%d)", stdout.Len())
	}

	loaded, err := key.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Zero()
	s, ok := loaded.Recipient().(fmt.Stringer)
	if !ok {
		t.Fatal("loaded recipient is not a fmt.Stringer")
	}
	want := s.String() + "\n"
	if got != want {
		t.Fatalf("stdout does not equal independently computed recipient (got len=%d want len=%d)", len(got), len(want))
	}
}

// FR-P2-12, NFR-4
func TestRecipientNeverLeaks(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.txt")
	mustRun(t, "keygen", "-out", good)

	zero := filepath.Join(dir, "zero.txt")
	if err := os.WriteFile(zero, []byte("# comment only\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	mustRun(t, "keygen", "-out", a)
	mustRun(t, "keygen", "-out", b)
	ab, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	two := filepath.Join(dir, "two.txt")
	if err := os.WriteFile(two, append(append([]byte{}, ab...), bb...), 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid := filepath.Join(dir, "hybrid.txt")
	if err := os.WriteFile(hybrid, []byte(h.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	goodBytes, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(dir, "malformed.txt")
	if err := os.WriteFile(malformed, goodBytes[:len(goodBytes)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(dir, "missing.txt")

	tests := []struct {
		name    string
		path    string
		code    int
		errText string
	}{
		{name: "success", path: good, code: exitOK},
		{name: "missing file", path: missing, code: exitFailure, errText: missing},
		{name: "zero identities", path: zero, code: exitFailure, errText: key.ErrNotSingleIdentity.Error()},
		{name: "two identities", path: two, code: exitFailure, errText: key.ErrNotSingleIdentity.Error()},
		{name: "non-X25519", path: hybrid, code: exitFailure, errText: key.ErrNotX25519.Error()},
		{name: "malformed", path: malformed, code: exitFailure, errText: key.ErrInvalidIdentity.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var idBytes []byte
			if tt.path != missing {
				var err error
				idBytes, err = os.ReadFile(tt.path)
				if err != nil {
					t.Fatal(err)
				}
			}

			var stdout, stderr bytes.Buffer
			code := run([]string{"recipient", "-identity", tt.path}, &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit = %d, want %d (stderr len=%d)", code, tt.code, stderr.Len())
			}
			assertRecipientNoLeak(t, tt.name, stdout.String(), stderr.String(), idBytes)
			if tt.code == exitOK {
				if stderr.Len() != 0 {
					t.Fatalf("stderr has %d bytes, want 0", stderr.Len())
				}
				return
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
			}
			if !strings.Contains(stderr.String(), tt.errText) {
				t.Fatalf("stderr missing %q (len=%d)", tt.errText, stderr.Len())
			}
		})
	}
}

// FR-P2-12
func TestRecipientLeavesIdentity(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	mustRun(t, "keygen", "-out", id)

	before, err := os.ReadFile(id)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(before)
	st, err := os.Stat(id)
	if err != nil {
		t.Fatal(err)
	}
	mode := st.Mode()

	var stdout, stderr bytes.Buffer
	code := run([]string{"recipient", "-identity", id}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitOK, stderr.Len())
	}

	after, err := os.ReadFile(id)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != sum {
		t.Fatal("identity file SHA-256 changed")
	}
	st, err = os.Stat(id)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode() != mode {
		t.Fatalf("identity file mode changed: got %v want %v", st.Mode(), mode)
	}
}

func TestRecipientHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"recipient", "-h"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitOK, stderr.Len())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr has %d bytes, want 0", stderr.Len())
	}
	found := false
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.TrimSpace(line) == usageRecipient {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("recipient -h missing contract line")
	}
}

func assertRecipientNoLeak(t *testing.T, fixture, stdout, stderr string, idBytes []byte) {
	t.Helper()
	secret := "AGE-SECRET-KEY-"
	if strings.Contains(strings.ToUpper(stdout), secret) || strings.Contains(strings.ToUpper(stderr), secret) {
		t.Errorf("%s: stream contains identity prefix", fixture)
	}
	for _, line := range strings.Split(string(idBytes), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(stdout, line) || strings.Contains(stderr, line) {
			t.Errorf("%s: stream contains identity-file line", fixture)
		}
	}
}
