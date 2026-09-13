package bech32

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func vendoredSource(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("bech32.go")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLicenceHeaderByteIdentical(t *testing.T) {
	vendored := vendoredSource(t)

	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	upstreamPath := filepath.Join(strings.TrimSpace(string(out)), "filippo.io", "age@v1.3.1", "internal", "bech32", "bech32.go")
	upstream, err := os.ReadFile(upstreamPath)
	if err != nil {
		t.Fatalf("read upstream: %v", err)
	}

	const terminator = "// THE SOFTWARE.\n"
	n := bytes.Index(upstream, []byte(terminator))
	if n < 0 {
		t.Fatal("upstream MIT header terminator not found")
	}
	n += len(terminator)
	if len(vendored) < n {
		t.Fatalf("vendored file is shorter than the MIT header (%d bytes)", n)
	}
	if !bytes.Equal(vendored[:n], upstream[:n]) {
		t.Fatal("MIT header is not byte-identical to filippo.io/age@v1.3.1")
	}
}

func TestNoLengthLimit(t *testing.T) {
	// Encode is not vendored, so a valid >90-character identity cannot be constructed.
	src := vendoredSource(t)
	for _, needle := range []string{"> 90", "len(s) > 90"} {
		if bytes.Contains(src, []byte(needle)) {
			t.Fatalf("vendored source contains BIP-173 length-limit guard %q", needle)
		}
	}
}

func TestProvenanceComment(t *testing.T) {
	src := vendoredSource(t)
	if !bytes.Contains(src, []byte("C2SP age specification")) {
		t.Fatal("vendored file missing provenance comment naming the C2SP age specification")
	}
}

func TestDecodeKnownIdentity(t *testing.T) {
	// Generate at runtime so tracked files never contain the identity prefix+1 token (FR-24).
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hrp, data, err := Decode(id.String())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	const wantHRP = "AGE-SECRET-KEY-"
	if hrp != wantHRP {
		t.Errorf("hrp = %q, want %q", hrp, wantHRP)
	}
	if got := len(data); got != 32 {
		t.Errorf("len(data) = %d, want 32", got)
	}
}
