package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
)

// 100003 fixed bytes stand in for age ciphertext, on the golden v1 identity
// at (3, 5). Captured before Seal took Fields: the decrypted manifest body
// and the five shard digests. manifest.age itself is age-randomized and is
// not the fixture.
func TestSplitCaptureFrozen(t *testing.T) {
	ct := make([]byte, 100003)
	for i := range ct {
		ct[i] = byte(i)
	}
	idPath := materialiseGoldenIdentity(t, goldenV1Dir(t))
	inPath := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(inPath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: idPath,
		InPath:       inPath,
		OutDir:       outDir,
		K:            3,
		N:            5,
		deps:         deps{injectCiphertext: func() []byte { return ct }},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	id, err := key.Load(idPath)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Zero()
	blob, err := os.ReadFile(filepath.Join(outDir, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := id.DecryptBytes(blob)
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join("..", "..", "test", "golden", "seal-plaintext")
	wantBody, err := os.ReadFile(filepath.Join(dir, "split-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, wantBody) {
		t.Fatalf("manifest body differs at byte %d (len got=%d want=%d)", firstDiff(body, wantBody), len(body), len(wantBody))
	}

	var digests bytes.Buffer
	for i := 0; i < 5; i++ {
		shard, err := os.ReadFile(filepath.Join(outDir, fmt.Sprintf("shard-%02d", i)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(shard)
		fmt.Fprintf(&digests, "%x\n", sum[:])
	}
	wantDigests, err := os.ReadFile(filepath.Join(dir, "split-digests.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digests.Bytes(), wantDigests) {
		t.Fatalf("shard digests:\n%s\nwant:\n%s", digests.String(), wantDigests)
	}
}

func firstDiff(got, want []byte) int {
	n := min(len(got), len(want))
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			return i
		}
	}
	return n
}
