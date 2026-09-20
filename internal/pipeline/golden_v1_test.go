package pipeline

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

// I-1: committed v1 shard set. Pipeline umask tests are process-global, so no t.Parallel.

var goldenV1Names = []string{
	"shard-00", "shard-01", "shard-02", "shard-03", "shard-04",
	"manifest.age",
	"identity.bech32data",
	"scalar.hex",
	"mackey.hex",
	"payload.sha256",
	"README.md",
}

func TestGoldenV1ShardSet(t *testing.T) {
	dir := goldenV1Dir(t)
	before := snapshotGolden(t, dir)
	t.Cleanup(func() { assertGoldenUnchanged(t, dir, before) })

	for _, name := range goldenV1Names {
		if bytes.Contains(before[name], []byte(key.HRP)) {
			t.Errorf("%s contains the identity HRP", name)
		}
	}

	idPath := materialiseGoldenIdentity(t, dir)
	inDir := copyGoldenShardSet(t, dir)
	wantHex, wantLen := goldenPayloadDigest(t, dir)

	outPath := filepath.Join(t.TempDir(), "out.bin")
	rep, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{idPath},
		InDirs:        []string{inDir},
		OutPath:       outPath,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(got)
	gotHex := hex.EncodeToString(sum[:])
	if gotHex != wantHex || int64(len(got)) != wantLen || rep.PlaintextLen != wantLen {
		t.Fatalf("restore sha256=%s len=%d report=%d, want sha256=%s len=%d",
			gotHex, len(got), rep.PlaintextLen, wantHex, wantLen)
	}

	vrep, err := Verify(context.Background(), VerifyOptions{
		IdentityPaths: []string{idPath},
		InDirs:        []string{inDir},
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if vrep.Result != VerifyHealthy {
		t.Fatalf("Result = %s, want %s", vrep.Result, VerifyHealthy)
	}
	report := formatVerifyReport(vrep)
	wantReport := fmt.Sprintf("manifest ok: k=3 n=5\n"+
		"shard-00 ok\nshard-01 ok\nshard-02 ok\nshard-03 ok\nshard-04 ok\n"+
		"usable 5 of 5, need 3\npayload ok: %d bytes\nresult: healthy\n", wantLen)
	if report != wantReport {
		t.Fatalf("verify report:\n%s\nwant:\n%s", report, wantReport)
	}
	lines := strings.Split(strings.TrimSuffix(report, "\n"), "\n")
	if len(lines) != 9 {
		t.Fatalf("verify report has %d lines, want n+4=9", len(lines))
	}

	id, err := key.Load(idPath)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Zero()
	mac, err := id.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mac)
	wantMAC := strings.TrimSpace(string(readGolden(t, dir, "mackey.hex")))
	raw, err := hex.DecodeString(strings.TrimSpace(string(readGolden(t, dir, "scalar.hex"))))
	if err != nil || len(raw) != 32 {
		t.Fatal("scalar.hex: want 32 bytes")
	}
	fromScalar, err := hkdf.Key(sha256.New, raw, []byte("envelope"), "envelope v1 manifest mac", 32)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fromScalar)
	if hex.EncodeToString(mac) != wantMAC || hex.EncodeToString(fromScalar) != wantMAC {
		t.Fatal("scalar HKDF / ManifestMACKey / mackey.hex disagree")
	}

	blob, err := os.ReadFile(filepath.Join(inDir, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Open(blob, id, id)
	if err != nil {
		t.Fatal(err)
	}
	set, err := key.LoadSet([]string{idPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	if _, err := set.DecryptBytes(blob); err != nil {
		t.Fatal(err)
	}
	if set.Interactions() != 0 {
		t.Fatalf("I-1: v1 golden decrypt Interactions = %d, want 0", set.Interactions())
	}
	if m.Version != 1 || m.K != 3 || m.N != 5 {
		t.Fatalf("manifest Version=%d k=%d n=%d, want 1 3 5", m.Version, m.K, m.N)
	}
	if m.MACSource != 0 || len(m.MACKeyID) != 0 {
		t.Fatal("decoded v1 body carried mac source fields")
	}
	if m.StripeLen != manifest.StripeLen(m.CiphertextLen, m.K) {
		t.Fatalf("StripeLen = %d, want %d", m.StripeLen, manifest.StripeLen(m.CiphertextLen, m.K))
	}
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("shard-%02d", i)
		sum := sha256.Sum256(before[name])
		if !bytes.Equal(m.Digests[i], sum[:]) {
			t.Fatalf("%s digest does not match committed shard bytes", name)
		}
		if int64(len(before[name])) != m.StripeLen {
			t.Fatalf("%s len = %d, want StripeLen %d", name, len(before[name]), m.StripeLen)
		}
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("mac_source")) || bytes.Contains(body, []byte("mac_key_id")) {
		t.Fatal("decoded v1 body JSON contains mac source keys")
	}

	resplit := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: idPath,
		InPath:       outPath,
		OutDir:       resplit,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	newBlob, err := os.ReadFile(filepath.Join(resplit, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	newM, err := manifest.Open(newBlob, id, id)
	if err != nil {
		t.Fatal(err)
	}
	if newM.Version != m.Version || newM.K != m.K || newM.N != m.N ||
		newM.CiphertextLen != m.CiphertextLen || newM.StripeLen != m.StripeLen {
		t.Fatal("re-split decoded v1 body disagrees with the committed fixture")
	}
}

func goldenV1Dir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "test", "golden", "v1-shardset")
	if _, err := os.Stat(filepath.Join(dir, "manifest.age")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func materialiseGoldenIdentity(t *testing.T, goldenDir string) string {
	t.Helper()
	data := bytes.TrimSpace(readGolden(t, goldenDir, "identity.bech32data"))
	if len(data) == 0 || data[0] == '1' {
		t.Fatal("identity.bech32data is empty or begins with 1")
	}
	// FR-24: assemble the identity line only in t.TempDir().
	line := key.HRP + "1" + string(data) + "\n"
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func copyGoldenShardSet(t *testing.T, goldenDir string) string {
	t.Helper()
	dst := t.TempDir()
	copyShards(t, goldenDir, dst, 5)
	copyFile(t, filepath.Join(goldenDir, "manifest.age"), filepath.Join(dst, "manifest.age"))
	return dst
}

func goldenPayloadDigest(t *testing.T, goldenDir string) (string, int64) {
	t.Helper()
	s := strings.TrimSpace(string(readGolden(t, goldenDir, "payload.sha256")))
	digest, length, ok := strings.Cut(s, "  ")
	if !ok || len(digest) != 64 {
		t.Fatal("payload.sha256: want '<64 hex>  <length>'")
	}
	var n int64
	if _, err := fmt.Sscanf(length, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return digest, n
}

func snapshotGolden(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(goldenV1Names))
	for _, name := range goldenV1Names {
		out[name] = readGolden(t, dir, name)
	}
	return out
}

func assertGoldenUnchanged(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := snapshotGolden(t, dir)
	for _, name := range goldenV1Names {
		if !bytes.Equal(before[name], after[name]) {
			t.Errorf("%s: tracked fixture bytes changed", name)
		}
	}
}

func readGolden(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Mirrors cmd/envelope writeVerifyReport so this test pins the n+4 stdout shape
// without importing cmd (D3).
func formatVerifyReport(rep *VerifyReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "manifest ok: k=%d n=%d\n", rep.K, rep.N)
	for _, s := range rep.Shards {
		fmt.Fprintf(&b, "%s %s\n", s.Name, s.State)
	}
	fmt.Fprintf(&b, "usable %d of %d, need %d\n", rep.Usable, rep.N, rep.K)
	switch {
	case !rep.PayloadChecked:
		fmt.Fprintln(&b, "payload skipped")
	case !rep.PayloadOK:
		fmt.Fprintln(&b, "payload failed")
	default:
		fmt.Fprintf(&b, "payload ok: %d bytes\n", rep.PlaintextLen)
	}
	fmt.Fprintf(&b, "result: %s\n", rep.Result)
	return b.String()
}
