package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// 36 MiB lands the ciphertext just past a bytes.Buffer doubling step, which
// is where split's resident set is closest to its ceiling for every (k, n).
// (3, 5) is the default geometry. The child is the plain binary from
// buildEnvelope: measuring this process would follow the race detector's
// heap, which is not the ceiling.
func TestMemoryCeilingHoldsForSplitAndRestore(t *testing.T) {
	const (
		fileBytes = 36 << 20
		k         = 3
		n         = 5
		overhead  = 16 << 20
	)
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(in, make([]byte, fileBytes), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := buildEnvelope(t)
	runChild(t, bin, "keygen", "-out", id)

	splitRSS, splitText := runChild(t, bin, "split", "-identity", id, "-in", in, "-out", shards, "-k", "3", "-n", "5")
	c := ciphertextLen(t, splitText)
	splitFactor := max(4.5, float64(n)/float64(k)+1.5)
	assertCeiling(t, "split", splitRSS, c, splitFactor*float64(c)+overhead)

	restoreRSS, _ := runChild(t, bin, "restore", "-identity", id, "-in", shards, "-out", out)
	restoreFactor := float64(n)/float64(k) + 4.5
	assertCeiling(t, "restore", restoreRSS, c, restoreFactor*float64(c)+overhead)

	verifyRSS, _ := runChild(t, bin, "verify", "-identity", id, "-in", shards)
	assertCeiling(t, "verify", verifyRSS, c, restoreFactor*float64(c)+overhead)
}

func assertCeiling(t *testing.T, name string, rss, c int64, bound float64) {
	t.Helper()
	t.Logf("%s maxrss %d bytes, %.3fx C, bound %.0f", name, rss, float64(rss)/float64(c), bound)
	if float64(rss) > bound {
		t.Fatalf("%s maxrss %d bytes (%.3fx C) exceeds bound %.0f", name, rss, float64(rss)/float64(c), bound)
	}
}

func runChild(t *testing.T, bin string, args ...string) (int64, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", args[0], err, stderr.String())
	}
	if cmd.ProcessState == nil {
		t.Fatal("no process state")
	}
	return maxRSSBytes(t, cmd.ProcessState), stderr.String()
}

func ciphertextLen(t *testing.T, stderr string) int64 {
	t.Helper()
	var n int64
	if _, err := fmt.Sscanf(stderr, "encrypted %d bytes\n", &n); err != nil {
		t.Fatalf("ciphertext length: %v\n%s", err, stderr)
	}
	if n <= 0 {
		t.Fatalf("ciphertext length = %d", n)
	}
	return n
}

func maxRSSBytes(t *testing.T, st *os.ProcessState) int64 {
	t.Helper()
	ru, ok := st.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		t.Fatalf("SysUsage is %T", st.SysUsage())
	}
	switch runtime.GOOS {
	case "darwin":
		// getrusage ru_maxrss is bytes.
		return ru.Maxrss
	case "linux":
		// getrusage ru_maxrss is kilobytes.
		return ru.Maxrss * 1024
	default:
		t.Fatalf("ru_maxrss unit is not known for %s", runtime.GOOS)
		return 0
	}
}
