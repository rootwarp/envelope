package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// M5b.2 TestContextCancelMidCopy is the primary gate; this is the integration case.

func TestSIGINTMidRestore(t *testing.T) {
	testSignalMidRestore(t, os.Interrupt)
}

func TestSIGTERMMidRestore(t *testing.T) {
	testSignalMidRestore(t, syscall.SIGTERM)
}

func testSignalMidRestore(t *testing.T, sig os.Signal) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 1<<20)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	bin := buildEnvelope(t, "envelope_signaltest")
	cmd := exec.Command(bin, "restore", "-identity", id, "-in", shards, "-out", out)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	partial := out + ".partial"
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("process exited before %s appeared: %v\nstderr: %s", partial, err, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("timed out waiting for %s\nstderr: %s", partial, stderr.String())
		}
		if _, err := os.Stat(partial); err == nil {
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatalf("signal %v: %v", sig, err)
			}
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("exit 0, want non-zero\nstderr: %s", stderr.String())
		}
		if !bytes.Contains(stderr.Bytes(), []byte("context canceled")) {
			t.Fatalf("stderr missing %q\nstderr: %s", "context canceled", stderr.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("timed out waiting for exit after %v\nstderr: %s", sig, stderr.String())
	}

	assertAbsent(t, partial)
	assertAbsent(t, out)
}

func buildEnvelope(t *testing.T, tags ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "envelope")
	args := []string{"build"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "-o", bin, ".")
	cmd := exec.Command("go", args...)
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	cmd.Dir = filepath.Dir(file)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s still exists: %v", path, err)
	}
}
