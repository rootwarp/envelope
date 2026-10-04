package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/pipeline"
)

// closedPipeWriter refuses every write.
type closedPipeWriter struct{}

func (closedPipeWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteVersionReportsStdoutFailure(t *testing.T) {
	err := runErr(context.Background(), []string{"-version"}, closedPipeWriter{}, io.Discard)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("stdout failure ignored: err=%v", err)
	}
	if strings.Contains(err.Error(), "envelope ") {
		t.Fatalf("write error carries version text: %v", err)
	}
}

func TestVerifyReportsStdoutFailure(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	err := runErr(context.Background(), []string{"verify", "-identity", id, "-in", shards}, closedPipeWriter{}, io.Discard)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("verify stdout failure ignored: err=%v", err)
	}
	if strings.Contains(err.Error(), "manifest ok") || strings.Contains(err.Error(), "result:") {
		t.Fatalf("write error carries report content: %v", err)
	}
}

func TestVerifyReportsOperationAndOutputFailure(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	if err := os.Remove(filepath.Join(shards, "shard-01")); err != nil {
		t.Fatal(err)
	}
	xorFileByte(t, filepath.Join(shards, "shard-02"), 0)

	var stderr bytes.Buffer
	err := runErr(context.Background(), []string{"verify", "-identity", id, "-in", shards}, closedPipeWriter{}, &stderr)
	if !errors.Is(err, pipeline.ErrDamaged) {
		t.Fatalf("errors.Is(., ErrDamaged) = false, err=%v", err)
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("errors.Is(., ErrClosedPipe) = false, err=%v", err)
	}
	if strings.Contains(err.Error(), "manifest ok") || strings.Contains(err.Error(), "result:") {
		t.Fatalf("joined error carries report content: %v", err)
	}
	if !strings.Contains(err.Error(), io.ErrClosedPipe.Error()) {
		t.Fatalf("joined error does not name the write failure: %v", err)
	}

	code := exitCode(err, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
	}
	got := stderr.String()
	diag := strings.Index(got, "failed digest at index 2")
	writeFail := strings.Index(got, io.ErrClosedPipe.Error())
	if diag < 0 || writeFail < 0 || diag >= writeFail {
		t.Fatalf("damage diagnosis not before write failure\nstderr: %s", got)
	}
}

func TestStdoutFailureExitsFailure(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		var stderr bytes.Buffer
		code := run([]string{"-version"}, closedPipeWriter{}, &stderr)
		if code != exitFailure {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
		}
		if !strings.Contains(stderr.String(), io.ErrClosedPipe.Error()) {
			t.Fatalf("stderr missing write failure: %s", stderr.String())
		}
	})
	t.Run("verify", func(t *testing.T) {
		id, shards, _ := mustSplitFixture(t)
		var stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-in", shards}, closedPipeWriter{}, &stderr)
		if code != exitFailure {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
		}
		if !strings.Contains(stderr.String(), io.ErrClosedPipe.Error()) {
			t.Fatalf("stderr missing write failure: %s", stderr.String())
		}
	})
}

func TestVerifyKeepsOperationErrorIdentity(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	if err := os.Remove(filepath.Join(shards, "shard-01")); err != nil {
		t.Fatal(err)
	}
	xorFileByte(t, filepath.Join(shards, "shard-02"), 0)

	var stdout, stderr bytes.Buffer
	err := runErr(context.Background(), []string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
	if err != pipeline.ErrDamaged {
		t.Fatalf("err = %T %v, want identity pipeline.ErrDamaged", err, err)
	}
	if stdout.Len() == 0 {
		t.Fatal("stdout empty, want verify report")
	}
}

func TestVersionUnderFileSizeLimitExitsFailure(t *testing.T) {
	skipWindows(t)
	bin := buildEnvelope(t)
	outPath := filepath.Join(t.TempDir(), "version.txt")
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	cmd := exec.Command("/bin/sh", "-c", "ulimit -f 0; exec \"$1\" -version", "sh", bin)
	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmdErr := cmd.Run()
	gotCode := 0
	if cmdErr != nil {
		var ee *exec.ExitError
		if !errors.As(cmdErr, &ee) {
			t.Fatalf("child: %v\nstderr: %s", cmdErr, stderr.String())
		}
		gotCode = ee.ExitCode()
	}
	if gotCode != exitFailure {
		t.Fatalf("exit = %d, want %d\nstderr: %s", gotCode, exitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write /dev/stdout: file too large") {
		t.Fatalf("stderr = %q, want write /dev/stdout: file too large", stderr.String())
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("stdout file size = %d, want 0", info.Size())
	}
}
