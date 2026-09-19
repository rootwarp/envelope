//go:build unix

package pipeline

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRestoreFIFOShardIsUnusable(t *testing.T) {
	restore, _, want := splitSized(t, 1<<20)
	path := filepath.Join(restore.InDirs[0], shardFileName(4))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Restore(context.Background(), restore, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restore.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	if rep == nil || len(rep.FailedIndex) != 1 || rep.FailedIndex[0] != 4 {
		t.Fatalf("FailedIndex = %v, want [4]", rep.FailedIndex)
	}
}
