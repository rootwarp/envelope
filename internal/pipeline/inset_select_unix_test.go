//go:build unix

package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func replaceWithFIFO(t *testing.T, dir string, i int) {
	t.Helper()
	path := filepath.Join(dir, shardFileName(i))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertRescued(t *testing.T, restore RestoreOptions, dirA, dirB, wantLine string, want []byte) {
	t.Helper()
	var status bytes.Buffer
	opts := restore
	opts.InDirs = []string{dirA, dirB}
	opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
	rrep, rerr := Restore(context.Background(), opts, &status)
	if rerr != nil {
		t.Fatalf("Restore err = %v, want nil (status len=%d)", rerr, status.Len())
	}
	assertIndexList(t, "FailedIndex", rrep.FailedIndex, nil)
	if !strings.Contains(status.String(), wantLine) {
		t.Fatalf("status missing %q; len=%d", wantLine, status.Len())
	}
	got, err := os.ReadFile(opts.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)

	var vstatus bytes.Buffer
	vrep, verr := verifyDirs(t, opts, &vstatus)
	if verr != nil {
		t.Fatalf("Verify err = %v, want nil (status len=%d)", verr, vstatus.Len())
	}
	assertVerifySlotClasses(t, rrep, vrep)
	if !strings.Contains(vstatus.String(), wantLine) {
		t.Fatalf("verify status missing %q; len=%d", wantLine, vstatus.Len())
	}
}

// FR-MD-04: a later directory can fill a slot the first directory rejected.
func TestSlotRescuedByLaterDirectory(t *testing.T) {
	restore, split := splitFixture(t)
	unsc := restore
	unsc.OutPath = filepath.Join(t.TempDir(), "unsc.bin")
	if _, err := Restore(context.Background(), unsc, io.Discard); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(unsc.OutPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fifo", func(t *testing.T) {
		dirA := cloneSplitDir(t, split.OutDir, split.N)
		dirB := cloneSplitDir(t, split.OutDir, split.N)
		replaceWithFIFO(t, dirA, 2)
		wantLine := fmt.Sprintf("unusable shard at index %d: %s", 2, filepath.Join(dirA, shardFileName(2)))
		assertRescued(t, restore, dirA, dirB, wantLine, want)
	})

	t.Run("digest", func(t *testing.T) {
		dirA := cloneSplitDir(t, split.OutDir, split.N)
		dirB := cloneSplitDir(t, split.OutDir, split.N)
		flipFileByte(t, filepath.Join(dirA, shardFileName(2)), 0)
		wantLine := fmt.Sprintf("failed digest at index %d: %s", 2, filepath.Join(dirA, shardFileName(2)))
		assertRescued(t, restore, dirA, dirB, wantLine, want)
	})
}

// FR-MD-06 I3 I4: duplicates collapse, and the deduplicated list is what
// decides whether diagnostics carry a path. FIFO at 3 and a flipped bit at 2
// pin reason-group order (unusable then digest), not index order.
func TestDuplicateDirsAreSingleDirectoryBehaviour(t *testing.T) {
	restore, split := splitFixture(t)
	src := split.OutDir
	flipFileByte(t, filepath.Join(src, shardFileName(2)), 0)
	replaceWithFIFO(t, src, 3)

	var one, many bytes.Buffer
	single := restore
	single.OutPath = filepath.Join(t.TempDir(), "a.bin")
	srep, err := Restore(context.Background(), single, &one)
	if err != nil {
		t.Fatal(err)
	}
	assertIndexList(t, "FailedIndex", srep.FailedIndex, []int{3, 2})

	dup := restore
	dup.InDirs = []string{src, src + "/", filepath.Join(src, ".")}
	dup.OutPath = filepath.Join(t.TempDir(), "b.bin")
	drep, err := Restore(context.Background(), dup, &many)
	if err != nil {
		t.Fatal(err)
	}
	assertIndexList(t, "FailedIndex", drep.FailedIndex, []int{3, 2})

	a := strings.ReplaceAll(one.String(), single.OutPath, "@OUT")
	c := strings.ReplaceAll(many.String(), dup.OutPath, "@OUT")
	if a != c {
		t.Errorf("duplicate -in stderr = %q, want %q", c, a)
	}
	ui := strings.Index(a, "unusable shard at index 3")
	di := strings.Index(a, "failed digest at index 2")
	if ui < 0 || di < 0 || ui > di {
		t.Errorf("stderr order unusable@3=%d digest@2=%d (want unusable first)", ui, di)
	}
}
