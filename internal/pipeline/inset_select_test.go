package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scatter copies shard i into dirs[i % len(dirs)] and a manifest into each.
// Shared by restore and verify tests (NFR-MD-4).
func scatter(t *testing.T, srcDir string, d int) []string {
	t.Helper()
	root := t.TempDir()
	dirs := make([]string, d)
	for i := range dirs {
		dirs[i] = filepath.Join(root, string(rune('a'+i)))
		if err := os.MkdirAll(dirs[i], 0o700); err != nil {
			t.Fatal(err)
		}
		copyFile(t, filepath.Join(srcDir, "manifest.age"), filepath.Join(dirs[i], "manifest.age"))
	}
	ents, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "shard-") {
			continue
		}
		copyFile(t, filepath.Join(srcDir, e.Name()), filepath.Join(dirs[n%d], e.Name()))
		n++
	}
	return dirs
}

func cloneSplitDir(t *testing.T, src string, n int) string {
	t.Helper()
	dst := t.TempDir()
	copyFile(t, filepath.Join(src, "manifest.age"), filepath.Join(dst, "manifest.age"))
	copyShards(t, src, dst, n)
	return dst
}

func emptyDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

func assertIndexList(t *testing.T, name string, got, want []int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
}

func assertVerifySlotClasses(t *testing.T, rrep *RestoreReport, vrep *VerifyReport) {
	t.Helper()
	if rrep == nil || vrep == nil {
		t.Fatalf("reports nil: restore=%v verify=%v", rrep == nil, vrep == nil)
	}
	if vrep.Usable != rrep.Usable {
		t.Fatalf("Usable restore=%d verify=%d", rrep.Usable, vrep.Usable)
	}
	if vrep.N != rrep.N {
		t.Fatalf("N restore=%d verify=%d", rrep.N, vrep.N)
	}
	failed := make([]bool, rrep.N)
	missing := make([]bool, rrep.N)
	for _, i := range rrep.FailedIndex {
		if i < 0 || i >= rrep.N {
			t.Fatalf("FailedIndex contains %d, n=%d", i, rrep.N)
		}
		if failed[i] {
			t.Fatalf("FailedIndex repeats %d: %v", i, rrep.FailedIndex)
		}
		failed[i] = true
	}
	for _, i := range rrep.MissingIndex {
		if i < 0 || i >= rrep.N {
			t.Fatalf("MissingIndex contains %d, n=%d", i, rrep.N)
		}
		missing[i] = true
	}
	if len(vrep.Shards) != rrep.N {
		t.Fatalf("len(Shards) = %d, want %d", len(vrep.Shards), rrep.N)
	}
	for i, s := range vrep.Shards {
		want := ShardOK
		switch {
		case failed[i]:
			want = ShardCorrupt
		case missing[i]:
			want = ShardMissing
		}
		if s.State != want {
			t.Errorf("slot %d: Verify %s, want %s (FailedIndex=%v MissingIndex=%v)",
				i, s.State, want, rrep.FailedIndex, rrep.MissingIndex)
		}
	}
}

func verifyDirs(t *testing.T, restore RestoreOptions, status io.Writer) (*VerifyReport, error) {
	t.Helper()
	return Verify(context.Background(), VerifyOptions{
		IdentityPaths: restore.IdentityPaths,
		InDirs:        restore.InDirs,
	}, status)
}

// FR-MD-04: per-slot aggregation across directories.
func TestSlotStateAggregation(t *testing.T) {
	restore, split := splitFixture(t)
	src := split.OutDir

	run := func(t *testing.T, dirA, dirB string) (*RestoreReport, *VerifyReport) {
		t.Helper()
		opts := restore
		opts.InDirs = []string{dirA, dirB}
		opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
		rrep, err := Restore(context.Background(), opts, io.Discard)
		if err != nil {
			t.Fatalf("Restore err = %v, want nil", err)
		}
		vrep, verr := verifyDirs(t, opts, io.Discard)
		if rrep != nil && len(rrep.FailedIndex) > 0 {
			if !errors.Is(verr, ErrDamaged) {
				t.Fatalf("Verify err = %v, want ErrDamaged", verr)
			}
		} else if verr != nil {
			t.Fatalf("Verify err = %v, want nil", verr)
		}
		assertVerifySlotClasses(t, rrep, vrep)
		return rrep, vrep
	}

	t.Run("usable", func(t *testing.T) {
		dirA := cloneSplitDir(t, src, split.N)
		dirB := cloneSplitDir(t, src, split.N)
		flipFileByte(t, filepath.Join(dirA, shardFileName(1)), 0)
		rrep, _ := run(t, dirA, dirB)
		assertIndexList(t, "FailedIndex", rrep.FailedIndex, nil)
		assertIndexList(t, "MissingIndex", rrep.MissingIndex, nil)
	})

	t.Run("corrupt", func(t *testing.T) {
		dirA := cloneSplitDir(t, src, split.N)
		dirB := cloneSplitDir(t, src, split.N)
		flipFileByte(t, filepath.Join(dirA, shardFileName(3)), 0)
		flipFileByte(t, filepath.Join(dirB, shardFileName(3)), 0)
		rrep, _ := run(t, dirA, dirB)
		assertIndexList(t, "FailedIndex", rrep.FailedIndex, []int{3})
		assertIndexList(t, "MissingIndex", rrep.MissingIndex, nil)
	})

	t.Run("missing", func(t *testing.T) {
		dirA := cloneSplitDir(t, src, split.N)
		dirB := cloneSplitDir(t, src, split.N)
		removeShardFiles(t, dirA, 2)
		removeShardFiles(t, dirB, 2)
		rrep, vrep := run(t, dirA, dirB)
		assertIndexList(t, "FailedIndex", rrep.FailedIndex, nil)
		assertIndexList(t, "MissingIndex", rrep.MissingIndex, []int{2})
		if vrep.Result != VerifyDegraded {
			t.Fatalf("Result = %s, want degraded", vrep.Result)
		}
	})

	t.Run("mixed", func(t *testing.T) {
		dirA := cloneSplitDir(t, src, split.N)
		dirB := cloneSplitDir(t, src, split.N)
		removeShardFiles(t, dirA, 2)
		removeShardFiles(t, dirB, 2)
		flipFileByte(t, filepath.Join(dirA, shardFileName(3)), 0)
		flipFileByte(t, filepath.Join(dirB, shardFileName(3)), 0)
		rrep, _ := run(t, dirA, dirB)
		assertIndexList(t, "MissingIndex", rrep.MissingIndex, []int{2})
		assertIndexList(t, "FailedIndex", rrep.FailedIndex, []int{3})
	})

	t.Run("present-outranks-absent", func(t *testing.T) {
		dirA := cloneSplitDir(t, src, split.N)
		dirB := cloneSplitDir(t, src, split.N)
		removeShardFiles(t, dirA, 2)
		flipFileByte(t, filepath.Join(dirB, shardFileName(2)), 0)
		rrep, _ := run(t, dirA, dirB)
		assertIndexList(t, "FailedIndex", rrep.FailedIndex, []int{2})
		assertIndexList(t, "MissingIndex", rrep.MissingIndex, nil)
	})
}

// FR-MD-04: a slot rotten in every directory is listed once.
func TestSlotRottenEverywhereListedOnce(t *testing.T) {
	restore, split := splitFixture(t)
	dirA := cloneSplitDir(t, split.OutDir, split.N)
	dirB := cloneSplitDir(t, split.OutDir, split.N)
	flipFileByte(t, filepath.Join(dirA, shardFileName(2)), 0)
	flipFileByte(t, filepath.Join(dirB, shardFileName(2)), 0)
	aPath := filepath.Join(dirA, shardFileName(2))
	bPath := filepath.Join(dirB, shardFileName(2))

	opts := restore
	opts.InDirs = []string{dirA, dirB}
	opts.OutPath = filepath.Join(t.TempDir(), "out.bin")

	var rstatus bytes.Buffer
	rrep, rerr := Restore(context.Background(), opts, &rstatus)
	if rerr != nil {
		t.Fatalf("Restore err = %v, want nil (status len=%d)", rerr, rstatus.Len())
	}
	assertIndexList(t, "FailedIndex", rrep.FailedIndex, []int{2})
	for _, p := range []string{aPath, bPath} {
		wantLine := fmt.Sprintf("failed digest at index %d: %s", 2, p)
		if !strings.Contains(rstatus.String(), wantLine) {
			t.Fatalf("restore status missing %q; len=%d", wantLine, rstatus.Len())
		}
	}
	if got := strings.Count(rstatus.String(), "failed digest at index 2"); got != 2 {
		t.Fatalf("restore digest lines for slot 2 = %d, want 2", got)
	}

	var vstatus bytes.Buffer
	vrep, verr := verifyDirs(t, opts, &vstatus)
	if !errors.Is(verr, ErrDamaged) {
		t.Fatalf("Verify err = %v, want ErrDamaged (status len=%d)", verr, vstatus.Len())
	}
	assertVerifySlotClasses(t, rrep, vrep)
	if vrep.Shards[2].State != ShardCorrupt {
		t.Fatalf("Shards[2].State = %s, want corrupt", vrep.Shards[2].State)
	}
	for _, p := range []string{aPath, bPath} {
		wantLine := fmt.Sprintf("failed digest at index %d: %s", 2, p)
		if !strings.Contains(vstatus.String(), wantLine) {
			t.Fatalf("verify status missing %q; len=%d", wantLine, vstatus.Len())
		}
	}
	if got := strings.Count(vstatus.String(), "failed digest at index 2"); got != 2 {
		t.Fatalf("verify digest lines for slot 2 = %d, want 2", got)
	}
}

// FR-MD-04: identical output whatever the distribution.
func TestScatteredRestoreMatchesGathered(t *testing.T) {
	restore, split := splitFixture(t)
	gathered := restore
	if _, err := Restore(context.Background(), gathered, io.Discard); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(gathered.OutPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range []int{2, 3, 5} {
		dirs := scatter(t, split.OutDir, d)
		opts := restore
		opts.InDirs = dirs
		opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
		rrep, err := Restore(context.Background(), opts, io.Discard)
		if err != nil {
			t.Fatalf("d=%d: Restore err = %v", d, err)
		}
		got, err := os.ReadFile(opts.OutPath)
		if err != nil {
			t.Fatal(err)
		}
		assertSameBytes(t, got, want)
		vrep, verr := verifyDirs(t, opts, io.Discard)
		if verr != nil {
			t.Fatalf("d=%d: Verify err = %v", d, verr)
		}
		assertVerifySlotClasses(t, rrep, vrep)
		if vrep.Result != VerifyHealthy {
			t.Fatalf("d=%d: Result = %s, want healthy", d, vrep.Result)
		}
		if rrep.Usable != split.N {
			t.Fatalf("d=%d: Usable = %d, want %d", d, rrep.Usable, split.N)
		}
	}
}

// NFR-MD-2 / FR-MD-04 I6: a rejected candidate is never assigned, so the slot
// can be rescued and FailedIndex stays empty. This is a proxy for I6 (peak
// memory independent of d), not a pin — an implementation that accumulated
// every candidate in a slice would still pass.
func TestRejectedCandidateNotRetained(t *testing.T) {
	restore, split := splitFixture(t)
	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}
	dirs := scatter(t, split.OutDir, 2)
	rot := t.TempDir()
	copyFile(t, filepath.Join(split.OutDir, "manifest.age"), filepath.Join(rot, "manifest.age"))
	for i := 0; i < split.N; i++ {
		src := filepath.Join(split.OutDir, shardFileName(i))
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		b[0] ^= 0xff
		if err := os.WriteFile(filepath.Join(rot, shardFileName(i)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var status bytes.Buffer
	opts := restore
	opts.InDirs = append([]string{rot}, dirs...)
	opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
	rrep, err := Restore(context.Background(), opts, &status)
	if err != nil {
		t.Fatalf("Restore = %v (status len=%d)", err, status.Len())
	}
	assertIndexList(t, "FailedIndex", rrep.FailedIndex, nil)
	if got := strings.Count(status.String(), "failed digest at index"); got != split.N {
		t.Errorf("rejected-copy lines = %d, want %d", got, split.N)
	}
	got, err := os.ReadFile(opts.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)

	vrep, verr := verifyDirs(t, opts, io.Discard)
	if verr != nil {
		t.Fatalf("Verify err = %v, want nil", verr)
	}
	assertVerifySlotClasses(t, rrep, vrep)
}

// NFR-MD-3: Restore and Verify leave every -in directory unchanged.
func TestInDirsUnchanged(t *testing.T) {
	restore, split := splitFixture(t)
	dirs := scatter(t, split.OutDir, 3)
	root := filepath.Dir(dirs[0])
	before := snapshotTree(t, root)

	opts := restore
	opts.InDirs = dirs
	opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
	if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	assertTreeUnchanged(t, before, snapshotTree(t, root))

	if _, err := verifyDirs(t, opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	assertTreeUnchanged(t, before, snapshotTree(t, root))
}

// FR-MD-04 X-MD-3: five directories, two emptied, restore matches the original.
func TestFiveDirsTwoEmptied(t *testing.T) {
	restore, split := splitFixture(t)
	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}
	dirs := scatter(t, split.OutDir, 5)
	emptyDir(t, dirs[1])
	emptyDir(t, dirs[4])

	opts := restore
	opts.InDirs = dirs
	opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
	rrep, err := Restore(context.Background(), opts, io.Discard)
	if err != nil {
		t.Fatalf("Restore err = %v, want nil", err)
	}
	got, err := os.ReadFile(opts.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	if rrep.Usable != 3 {
		t.Fatalf("Usable = %d, want 3", rrep.Usable)
	}
	if len(rrep.MissingIndex) != 2 {
		t.Fatalf("MissingIndex = %v, want two entries", rrep.MissingIndex)
	}
	assertIndexList(t, "FailedIndex", rrep.FailedIndex, nil)

	vrep, verr := verifyDirs(t, opts, io.Discard)
	if verr != nil {
		t.Fatalf("Verify err = %v, want nil", verr)
	}
	assertVerifySlotClasses(t, rrep, vrep)
	if vrep.Result != VerifyDegraded {
		t.Fatalf("Result = %s, want degraded", vrep.Result)
	}
}
