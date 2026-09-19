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
	"time"

	"github.com/rootwarp/envelope/internal/key"
)

// FR-P2-13
func TestVerifyResultClasses(t *testing.T) {
	for _, tc := range []struct {
		name           string
		fixture        func(*testing.T) (RestoreOptions, []byte)
		wantResult     VerifyResult
		wantUsable     int
		wantStates     []ShardState
		wantPayloadOK  bool
		wantChecked    bool
		wantPlaintext  bool
		wantErrDamaged bool
		wantTooFew     bool
		statusSub      string
	}{
		{
			name: "healthy",
			fixture: func(t *testing.T) (RestoreOptions, []byte) {
				r, split := splitFixture(t)
				b, err := os.ReadFile(split.InPath)
				if err != nil {
					t.Fatal(err)
				}
				return r, b
			},
			wantResult:    VerifyHealthy,
			wantUsable:    5,
			wantStates:    []ShardState{ShardOK, ShardOK, ShardOK, ShardOK, ShardOK},
			wantPayloadOK: true,
			wantChecked:   true,
			wantPlaintext: true,
		},
		{
			name: "two deleted",
			fixture: func(t *testing.T) (RestoreOptions, []byte) {
				r, _, w := splitSized(t, 4096)
				removeShardFiles(t, r.InDir, 3, 4)
				return r, w
			},
			wantResult:    VerifyDegraded,
			wantUsable:    3,
			wantStates:    []ShardState{ShardOK, ShardOK, ShardOK, ShardMissing, ShardMissing},
			wantPayloadOK: true,
			wantChecked:   true,
			wantPlaintext: true,
		},
		{
			name: "three deleted",
			fixture: func(t *testing.T) (RestoreOptions, []byte) {
				r, _, w := splitSized(t, 4096)
				removeShardFiles(t, r.InDir, 0, 1, 2)
				return r, w
			},
			wantResult:    VerifyUnrestorable,
			wantUsable:    2,
			wantStates:    []ShardState{ShardMissing, ShardMissing, ShardMissing, ShardOK, ShardOK},
			wantPayloadOK: false,
			wantChecked:   false,
			wantTooFew:    true,
		},
		{
			name: "one corrupted",
			fixture: func(t *testing.T) (RestoreOptions, []byte) {
				r, _, w := splitSized(t, 4096)
				flipFileByte(t, filepath.Join(r.InDir, shardFileName(2)), 0)
				return r, w
			},
			wantResult:     VerifyDamaged,
			wantUsable:     4,
			wantStates:     []ShardState{ShardOK, ShardOK, ShardCorrupt, ShardOK, ShardOK},
			wantPayloadOK:  true,
			wantChecked:    true,
			wantPlaintext:  true,
			wantErrDamaged: true,
			statusSub:      "failed digest at index 2",
		},
		{
			name: "three corrupted",
			fixture: func(t *testing.T) (RestoreOptions, []byte) {
				r, _, w := splitSized(t, 4096)
				for _, i := range []int{0, 1, 2} {
					flipFileByte(t, filepath.Join(r.InDir, shardFileName(i)), 0)
				}
				return r, w
			},
			wantResult:    VerifyUnrestorable,
			wantUsable:    2,
			wantStates:    []ShardState{ShardCorrupt, ShardCorrupt, ShardCorrupt, ShardOK, ShardOK},
			wantPayloadOK: false,
			wantChecked:   false,
			wantTooFew:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore, input := tc.fixture(t)
			var status bytes.Buffer
			rep, err := Verify(context.Background(), VerifyOptions{
				IdentityPath: restore.IdentityPath,
				InDir:        restore.InDir,
			}, &status)
			if rep == nil {
				t.Fatal("report is nil")
			}
			if rep.K != 3 || rep.N != 5 {
				t.Fatalf("K=%d N=%d, want 3, 5", rep.K, rep.N)
			}
			if rep.Result != tc.wantResult {
				t.Fatalf("Result = %s, want %s", rep.Result, tc.wantResult)
			}
			if rep.Usable != tc.wantUsable {
				t.Fatalf("Usable = %d, want %d", rep.Usable, tc.wantUsable)
			}
			if rep.PayloadChecked != tc.wantChecked {
				t.Fatalf("PayloadChecked = %v, want %v", rep.PayloadChecked, tc.wantChecked)
			}
			if rep.PayloadOK != tc.wantPayloadOK {
				t.Fatalf("PayloadOK = %v, want %v", rep.PayloadOK, tc.wantPayloadOK)
			}
			if len(rep.Shards) != 5 {
				t.Fatalf("len(Shards) = %d, want 5", len(rep.Shards))
			}
			for i, want := range tc.wantStates {
				got := rep.Shards[i]
				if got.Name != shardFileName(i) {
					t.Errorf("Shards[%d].Name = %q, want %q", i, got.Name, shardFileName(i))
				}
				if got.State != want {
					t.Errorf("Shards[%d].State = %s, want %s", i, got.State, want)
				}
			}
			if tc.wantPlaintext && rep.PlaintextLen != int64(len(input)) {
				t.Fatalf("PlaintextLen = %d, want %d", rep.PlaintextLen, len(input))
			}
			switch {
			case tc.wantErrDamaged:
				if !errors.Is(err, ErrDamaged) {
					t.Fatalf("errors.Is(., ErrDamaged) = false, err=%v", err)
				}
			case tc.wantTooFew:
				assertTooFewShards(t, err, 3, 2)
			default:
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.statusSub != "" && !strings.Contains(status.String(), tc.statusSub) {
				t.Fatalf("status %q missing %q", status.String(), tc.statusSub)
			}
		})
	}
}

// FR-P2-13 "tampered after reconstruction"
func TestVerifyPayloadTamper(t *testing.T) {
	restore, _, _ := splitSized(t, 4096)
	testAtJoin = func(ct []byte, _ int64) {
		if !bytes.HasPrefix(ct, []byte("age-encryption.org/v1\n")) {
			t.Fatal("joined ciphertext is not an age v1 header")
		}
		off := bytes.Index(ct, []byte("\n--- "))
		if off < 0 {
			t.Fatal("age header MAC line not found")
		}
		nl := bytes.IndexByte(ct[off+1:], '\n')
		if nl < 0 {
			t.Fatal("age header MAC line is truncated")
		}
		i := off + 1 + nl + 1
		if i >= len(ct) {
			t.Fatal("no STREAM body after age header")
		}
		ct[i] ^= 0x01
	}
	t.Cleanup(func() { testAtJoin = nil })

	rep, err := Verify(context.Background(), VerifyOptions{
		IdentityPath: restore.IdentityPath,
		InDir:        restore.InDir,
	}, nil)
	if rep == nil {
		t.Fatal("report is nil")
	}
	if !rep.PayloadChecked || rep.PayloadOK {
		t.Fatalf("PayloadChecked=%v PayloadOK=%v, want true, false", rep.PayloadChecked, rep.PayloadOK)
	}
	if rep.Result != VerifyUnrestorable {
		t.Fatalf("Result = %s, want unrestorable", rep.Result)
	}
	if err == nil || !strings.HasPrefix(err.Error(), "payload:") {
		t.Fatalf("err = %v, want payload: prefix", err)
	}
}

// FR-P2-13 "nothing is written, anywhere"
func TestVerifyWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture func(*testing.T) RestoreOptions
		check   func(*testing.T, error)
	}{
		{
			name: "healthy",
			fixture: func(t *testing.T) RestoreOptions {
				r, _ := splitFixture(t)
				return r
			},
			check: func(t *testing.T, err error) {
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "damaged",
			fixture: func(t *testing.T) RestoreOptions {
				r, _, _ := splitSized(t, 4096)
				flipFileByte(t, filepath.Join(r.InDir, shardFileName(2)), 0)
				return r
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, ErrDamaged) {
					t.Fatalf("errors.Is(., ErrDamaged) = false, err=%v", err)
				}
			},
		},
		{
			name: "unrestorable",
			fixture: func(t *testing.T) RestoreOptions {
				r, _, _ := splitSized(t, 4096)
				removeShardFiles(t, r.InDir, 0, 1, 2)
				return r
			},
			check: func(t *testing.T, err error) {
				assertTooFewShards(t, err, 3, 2)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Dir(t.TempDir())
			restore := tc.fixture(t)
			before := snapshotTree(t, root)
			_, err := Verify(context.Background(), VerifyOptions{
				IdentityPath: restore.IdentityPath,
				InDir:        restore.InDir,
			}, io.Discard)
			tc.check(t, err)
			after := snapshotTree(t, root)
			assertTreeUnchanged(t, before, after)
		})
	}

	t.Run("read-only in", func(t *testing.T) {
		root := filepath.Dir(t.TempDir())
		restore, _ := splitFixture(t)
		in := restore.InDir
		t.Cleanup(func() {
			_ = os.Chmod(in, 0o700)
			entries, err := os.ReadDir(in)
			if err != nil {
				return
			}
			for _, e := range entries {
				_ = os.Chmod(filepath.Join(in, e.Name()), 0o644)
			}
		})
		entries, err := os.ReadDir(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.Chmod(filepath.Join(in, e.Name()), 0o444); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(in, 0o555); err != nil {
			t.Fatal(err)
		}

		before := snapshotTree(t, root)
		rep, err := Verify(context.Background(), VerifyOptions{
			IdentityPath: restore.IdentityPath,
			InDir:        restore.InDir,
		}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if rep == nil || rep.Result != VerifyHealthy {
			t.Fatalf("Result = %v, want healthy", rep)
		}
		after := snapshotTree(t, root)
		assertTreeUnchanged(t, before, after)
	})
}

func TestVerifyStaleManifest(t *testing.T) {
	idPath := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := key.Create(idPath); err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(t.TempDir(), "in.bin")
	writeRandomFile(t, inPath, 1024)

	dirA := t.TempDir()
	dirB := t.TempDir()
	opts := SplitOptions{
		IdentityPath: idPath,
		InPath:       inPath,
		OutDir:       dirA,
		K:            3,
		N:            5,
	}
	if _, err := Split(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	stale, err := os.ReadFile(filepath.Join(dirA, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}

	opts.OutDir = dirB
	if _, err := Split(context.Background(), opts, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirB, "manifest.age"), stale, 0o644); err != nil {
		t.Fatal(err)
	}

	restore := RestoreOptions{
		IdentityPath: idPath,
		InDir:        dirB,
		OutPath:      filepath.Join(t.TempDir(), "out.bin"),
	}
	rep, verr := Verify(context.Background(), VerifyOptions{
		IdentityPath: restore.IdentityPath,
		InDir:        restore.InDir,
	}, io.Discard)
	if rep == nil {
		t.Fatal("report is nil")
	}
	if rep.Usable != 0 {
		t.Fatalf("Usable = %d, want 0", rep.Usable)
	}
	if len(rep.Shards) != 5 {
		t.Fatalf("len(Shards) = %d, want 5", len(rep.Shards))
	}
	for i, s := range rep.Shards {
		if s.State != ShardCorrupt {
			t.Errorf("Shards[%d].State = %s, want corrupt", i, s.State)
		}
	}
	if rep.PayloadChecked || rep.PayloadOK {
		t.Fatalf("PayloadChecked=%v PayloadOK=%v, want false, false", rep.PayloadChecked, rep.PayloadOK)
	}
	if !errors.Is(verr, ErrStaleManifest) {
		t.Fatalf("errors.Is(., ErrStaleManifest) = false, err=%v", verr)
	}

	_, rerr := Restore(context.Background(), restore, io.Discard)
	if rerr == nil {
		t.Fatal("Restore err = nil, want stale-manifest error")
	}
	if verr.Error() != rerr.Error() {
		t.Fatalf("Verify err %q, Restore err %q", verr.Error(), rerr.Error())
	}
}

func TestVerifyMatchesRestoreDiagnostics(t *testing.T) {
	t.Run("no manifest", func(t *testing.T) {
		restore, split := splitFixture(t)
		if err := os.Remove(filepath.Join(split.OutDir, "manifest.age")); err != nil {
			t.Fatal(err)
		}
		assertVerifyMatchesRestoreErr(t, restore)
	})

	t.Run("wrong identity", func(t *testing.T) {
		restore, _ := splitFixture(t)
		other := filepath.Join(t.TempDir(), "identity.txt")
		if _, err := key.Create(other); err != nil {
			t.Fatal(err)
		}
		restore.IdentityPath = other
		assertVerifyMatchesRestoreErr(t, restore)
	})

	t.Run("MAC mismatch", func(t *testing.T) {
		restore, _ := splitFixture(t)
		p := filepath.Join(restore.InDir, "manifest.age")
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		flipFileByte(t, p, int(fi.Size())/2)
		assertVerifyMatchesRestoreErr(t, restore)
	})

	t.Run("unreadable shard-00", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not deny root")
		}
		restore, _ := splitFixture(t)
		path := filepath.Join(restore.InDir, shardFileName(0))
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
		if f, err := os.OpenFile(path, readOpenFlags, 0); err == nil {
			f.Close()
			t.Skip("process can still read chmod 0000 shard")
		}

		restore.OutPath = filepath.Join(t.TempDir(), "out.bin")
		var rstatus, vstatus bytes.Buffer
		rrep, rerr := Restore(context.Background(), restore, &rstatus)
		vrep, verr := Verify(context.Background(), VerifyOptions{
			IdentityPath: restore.IdentityPath,
			InDir:        restore.InDir,
		}, &vstatus)

		// Phase 1 loadShard treats open errors other than ErrNotExist as
		// unusable, so chmod 0000 does not abort openShardSet. Restore then
		// succeeds if k shards remain (and writes "restored N bytes"); Verify
		// reports damaged. Shared screening status is the unusable line.
		if rerr == nil {
			if rrep == nil {
				t.Fatal("Restore report is nil")
			}
			if len(rrep.FailedIndex) != 1 || rrep.FailedIndex[0] != 0 {
				t.Fatalf("Restore FailedIndex = %v, want [0]", rrep.FailedIndex)
			}
			if vrep == nil {
				t.Fatal("Verify report is nil; Restore classified chmod 0000 as unusable")
			}
			if vrep.Shards[0].State != ShardCorrupt {
				t.Fatalf("Shards[0].State = %s, want corrupt", vrep.Shards[0].State)
			}
			if !errors.Is(verr, ErrDamaged) {
				t.Fatalf("Verify err = %v, want ErrDamaged", verr)
			}
			const unusable = "unusable shard at index 0\n"
			if vstatus.String() != unusable {
				t.Fatalf("Verify status %q, want %q", vstatus.String(), unusable)
			}
			if !strings.Contains(rstatus.String(), "unusable shard at index 0") {
				t.Fatalf("Restore status %q missing unusable line", rstatus.String())
			}
			return
		}

		if rrep != nil || vrep != nil {
			t.Fatalf("reports: Restore %v Verify %v, want nil", rrep != nil, vrep != nil)
		}
		if verr == nil || rerr.Error() != verr.Error() {
			t.Fatalf("Verify err %v, Restore err %v", verr, rerr)
		}
	})
}

func TestVerifyCancelled(t *testing.T) {
	root := filepath.Dir(t.TempDir())
	restore, _ := splitFixture(t)
	before := snapshotTree(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := Verify(ctx, VerifyOptions{
		IdentityPath: restore.IdentityPath,
		InDir:        restore.InDir,
	}, io.Discard)
	if rep != nil {
		t.Fatal("report is not nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(., context.Canceled) = false, err=%v", err)
	}
	after := snapshotTree(t, root)
	assertTreeUnchanged(t, before, after)
}

func assertVerifyMatchesRestoreErr(t *testing.T, restore RestoreOptions) {
	t.Helper()
	restore.OutPath = filepath.Join(t.TempDir(), "out.bin")
	_, rerr := Restore(context.Background(), restore, io.Discard)
	rep, verr := Verify(context.Background(), VerifyOptions{
		IdentityPath: restore.IdentityPath,
		InDir:        restore.InDir,
	}, io.Discard)
	if rep != nil {
		t.Fatal("report is not nil")
	}
	if rerr == nil || verr == nil {
		t.Fatalf("Restore err %v, Verify err %v", rerr, verr)
	}
	if rerr.Error() != verr.Error() {
		t.Fatalf("Verify err %q, Restore err %q", verr.Error(), rerr.Error())
	}
}

type treeEntry struct {
	path string
	size int64
	mode os.FileMode
	mod  time.Time
}

func snapshotTree(t *testing.T, root string) []treeEntry {
	t.Helper()
	var out []treeEntry
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		size := int64(0)
		if info.Mode().IsRegular() {
			size = info.Size()
		}
		out = append(out, treeEntry{
			path: rel,
			size: size,
			mode: info.Mode(),
			mod:  info.ModTime(),
		})
		if strings.HasSuffix(d.Name(), ".partial") {
			t.Errorf("*.partial present: %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertTreeUnchanged(t *testing.T, before, after []treeEntry) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("tree listing length %d -> %d\nbefore:\n%s\nafter:\n%s",
			len(before), len(after), formatTree(before), formatTree(after))
	}
	for i := range before {
		b, a := before[i], after[i]
		if b.path != a.path || b.size != a.size || b.mode != a.mode || !b.mod.Equal(a.mod) {
			t.Fatalf("tree changed at %d: %s size=%d mode=%s -> %s size=%d mode=%s",
				i, b.path, b.size, b.mode, a.path, a.size, a.mode)
		}
	}
}

func formatTree(entries []treeEntry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%s size=%d mode=%s\n", e.path, e.size, e.mode)
	}
	return b.String()
}
