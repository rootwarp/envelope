package pipeline

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
