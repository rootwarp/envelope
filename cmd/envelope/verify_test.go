package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/pipeline"
)

const (
	wantHealthy32 = `manifest ok: k=3 n=5
shard-00 ok
shard-01 ok
shard-02 ok
shard-03 ok
shard-04 ok
usable 5 of 5, need 3
payload ok: 32 bytes
result: healthy
`
	wantDamaged32 = `manifest ok: k=3 n=5
shard-00 ok
shard-01 missing
shard-02 corrupt
shard-03 ok
shard-04 ok
usable 3 of 5, need 3
payload ok: 32 bytes
result: damaged
`
	wantDegraded32 = `manifest ok: k=3 n=5
shard-00 ok
shard-01 ok
shard-02 ok
shard-03 missing
shard-04 missing
usable 3 of 5, need 3
payload ok: 32 bytes
result: degraded
`
	wantTooFew32 = `manifest ok: k=3 n=5
shard-00 missing
shard-01 missing
shard-02 missing
shard-03 ok
shard-04 ok
usable 2 of 5, need 3
payload skipped
result: unrestorable
`
	wantStale32 = `manifest ok: k=3 n=5
shard-00 corrupt
shard-01 corrupt
shard-02 corrupt
shard-03 corrupt
shard-04 corrupt
usable 0 of 5, need 3
payload skipped
result: unrestorable
`
)

// FR-P2-13
func TestVerifyReportGolden(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		id, shards, _ := mustSplitFixture(t)
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitOK, stderr.Len())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr has %d bytes, want 0", stderr.Len())
		}
		if got := stdout.String(); got != wantHealthy32 {
			t.Fatalf("stdout =\n%s\nwant\n%s", got, wantHealthy32)
		}
	})

	t.Run("damaged", func(t *testing.T) {
		id, shards, _ := mustSplitFixture(t)
		if err := os.Remove(filepath.Join(shards, "shard-01")); err != nil {
			t.Fatal(err)
		}
		xorFileByte(t, filepath.Join(shards, "shard-02"), 0)
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
		if code != exitFailure {
			t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitFailure, stderr.Len())
		}
		if got := stdout.String(); got != wantDamaged32 {
			t.Fatalf("stdout =\n%s\nwant\n%s", got, wantDamaged32)
		}
	})

	t.Run("payload failed", func(t *testing.T) {
		var buf bytes.Buffer
		writeVerifyReport(&buf, &pipeline.VerifyReport{
			K: 3, N: 5,
			Shards: []pipeline.ShardStatus{
				{Name: "shard-00", State: pipeline.ShardOK},
				{Name: "shard-01", State: pipeline.ShardOK},
				{Name: "shard-02", State: pipeline.ShardOK},
				{Name: "shard-03", State: pipeline.ShardOK},
				{Name: "shard-04", State: pipeline.ShardOK},
			},
			Usable:         5,
			PayloadChecked: true,
			Result:         pipeline.VerifyUnrestorable,
		})
		const want = `manifest ok: k=3 n=5
shard-00 ok
shard-01 ok
shard-02 ok
shard-03 ok
shard-04 ok
usable 5 of 5, need 3
payload failed
result: unrestorable
`
		if got := buf.String(); got != want {
			t.Fatalf("stdout =\n%s\nwant\n%s", got, want)
		}
	})

	t.Run("payload skipped", func(t *testing.T) {
		var buf bytes.Buffer
		writeVerifyReport(&buf, &pipeline.VerifyReport{
			K: 3, N: 5,
			Shards: []pipeline.ShardStatus{
				{Name: "shard-00", State: pipeline.ShardMissing},
				{Name: "shard-01", State: pipeline.ShardMissing},
				{Name: "shard-02", State: pipeline.ShardMissing},
				{Name: "shard-03", State: pipeline.ShardOK},
				{Name: "shard-04", State: pipeline.ShardOK},
			},
			Usable: 2,
			Result: pipeline.VerifyUnrestorable,
		})
		const want = `manifest ok: k=3 n=5
shard-00 missing
shard-01 missing
shard-02 missing
shard-03 ok
shard-04 ok
usable 2 of 5, need 3
payload skipped
result: unrestorable
`
		if got := buf.String(); got != want {
			t.Fatalf("stdout =\n%s\nwant\n%s", got, want)
		}
	})
}

// FR-P2-13. Cancelled is TestVerifyCancelled: run() cannot cancel its own signal ctx.
func TestVerifyExitCodes(t *testing.T) {
	tests := []struct {
		name        string
		code        int
		prep        func(*testing.T) (args []string, wantOut string)
		errEmpty    bool
		errContains []string
	}{
		{
			name: "healthy",
			code: exitOK,
			prep: func(t *testing.T) ([]string, string) {
				id, shards, _ := mustSplitFixture(t)
				return []string{"verify", "-identity", id, "-in", shards}, wantHealthy32
			},
			errEmpty: true,
		},
		{
			name: "degraded",
			code: exitOK,
			prep: func(t *testing.T) ([]string, string) {
				id, shards, _ := mustSplitFixture(t)
				for _, name := range []string{"shard-03", "shard-04"} {
					if err := os.Remove(filepath.Join(shards, name)); err != nil {
						t.Fatal(err)
					}
				}
				return []string{"verify", "-identity", id, "-in", shards}, wantDegraded32
			},
			errEmpty: true,
		},
		{
			name: "damaged",
			code: exitFailure,
			prep: func(t *testing.T) ([]string, string) {
				id, shards, _ := mustSplitFixture(t)
				if err := os.Remove(filepath.Join(shards, "shard-01")); err != nil {
					t.Fatal(err)
				}
				xorFileByte(t, filepath.Join(shards, "shard-02"), 0)
				return []string{"verify", "-identity", id, "-in", shards}, wantDamaged32
			},
			errContains: []string{"failed digest at index 2", pipeline.ErrDamaged.Error()},
		},
		{
			name: "unrestorable by count",
			code: exitFailure,
			prep: func(t *testing.T) ([]string, string) {
				id, shards, _ := mustSplitFixture(t)
				for _, name := range []string{"shard-00", "shard-01", "shard-02"} {
					if err := os.Remove(filepath.Join(shards, name)); err != nil {
						t.Fatal(err)
					}
				}
				return []string{"verify", "-identity", id, "-in", shards}, wantTooFew32
			},
			errContains: []string{"need at least 3 usable shards, have 2"},
		},
		{
			name: "stale",
			code: exitFailure,
			prep: func(t *testing.T) ([]string, string) {
				return staleVerifyArgs(t), wantStale32
			},
			errContains: []string{
				"failed digest at index 0",
				"0 of 5 shards matched the manifest — the manifest may not belong to this shard set.",
			},
		},
		{
			name: "no manifest",
			code: exitFailure,
			prep: func(t *testing.T) ([]string, string) {
				id, shards, _ := mustSplitFixture(t)
				if err := os.Remove(filepath.Join(shards, "manifest.age")); err != nil {
					t.Fatal(err)
				}
				return []string{"verify", "-identity", id, "-in", shards}, ""
			},
			errContains: []string{"no manifest.age in the shard directory"},
		},
		{
			name: "wrong identity",
			code: exitFailure,
			prep: func(t *testing.T) ([]string, string) {
				id, shards, _ := mustSplitFixture(t)
				other := filepath.Join(filepath.Dir(id), "other.txt")
				mustRun(t, "keygen", "-out", other)
				return []string{"verify", "-identity", other, "-in", shards}, ""
			},
			errContains: []string{"no identity matched the file"},
		},
		{
			name: "usage",
			code: exitUsage,
			prep: func(*testing.T) ([]string, string) {
				return []string{"verify"}, ""
			},
			errContains: []string{`"identity, in"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, wantOut := tt.prep(t)
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit = %d, want %d\nstdout=%q\nstderr=%q", code, tt.code, stdout.String(), stderr.String())
			}
			if got := stdout.String(); got != wantOut {
				t.Fatalf("stdout =\n%s\nwant\n%s", got, wantOut)
			}
			errStr := stderr.String()
			if tt.errEmpty {
				if stderr.Len() != 0 {
					t.Fatalf("stderr has %d bytes, want 0", stderr.Len())
				}
				return
			}
			for _, s := range tt.errContains {
				if !strings.Contains(errStr, s) {
					t.Fatalf("stderr missing %q (len=%d)", s, stderr.Len())
				}
			}
			if tt.code == exitFailure {
				line := lastLine(errStr)
				if line == "" {
					t.Fatal("stderr empty")
				}
				if n := strings.Count(errStr, line); n != 1 {
					t.Fatalf("error %q printed %d times (stderr len=%d)", line, n, stderr.Len())
				}
			}
			if tt.code == exitUsage {
				assertContractOnStderr(t, errStr, usageVerify)
			}
		})
	}
}

// An in-process run() cannot cancel its own signal ctx. Payload-stage cancel
// is pipeline TestVerifyCancelled (nil report) plus exitCode's default branch.
func TestVerifyCancelled(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	err := runErr(ctx, []string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
	code := exitCode(err, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	got := stderr.String()
	if n := strings.Count(got, err.Error()); n != 1 {
		t.Fatalf("error %q printed %d times (stderr len=%d)", err.Error(), n, stderr.Len())
	}
}

// NFR-4
func TestVerifyMarkerNeverReachesOutput(t *testing.T) {
	setup := func(t *testing.T) (id, shards string, marker []byte) {
		t.Helper()
		dir := t.TempDir()
		id = filepath.Join(dir, "identity.txt")
		in := filepath.Join(dir, "in.bin")
		shards = filepath.Join(dir, "shards")
		marker = syntheticMarker(t)
		inBytes := make([]byte, 4096)
		if _, err := rand.Read(inBytes); err != nil {
			t.Fatal(err)
		}
		copy(inBytes[1024:], marker)
		if err := os.WriteFile(in, inBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		mustRun(t, "keygen", "-out", id)
		mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
		return id, shards, marker
	}
	check := func(t *testing.T, marker []byte, stdout, stderr string) {
		t.Helper()
		if strings.Contains(stdout, string(marker)) || strings.Contains(stderr, string(marker)) {
			t.Error("marker present in a stream")
		}
		secret := "AGE-SECRET-KEY-"
		if strings.Contains(strings.ToUpper(stdout), secret) || strings.Contains(strings.ToUpper(stderr), secret) {
			t.Error("stream contains identity prefix")
		}
	}

	t.Run("healthy", func(t *testing.T) {
		id, shards, marker := setup(t)
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitOK, stderr.Len())
		}
		check(t, marker, stdout.String(), stderr.String())
	})

	t.Run("damaged", func(t *testing.T) {
		id, shards, marker := setup(t)
		xorFileByte(t, filepath.Join(shards, "shard-02"), 0)
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
		if code != exitFailure {
			t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitFailure, stderr.Len())
		}
		check(t, marker, stdout.String(), stderr.String())
	})

	t.Run("unrestorable", func(t *testing.T) {
		id, shards, marker := setup(t)
		for _, name := range []string{"shard-00", "shard-01", "shard-02"} {
			if err := os.Remove(filepath.Join(shards, name)); err != nil {
				t.Fatal(err)
			}
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
		if code != exitFailure {
			t.Fatalf("exit = %d, want %d (stderr len=%d)", code, exitFailure, stderr.Len())
		}
		check(t, marker, stdout.String(), stderr.String())
	})
}

func staleVerifyArgs(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	dirA := filepath.Join(dir, "a")
	dirB := filepath.Join(dir, "b")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", dirA)
	stale, err := os.ReadFile(filepath.Join(dirA, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, "split", "-identity", id, "-in", in, "-out", dirB)
	if err := os.WriteFile(filepath.Join(dirB, "manifest.age"), stale, 0o644); err != nil {
		t.Fatal(err)
	}
	return []string{"verify", "-identity", id, "-in", dirB}
}
