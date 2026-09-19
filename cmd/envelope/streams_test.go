package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// FR-P2-04
func TestErrorPrintedOnce(t *testing.T) {
	tests := []struct {
		name string
		args func(*testing.T) []string
	}{
		{
			name: "wrong identity",
			args: func(t *testing.T) []string {
				id, shards, out := mustSplitFixture(t)
				other := filepath.Join(filepath.Dir(id), "other.txt")
				mustRun(t, "keygen", "-out", other)
				return []string{"restore", "-identity", other, "-in", shards, "-out", out}
			},
		},
		{
			name: "MAC mismatch",
			args: func(t *testing.T) []string {
				id, shards, out := mustSplitFixture(t)
				tamperManifestMAC(t, id, filepath.Join(shards, "manifest.age"))
				return []string{"restore", "-identity", id, "-in", shards, "-out", out}
			},
		},
		{
			name: "no manifest",
			args: func(t *testing.T) []string {
				id, shards, out := mustSplitFixture(t)
				if err := os.Remove(filepath.Join(shards, "manifest.age")); err != nil {
					t.Fatal(err)
				}
				return []string{"restore", "-identity", id, "-in", shards, "-out", out}
			},
		},
		{
			name: "stale manifest",
			args: func(t *testing.T) []string {
				dir := t.TempDir()
				id := filepath.Join(dir, "identity.txt")
				in := filepath.Join(dir, "in.bin")
				dirA := filepath.Join(dir, "a")
				dirB := filepath.Join(dir, "b")
				out := filepath.Join(dir, "out.bin")
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
				return []string{"restore", "-identity", id, "-in", dirB, "-out", out}
			},
		},
		{
			name: "too few shards",
			args: func(t *testing.T) []string {
				id, shards, out := mustSplitFixture(t)
				for _, name := range []string{"shard-00", "shard-01", "shard-02"} {
					if err := os.Remove(filepath.Join(shards, name)); err != nil {
						t.Fatal(err)
					}
				}
				return []string{"restore", "-identity", id, "-in", shards, "-out", out}
			},
		},
		{
			name: "non-empty split -out",
			args: func(t *testing.T) []string {
				dir := t.TempDir()
				id := filepath.Join(dir, "identity.txt")
				in := filepath.Join(dir, "in.bin")
				shards := filepath.Join(dir, "shards")
				mustRun(t, "keygen", "-out", id)
				writeOpaque(t, in, 32)
				if err := os.MkdirAll(shards, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(shards, "occupant"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				return []string{"split", "-identity", id, "-in", in, "-out", shards}
			},
		},
		{
			name: "existing keygen -out",
			args: func(t *testing.T) []string {
				out := filepath.Join(t.TempDir(), "identity.txt")
				writeOpaque(t, out, 32)
				return []string{"keygen", "-out", out}
			},
		},
		{
			name: "leftover .partial",
			args: func(t *testing.T) []string {
				id, shards, out := mustSplitFixture(t)
				writeOpaque(t, out+".partial", 32)
				return []string{"restore", "-identity", id, "-in", shards, "-out", out}
			},
		},
		{
			name: "recipient missing file",
			args: func(t *testing.T) []string {
				return []string{"recipient", "-identity", filepath.Join(t.TempDir(), "missing.txt")}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args(t), &stdout, &stderr)
			assertErrorPrintedOnce(t, code, &stdout, &stderr)
		})
	}

	t.Run("build info unavailable", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := writeVersion(&stdout, nil, false)
		code := exitCode(err, &stderr)
		assertErrorPrintedOnce(t, code, &stdout, &stderr)
	})
}

// NFR-3
func TestSubprocessStreamsMatchRun(t *testing.T) {
	bin := buildEnvelope(t)
	cases := []struct {
		name string
		args []string
	}{
		{name: "split -h", args: []string{"split", "-h"}},
		{name: "split missing flags", args: []string{"split"}},
		{name: "unknown command", args: []string{usageMark}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var wantOut, wantErr bytes.Buffer
			wantCode := run(tt.args, &wantOut, &wantErr)

			cmd := exec.Command(bin, tt.args...)
			cmd.Env = childEnv()
			var gotOut, gotErr bytes.Buffer
			cmd.Stdout = &gotOut
			cmd.Stderr = &gotErr
			err := cmd.Run()
			gotCode := 0
			if err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("child %v: %v", tt.args, err)
				}
				gotCode = ee.ExitCode()
			}

			if gotCode != wantCode {
				t.Errorf("exit=%d want %d", gotCode, wantCode)
			}
			if !bytes.Equal(gotOut.Bytes(), wantOut.Bytes()) {
				t.Errorf("stdout mismatch: child len=%d run len=%d\nchild=%q\nrun=%q",
					gotOut.Len(), wantOut.Len(), gotOut.String(), wantOut.String())
			}
			if !bytes.Equal(gotErr.Bytes(), wantErr.Bytes()) {
				t.Errorf("stderr mismatch: child len=%d run len=%d\nchild=%q\nrun=%q",
					gotErr.Len(), wantErr.Len(), gotErr.String(), wantErr.String())
			}
			if bytes.Contains(gotOut.Bytes(), []byte(usageMark)) || bytes.Contains(gotErr.Bytes(), []byte(usageMark)) {
				t.Errorf("marker in child streams: stdout len=%d stderr len=%d", gotOut.Len(), gotErr.Len())
			}
		})
	}
}

func assertErrorPrintedOnce(t *testing.T, code int, stdout, stderr *bytes.Buffer) {
	t.Helper()
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
	got := stderr.String()
	line := lastLine(got)
	if line == "" {
		t.Fatal("stderr empty")
	}
	if n := strings.Count(got, line); n != 1 {
		t.Fatalf("error %q printed %d times (stderr len=%d)", line, n, stderr.Len())
	}
}

// mustSplitFixture is the shared prep behind TestDistinguishableFailures:
// keygen, a 32-byte input, and split into shards.
func mustSplitFixture(t *testing.T) (id, shards, out string) {
	t.Helper()
	dir := t.TempDir()
	id = filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards = filepath.Join(dir, "shards")
	out = filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
	return id, shards, out
}

// childEnv copies the process environment without the two library debug
// switches that write around injected writers (O19).
func childEnv() []string {
	src := os.Environ()
	env := make([]string, 0, len(src))
	for _, kv := range src {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "URFAVE_CLI_TRACING", "CLI_TEMPLATE_ERROR_DEBUG":
			continue
		}
		env = append(env, kv)
	}
	return env
}
