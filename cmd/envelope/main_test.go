package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunIsCallableWithBuffers(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "identity.txt")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "-out", tmp}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatal("identity file was not created")
	}
}

func TestHelpMatchesContract(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contract string
		flags    []string
	}{
		{
			name:     "keygen -h",
			args:     []string{"keygen", "-h"},
			contract: usageKeygen,
			flags:    []string{"-out"},
		},
		{
			name:     "split -h",
			args:     []string{"split", "-h"},
			contract: usageSplit,
			flags:    []string{"-identity", "-in", "-out", "-k", "-n"},
		},
		{
			name:     "restore -h",
			args:     []string{"restore", "-h"},
			contract: usageRestore,
			flags:    []string{"-identity", "-in", "-out"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d", code, exitUsage)
			}
			help := stdout.String() + stderr.String()
			found := false
			for _, line := range strings.Split(help, "\n") {
				if line == tt.contract {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("help missing contract line %q", tt.contract)
			}
			for _, f := range tt.flags {
				if !strings.Contains(help, f) {
					t.Fatalf("help missing flag %s", f)
				}
			}
		})
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args func(*testing.T) []string
		want int
	}{
		{
			name: "unknown subcommand",
			args: func(*testing.T) []string { return []string{"nope"} },
			want: exitUsage,
		},
		{
			name: "unknown flag",
			args: func(*testing.T) []string { return []string{"keygen", "-bogus"} },
			want: exitUsage,
		},
		{
			name: "missing required flag",
			args: func(*testing.T) []string { return []string{"keygen"} },
			want: exitUsage,
		},
		{
			name: "flag.ErrHelp",
			args: func(*testing.T) []string { return []string{"keygen", "-h"} },
			want: exitUsage,
		},
		{
			name: "-k 0",
			args: func(*testing.T) []string {
				return []string{"split", "-identity", "id", "-in", "in", "-out", "out", "-k", "0"}
			},
			want: exitUsage,
		},
		{
			name: "-n 3 -k 3",
			args: func(*testing.T) []string {
				return []string{"split", "-identity", "id", "-in", "in", "-out", "out", "-n", "3", "-k", "3"}
			},
			want: exitUsage,
		},
		{
			name: "-n 257",
			args: func(*testing.T) []string {
				return []string{"split", "-identity", "id", "-in", "in", "-out", "out", "-n", "257"}
			},
			want: exitUsage,
		},
		{
			name: "wrong identity restore",
			args: func(t *testing.T) []string {
				dir := t.TempDir()
				id := filepath.Join(dir, "identity.txt")
				other := filepath.Join(dir, "other.txt")
				in := filepath.Join(dir, "in.bin")
				shards := filepath.Join(dir, "shards")
				out := filepath.Join(dir, "out.bin")
				mustRun(t, "keygen", "-out", id)
				mustRun(t, "keygen", "-out", other)
				writeOpaque(t, in, 32)
				mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
				return []string{"restore", "-identity", other, "-in", shards, "-out", out}
			},
			want: exitFailure,
		},
		{
			name: "non-empty -out split",
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
			want: exitFailure,
		},
		{
			name: "success",
			args: func(t *testing.T) []string {
				return []string{"keygen", "-out", filepath.Join(t.TempDir(), "identity.txt")}
			},
			want: exitOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args(t), &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("exit = %d, want %d", code, tt.want)
			}
		})
	}
}

func TestVersionNamesBothPins(t *testing.T) {
	// ReadBuildInfo reports resolved module versions and returns nothing useful
	// outside module mode, so this AC holds for a normal go build.
	var stdout, stderr bytes.Buffer
	code := run([]string{"-version"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	out := stdout.String()
	if !strings.Contains(out, "filippo.io/age v1.3.1") {
		t.Fatalf("stdout missing filippo.io/age v1.3.1")
	}
	if !strings.Contains(out, "github.com/klauspost/reedsolomon v1.14.2") {
		t.Fatalf("stdout missing github.com/klauspost/reedsolomon v1.14.2")
	}
}

func TestVersionPrecedesDispatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-version", "split"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "filippo.io/age v1.3.1") {
		t.Fatal("did not take the version branch")
	}
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	code := run(args, io.Discard, io.Discard)
	if code != exitOK {
		t.Fatalf("run %v: exit = %d", args, code)
	}
}

func writeOpaque(t *testing.T, path string, n int) {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
