package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// FR-P2-11
func TestCompletionScripts(t *testing.T) {
	tmpPrefix := os.TempDir()
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{"completion", shell}, &stdout, &stderr)
			if code != exitOK {
				t.Fatalf("exit=%d want %d\nstderr=%q", code, exitOK, stderr.String())
			}
			out := stdout.String()
			if out == "" {
				t.Fatal("stdout empty")
			}
			if !strings.Contains(out, "envelope") {
				t.Fatalf("stdout missing %q", "envelope")
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
			for _, needle := range []string{"/Users/", "/home/", tmpPrefix} {
				if strings.Contains(out, needle) {
					t.Errorf("script contains %q", needle)
				}
			}
		})
	}
}

// FR-P2-11
func TestCompletionNeverActs(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	keyOut := filepath.Join(dir, "id")
	splitOut := filepath.Join(dir, "d")
	restoreOut := filepath.Join(dir, "o")
	tests := []struct {
		name string
		args []string
		gone []string
	}{
		{
			name: "keygen",
			args: []string{"keygen", "-out", keyOut, "--generate-shell-completion"},
			gone: []string{keyOut},
		},
		{
			name: "split",
			args: []string{"split", "-identity", id, "-in", in, "-out", splitOut, "--generate-shell-completion"},
			gone: []string{splitOut},
		},
		{
			name: "restore",
			args: []string{"restore", "-identity", id, "-in", shards, "-out", restoreOut, "--generate-shell-completion"},
			gone: []string{restoreOut, restoreOut + ".partial"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit=%d want %d\nstdout=%q\nstderr=%q", code, exitOK, stdout.String(), stderr.String())
			}
			for _, path := range tt.gone {
				assertAbsent(t, path)
			}
		})
	}
}

// FR-P2-11. Root completion reads os.Args, not Run's argv, so this is a
// stock-binary subprocess (buildEnvelope with no tags).
func TestRootCompletion(t *testing.T) {
	bin := buildEnvelope(t)
	cmd := exec.Command(bin, "--generate-shell-completion")
	cmd.Env = childEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("exit error: %v\nstderr=%q", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	out := stdout.String()
	for _, name := range []string{"keygen", "split", "restore"} {
		if !strings.Contains(out, name) {
			t.Errorf("stdout missing %q: %q", name, out)
		}
	}
}
