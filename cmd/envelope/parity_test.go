package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// FR-P2-06
func TestVersionBuildInfoUnavailable(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := writeVersion(&out, nil, false)
	code := exitCode(err, &errBuf)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	if got, want := errBuf.String(), "build info unavailable\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
}

// FR-P2-06
func TestWriteVersionHonorsReplace(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-test"},
		Deps: []*debug.Module{
			{
				Path:    "filippo.io/age",
				Version: "v1.3.1",
				Replace: &debug.Module{Path: "example.com/age", Version: "v9.9.9-replace"},
			},
			{
				Path:    "github.com/klauspost/reedsolomon",
				Version: "v1.14.2",
			},
		},
	}
	var out bytes.Buffer
	if err := writeVersion(&out, info, true); err != nil {
		t.Fatal(err)
	}
	want := "envelope v0.0.0-test\nfilippo.io/age v9.9.9-replace\ngithub.com/klauspost/reedsolomon v1.14.2\n"
	if got := out.String(); got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

// FR-P2-02
func TestFlagSyntaxes(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 64)
	want, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}

	forms := []string{"-flag v", "-flag=v", "--flag v", "--flag=v"}
	for _, form := range forms {
		t.Run(form, func(t *testing.T) {
			shards := filepath.Join(t.TempDir(), "shards")
			out := filepath.Join(t.TempDir(), "out.bin")
			mustRun(t, flagArgv(t, form, "split",
				"identity", id, "in", in, "out", shards, "k", "4", "n", "6")...)
			n, man := countShardFiles(t, shards)
			if n != 6 {
				t.Fatalf("shards = %d, want 6", n)
			}
			if !man {
				t.Fatal("manifest.age missing")
			}
			mustRun(t, flagArgv(t, form, "restore",
				"identity", id, "in", shards, "out", out)...)
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			assertSameBytes(t, got, want)
		})
	}
}

// FR-P2-01
func TestRunIsReentrant(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)

	t.Run("k n then defaults", func(t *testing.T) {
		first := filepath.Join(t.TempDir(), "s")
		mustRun(t, "split", "-identity", id, "-in", in, "-out", first, "-k", "4", "-n", "6")
		second := filepath.Join(t.TempDir(), "s")
		mustRun(t, "split", "-identity", id, "-in", in, "-out", second)
		n, man := countShardFiles(t, second)
		if n != 5 {
			t.Fatalf("default split shards = %d, want 5", n)
		}
		if !man {
			t.Fatal("manifest.age missing")
		}
	})

	t.Run("required flag after set", func(t *testing.T) {
		a := filepath.Join(t.TempDir(), "a")
		mustRun(t, "keygen", "-out", a)
		var stdout, stderr bytes.Buffer
		code := run([]string{"keygen"}, &stdout, &stderr)
		if code != exitUsage {
			t.Fatalf("exit = %d, want %d", code, exitUsage)
		}
		const want = `Required flag "out" not set`
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr %q missing %q", stderr.String(), want)
		}
	})
}

// FR-P2-05
func TestHelpDoesNotAct(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	splitOut := filepath.Join(dir, "d")
	keyOut := filepath.Join(dir, "x")
	restoreOut := filepath.Join(dir, "o")
	tests := []struct {
		name string
		args []string
		gone []string
	}{
		{
			name: "split",
			args: []string{"split", "-identity", id, "-in", in, "-out", splitOut, "-h"},
			gone: []string{splitOut},
		},
		{
			name: "keygen",
			args: []string{"keygen", "-out", keyOut, "-h"},
			gone: []string{keyOut},
		},
		{
			name: "restore",
			args: []string{"restore", "-identity", id, "-in", shards, "-out", restoreOut, "-h"},
			gone: []string{restoreOut, restoreOut + ".partial"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit = %d, want %d", code, exitOK)
			}
			for _, path := range tt.gone {
				assertAbsent(t, path)
			}
		})
	}
}

// FR-P2-05
func TestRootHelpCarriesContract(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	var helpLines []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		helpLines = append(helpLines, strings.TrimSpace(line))
	}
	for _, want := range strings.Split(usageAll, "\n") {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		found := false
		for _, got := range helpLines {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("root help missing contract line %q", want)
		}
	}
}

func flagArgv(t *testing.T, form, cmd string, kv ...string) []string {
	t.Helper()
	if len(kv)%2 != 0 {
		t.Fatalf("flag pairs must be even, got %d", len(kv))
	}
	args := []string{cmd}
	for i := 0; i < len(kv); i += 2 {
		args = append(args, flagArgs(t, form, kv[i], kv[i+1])...)
	}
	return args
}

func flagArgs(t *testing.T, form, name, value string) []string {
	t.Helper()
	switch form {
	case "-flag v":
		return []string{"-" + name, value}
	case "-flag=v":
		return []string{"-" + name + "=" + value}
	case "--flag v":
		return []string{"--" + name, value}
	case "--flag=v":
		return []string{"--" + name + "=" + value}
	default:
		t.Fatalf("unknown flag form %q", form)
		return nil
	}
}

func countShardFiles(t *testing.T, dir string) (n int, hasManifest bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch name := e.Name(); {
		case name == "manifest.age":
			hasManifest = true
		case strings.HasPrefix(name, "shard-"):
			n++
		}
	}
	return n, hasManifest
}

// assertSameBytes compares payloads without ever putting them in the log.
func assertSameBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	off := -1
	for i := 0; i < min(len(got), len(want)); i++ {
		if got[i] != want[i] {
			off = i
			break
		}
	}
	t.Fatalf("mismatch: len got=%d want=%d, first diff at %d", len(got), len(want), off)
}
