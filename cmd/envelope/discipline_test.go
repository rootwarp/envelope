package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckDisciplineRulesStillFail runs the real script against a throwaway
// module. The script cds to its own parent and exits on the first hit, so a
// rewritten message cannot be checked in this tree without planting a violation.
func TestCheckDisciplineRulesStillFail(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check-discipline.sh"))
	if err != nil {
		t.Fatal(err)
	}
	needle := "AGE-SECRET-KEY-" + "1"
	// Split so this file does not itself trip the process-stream or payload-log gates.
	stdout := "os.Std" + "out"
	streams := stdout + "/" + "os.Std" + "err"
	leakLine := "t." + "Log(" + "plaintext)"

	cases := []struct {
		name  string
		want  string
		setup func(t *testing.T, root string)
	}{
		{
			name: "stdout under internal",
			want: "process streams: " + streams + " under internal/",
			setup: func(t *testing.T, root string) {
				writeDisciplineFile(t, filepath.Join(root, "internal", "bad", "bad.go"),
					"package bad\n\nimport \"os\"\n\nfunc f() { _ = "+stdout+" }\n")
			},
		},
		{
			name: "stdout in cmd",
			want: "process streams: " + streams + " in cmd/envelope besides main's one-liner",
			setup: func(t *testing.T, root string) {
				writeDisciplineFile(t, filepath.Join(root, "cmd", "envelope", "extra.go"),
					"package main\n\nimport \"os\"\n\nfunc extra() { _ = "+stdout+" }\n")
			},
		},
		{
			name: "logged payload",
			want: "test logs a payload variable (plaintext, payload, secret, scalar, or macKey)",
			setup: func(t *testing.T, root string) {
				writeDisciplineFile(t, filepath.Join(root, "leak_test.go"),
					"package discipline\n\nimport \"testing\"\n\nfunc TestLeak(t *testing.T) {\n\tvar plaintext []byte\n\t"+leakLine+"\n}\n")
			},
		},
		{
			name: "tracked identity",
			want: "native identity line (" + needle + ") in tracked files",
			setup: func(t *testing.T, root string) {
				writeDisciplineFile(t, filepath.Join(root, "notes.txt"), needle+"\n")
				gitAt(t, root, "add", "notes.txt")
			},
		},
		{
			name: "filetxn non-stdlib import",
			want: "D13: filetxn imports example.com/ext (stdlib only)",
			setup: func(t *testing.T, root string) {
				writeDisciplineFile(t, filepath.Join(root, "go.mod"),
					"module example.com/discipline\n\ngo 1.26\n\nrequire example.com/ext v0.0.0\nreplace example.com/ext => ./ext\n")
				writeDisciplineFile(t, filepath.Join(root, "ext", "ext.go"), "package ext\n")
				writeDisciplineFile(t, filepath.Join(root, "internal", "filetxn", "filetxn.go"),
					"package filetxn\n\nimport _ \"example.com/ext\"\n")
			},
		},
		{
			name: "unexpected filetxn importer",
			want: "D13: example.com/discipline/internal/other imports filetxn (only key and pipeline may)",
			setup: func(t *testing.T, root string) {
				writeDisciplineFile(t, filepath.Join(root, "internal", "filetxn", "filetxn.go"), "package filetxn\n")
				writeDisciplineFile(t, filepath.Join(root, "internal", "other", "other.go"),
					"package other\n\nimport _ \"example.com/discipline/internal/filetxn\"\n")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeDisciplineFile(t, filepath.Join(root, "go.mod"), "module example.com/discipline\n\ngo 1.26\n")
			scriptPath := filepath.Join(root, "scripts", "check-discipline.sh")
			writeDisciplineFile(t, scriptPath, string(script))
			if err := os.Chmod(scriptPath, 0o755); err != nil {
				t.Fatal(err)
			}
			// A parent GIT_DIR would make ls-files read this repository.
			gitAt(t, root, "init", "-q")
			tc.setup(t, root)

			cmd := exec.Command("bash", scriptPath)
			cmd.Dir = root
			cmd.Env = disciplineEnv()
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("exit 0, want failure\n%s", out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("output missing %q:\n%s", tc.want, out)
			}
		})
	}
}

func writeDisciplineFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitAt(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = disciplineEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func disciplineEnv() []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_PREFIX", "GIT_COMMON_DIR", "GOFLAGS":
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"GOTOOLCHAIN=local",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOFLAGS=-mod=mod",
	)
}
