package fakeplugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDisciplinePasses(t *testing.T) {
	out, err := runDiscipline(t, repoRoot(t))
	if err != nil {
		t.Fatalf("check-discipline.sh: %v\n%s", err, out)
	}
}

func TestDisciplineD4(t *testing.T) {
	root := scratchDiscipline(t)
	writeFile(t, filepath.Join(root, "internal", "key", "key.go"), "package key\n")
	writeFile(t, filepath.Join(root, "internal", "manifest", "manifest.go"),
		"package manifest\n\nimport _ \"github.com/rootwarp/envelope/internal/key\"\n")
	assertDisciplineRule(t, root, "D4")
}

func TestDisciplineD8(t *testing.T) {
	root := scratchDiscipline(t)
	writeFile(t, filepath.Join(root, "internal", "crypt", "crypt.go"), "package crypt\n")
	writeFile(t, filepath.Join(root, "internal", "erasure", "erasure.go"), "package erasure\n")
	writeFile(t, filepath.Join(root, "internal", "key", "key.go"),
		"package key\n\nimport _ \"github.com/rootwarp/envelope/internal/erasure\"\n")
	assertDisciplineRule(t, root, "D8")
}

func TestDisciplineNoAgeIdentifier(t *testing.T) {
	root := scratchDiscipline(t)
	writeFile(t, filepath.Join(root, "internal", "pipeline", "p.go"),
		"package pipeline\n\nvar _ = age.Decrypt\n")
	assertDisciplineRule(t, root, "D2")
}

func TestDisciplineD9(t *testing.T) {
	root := scratchDiscipline(t)
	writeFile(t, filepath.Join(root, "internal", "crypt", "crypt.go"), "package crypt\n")
	// _test.go import: D5's .Imports-only form would miss this; D9 must not.
	writeFile(t, filepath.Join(root, "internal", "crypt", "crypt_test.go"),
		"package crypt\n\nimport _ \"filippo.io/age/plugin\"\n")
	assertDisciplineRule(t, root, "D9")
}

func TestDisciplineD10(t *testing.T) {
	root := scratchDiscipline(t)
	writeFile(t, filepath.Join(root, "test", "fakeplugin", "fakeplugin.go"), "package fakeplugin\n")
	writeFile(t, filepath.Join(root, "bad.go"),
		"package envelope\n\nimport _ \"github.com/rootwarp/envelope/test/fakeplugin\"\n")
	assertDisciplineRule(t, root, "D10")
}

func TestDisciplineD11(t *testing.T) {
	root := scratchDiscipline(t)
	writeFile(t, filepath.Join(root, "internal", "key", "doc.go"), "package key\n\n// yubikey\n")
	assertDisciplineRule(t, root, "D11")
}

func TestDisciplineD12(t *testing.T) {
	root := scratchDiscipline(t)
	needle := "Sys" + "ProcAttr"
	writeFile(t, filepath.Join(root, "p.go"), "package p\n\nvar s = \""+needle+"\"\n")
	assertDisciplineRule(t, root, "D12")
}

func assertDisciplineRule(t *testing.T, root, rule string) {
	t.Helper()
	out, err := runDiscipline(t, root)
	if err == nil {
		t.Fatalf("check-discipline.sh exited 0, want %s failure\n%s", rule, out)
	}
	if !strings.Contains(out, rule+":") {
		t.Fatalf("output does not name %s:\n%s", rule, out)
	}
}

func scratchDiscipline(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	src := repoRoot(t)
	copyFile(t, filepath.Join(src, "go.mod"), filepath.Join(root, "go.mod"), 0o644)
	copyFile(t, filepath.Join(src, "go.sum"), filepath.Join(root, "go.sum"), 0o644)
	copyFile(t, filepath.Join(src, "scripts", "check-discipline.sh"),
		filepath.Join(root, "scripts", "check-discipline.sh"), 0o755)
	cmd := exec.Command("git", "init", "-q")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return root
}

func runDiscipline(t *testing.T, root string) (string, error) {
	t.Helper()
	script := filepath.Join(root, "scripts", "check-discipline.sh")
	cmd := exec.Command("bash", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=off")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		t.Fatal(err)
	}
}
