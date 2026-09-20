package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestProgrammaticCancelRefusedBeforePlugin(t *testing.T) {
	skipWindows(t)
	// Unwrap polls no context: a deadline cannot interrupt a blocked plugin
	// read. FR-YK-13 refuses the run before any identity-side plugin starts
	// rather than starting one and hoping a cancel unblocks it.
	name := "envtest"
	fakeplugin.Install(t, name)

	testOpenTerminal = func() (Terminal, error) {
		return nil, key.ErrNoTerminal
	}
	t.Cleanup(func() { testOpenTerminal = nil })

	t.Run("restore", func(t *testing.T) {
		restore, _ := splitFixture(t)
		restore.IdentityPaths = []string{writePluginIdentity(t, name, fakeplugin.ModePIN)}
		restore.OutPath = filepath.Join(t.TempDir(), "out.bin")
		restore.Terminal = nil

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		errc := make(chan error, 1)
		go func() {
			_, err := Restore(ctx, restore, io.Discard)
			errc <- err
		}()
		select {
		case err := <-errc:
			if !errors.Is(err, ErrNoPinTerminal) {
				t.Fatalf("errors.Is(., ErrNoPinTerminal) = false: %v", err)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled instead of refusing up front: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Restore did not refuse before a plugin could block; programmatic cancel cannot unblock Unwrap")
		}
		assertNoOutOrPartial(t, restore.OutPath)
		if n := len(fakeplugin.Invocations(t)); n != 0 {
			t.Fatalf("plugin invocations = %d, want 0", n)
		}
	})

	t.Run("split", func(t *testing.T) {
		stub := writePluginStub(t, name, fakeplugin.ModePIN)
		rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
		bundle := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{stub},
			Recipients:    []string{rec},
			OutPath:       bundle,
			Terminal:      stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		in := filepath.Join(t.TempDir(), "in.bin")
		if err := os.WriteFile(in, []byte("cancel-limit"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := t.TempDir()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		errc := make(chan error, 1)
		go func() {
			_, err := Split(ctx, SplitOptions{
				IdentityPath: bundle,
				InPath:       in,
				OutDir:       out,
				K:            3,
				N:            5,
			}, io.Discard)
			errc <- err
		}()
		select {
		case err := <-errc:
			if !errors.Is(err, ErrNoPinTerminal) {
				t.Fatalf("errors.Is(., ErrNoPinTerminal) = false: %v", err)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled instead of refusing up front: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Split did not refuse the pin unwrap; programmatic cancel cannot unblock Unwrap")
		}
		assertNoShardOrManifest(t, out)
		assertNoPartialIn(t, out)
	})
}

func TestSplitS9FailureRemovesAlreadyWrittenShards(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeFatal)
	rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{stub},
		Recipients:    []string{rec},
		OutPath:       bundle,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("s9-cleanup"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	testAtCiphertext = func([]byte) {
		if err := os.WriteFile(filepath.Join(out, shardFileName(0)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "manifest.age"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "manifest.age.tmp"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { testAtCiphertext = nil })

	_, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       out,
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, io.Discard)
	if err == nil {
		t.Fatal("err = nil, want S9 failure")
	}
	assertNoShardOrManifest(t, out)
	assertNoPartialIn(t, out)
}

func TestNoDetachedPluginProcessGroup(t *testing.T) {
	// Behavioural sibling of D12: the literals must not appear as contiguous
	// text anywhere in the tree. Concatenated here so the grep gate stays green.
	needles := []string{"Sys" + "ProcAttr", "Set" + "pgid"}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if bytes.Contains(b, []byte(n)) {
				t.Errorf("%s contains %s", path, n)
			}
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if bytes.Contains(b, []byte("Process.Kill")) {
			rel, _ := filepath.Rel(root, path)
			if !strings.HasPrefix(rel, "internal/") && !strings.HasPrefix(rel, "cmd/") {
				return nil
			}
			t.Errorf("%s kills a process Envelope does not own", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDocsCancellation(t *testing.T) {
	usage, err := os.ReadFile(filepath.Join("..", "..", "docs", "usage.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(usage)
	for _, needle := range []string{
		"Ctrl-C",
		"process group",
		"programmatic",
		"SIGTERM",
		"refused up front",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("docs/usage.md missing %q", needle)
		}
	}
	check, err := os.ReadFile(filepath.Join("..", "..", "docs", "hardware-checklist.md"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(check)
	for _, needle := range []string{
		"pgrep age-plugin",
		"no `.partial`",
	} {
		if !strings.Contains(got, needle) {
			t.Errorf("docs/hardware-checklist.md missing %q", needle)
		}
	}
}
