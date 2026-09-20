//go:build unix

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

const signalTestReadyEnv = "ENVELOPE_SIGNALTEST_READY"

type pinTerm struct{}

func (pinTerm) Notify(string) {}
func (pinTerm) ReadLine(string, bool) (string, error) {
	return fakeplugin.PIN, nil
}
func (pinTerm) Close() error { return nil }

func TestSIGINTPluginPromptRestore(t *testing.T) {
	skipWindows(t)
	bin := buildEnvelope(t, "envelope_signaltest")
	name := "envtest"
	pluginDir := fakeplugin.Install(t, name)
	bundle, shards := mustPluginBundleSplit(t, name)

	dir := t.TempDir()
	out := filepath.Join(dir, "out.bin")
	ready := filepath.Join(dir, "ready")
	t.Setenv(signalTestReadyEnv, ready)
	cmd := exec.Command(bin, "restore", "-identity", bundle, "-in", shards, "-out", out)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cleanupPluginCmd(t, cmd)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	waitSignalReady(t, ready, done, cmd, &stderr)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}
	waitSignalExit(t, done, cmd, &stderr)

	assertAbsent(t, out)
	assertAbsent(t, out+".partial")
	assertNoSurvivingPlugin(t, filepath.Join(pluginDir, "age-plugin-"+name))
}

func TestSIGINTPluginPromptSplit(t *testing.T) {
	skipWindows(t)
	bin := buildEnvelope(t, "envelope_signaltest")
	name := "envtest"
	pluginDir := fakeplugin.Install(t, name)
	bundle := mustPluginBundle(t, name)

	dir := t.TempDir()
	in := filepath.Join(dir, "in.bin")
	writeOpaque(t, in, 32)
	out := filepath.Join(dir, "shards")
	ready := filepath.Join(dir, "ready")
	t.Setenv(signalTestReadyEnv, ready)
	cmd := exec.Command(bin, "split", "-identity", bundle, "-in", in, "-out", out, "-k", "3", "-n", "5")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cleanupPluginCmd(t, cmd)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	waitSignalReady(t, ready, done, cmd, &stderr)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}
	waitSignalExit(t, done, cmd, &stderr)

	assertNoSplitLeftovers(t, out)
	assertNoSurvivingPlugin(t, filepath.Join(pluginDir, "age-plugin-"+name))
}

func mustPluginBundle(t *testing.T, name string) string {
	t.Helper()
	prev := testTerminal
	testTerminal = pinTerm{}
	t.Cleanup(func() { testTerminal = prev })

	dir := t.TempDir()
	stub := filepath.Join(dir, "stub.txt")
	if err := os.WriteFile(stub, []byte(fakeplugin.Identity(name, fakeplugin.ModePIN)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	bundle := filepath.Join(dir, "bundle.txt")
	mustRun(t, "bind", "-identity", stub, "-recipient", rec, "-out", bundle)
	return bundle
}

func mustPluginBundleSplit(t *testing.T, name string) (bundle, shards string) {
	t.Helper()
	bundle = mustPluginBundle(t, name)
	dir := filepath.Dir(bundle)
	in := filepath.Join(dir, "in.bin")
	writeOpaque(t, in, 32)
	shards = filepath.Join(dir, "shards")
	mustRun(t, "split", "-identity", bundle, "-in", in, "-out", shards, "-k", "3", "-n", "5")
	return bundle, shards
}

func waitSignalReady(t *testing.T, ready string, done <-chan error, cmd *exec.Cmd, stderr *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("process exited before plugin prompt: %v\nstderr: %s", err, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("timed out waiting for plugin prompt\nstderr: %s", stderr.String())
		}
		if _, err := os.Stat(ready); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitSignalExit(t *testing.T, done <-chan error, cmd *exec.Cmd, stderr *bytes.Buffer) {
	t.Helper()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("exit 0, want non-zero\nstderr: %s", stderr.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("timed out waiting for exit after interrupt\nstderr: %s", stderr.String())
	}
}

func cleanupPluginCmd(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		for _, pid := range fakeplugin.PIDs(t) {
			p, err := os.FindProcess(pid)
			if err != nil {
				continue
			}
			_ = p.Kill()
		}
	})
}

func assertNoSplitLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == "manifest.age" || name == "manifest.age.tmp" || strings.HasPrefix(name, "shard-") {
			t.Fatalf("incomplete split left %s", name)
		}
	}
}

func assertNoSurvivingPlugin(t *testing.T, pluginBin string) {
	t.Helper()
	if live := fakeplugin.LivePIDs(t); len(live) > 0 {
		t.Fatalf("plugin pids still running: %v", live)
	}
	out, err := exec.Command("pgrep", "-f", pluginBin).CombinedOutput()
	if err == nil && len(bytes.TrimSpace(out)) > 0 {
		t.Fatalf("pgrep still lists %s: %s", pluginBin, out)
	}
}
