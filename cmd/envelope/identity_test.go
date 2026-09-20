package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/pipeline"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows support is TODO")
	}
}

func skipIfControllingTerminal(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		f.Close()
		t.Skip("controlling terminal present")
	}
}

type stubTerm struct{}

func (stubTerm) Notify(string)                         {}
func (stubTerm) ReadLine(string, bool) (string, error) { return "", errors.New("no pin") }
func (stubTerm) Close() error                          { return nil }

func writePluginIdentity(t *testing.T, name string, mode fakeplugin.Mode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin.txt")
	if err := os.WriteFile(path, []byte(fakeplugin.Identity(name, mode)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWrongIdentityNamesNativeNotPlugin(t *testing.T) {
	skipWindows(t)
	id, shards, out := mustSplitFixture(t)
	_ = id
	wrong := filepath.Join(t.TempDir(), "paper.txt")
	mustRun(t, "keygen", "-out", wrong)
	name := "envtest"
	fakeplugin.Install(t, name)
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModeOK)

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", pluginPath, "-identity", wrong, "-in", shards, "-out", out}, &stdout, &stderr)
	if code == exitOK {
		t.Fatal("exit 0, want failure")
	}
	got := stderr.String()
	if !strings.Contains(got, wrong) {
		t.Fatalf("stderr %q does not name native path %s", got, wrong)
	}
	if strings.Contains(got, pluginPath) {
		t.Fatalf("stderr %q names plugin path %s", got, pluginPath)
	}
	assertAbsent(t, out)
	assertAbsent(t, out+".partial")
}

func TestRepeatableIdentityParses(t *testing.T) {
	id, shards, out := mustSplitFixture(t)
	other := filepath.Join(t.TempDir(), "other.txt")
	mustRun(t, "keygen", "-out", other)
	want, err := os.ReadFile(filepath.Join(filepath.Dir(id), "in.bin"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("restore", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"restore", "-identity", id, "-identity", other, "-in", shards, "-out", out}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		assertSameBytes(t, got, want)
	})

	t.Run("verify", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-identity", other, "-in", shards}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
		}
		if got := stdout.String(); got != wantHealthy32 {
			t.Fatalf("stdout =\n%s\nwant\n%s", got, wantHealthy32)
		}
	})
}

func TestSingleIdentityByteIdentical(t *testing.T) {
	id, shards, out := mustSplitFixture(t)
	want, err := os.ReadFile(filepath.Join(filepath.Dir(id), "in.bin"))
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
	wantErr := fmt.Sprintf("restored %d bytes to %s\n", len(want), out)
	if stderr.String() != wantErr {
		t.Fatalf("stderr = %q, want %q", stderr.String(), wantErr)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)

	var vOut, vErr bytes.Buffer
	if code := run([]string{"verify", "-identity", id, "-in", shards}, &vOut, &vErr); code != exitOK {
		t.Fatalf("verify exit = %d, want %d\nstderr: %s", code, exitOK, vErr.String())
	}
	if vErr.Len() != 0 {
		t.Fatalf("verify stderr has %d bytes, want 0", vErr.Len())
	}
	if got := vOut.String(); got != wantHealthy32 {
		t.Fatalf("verify stdout =\n%s\nwant\n%s", got, wantHealthy32)
	}
}

func TestEmptyIdentityFlag(t *testing.T) {
	const emptyMsg = `invalid value "" for flag -identity`
	const missingMsg = `Required flag "identity" not set`

	rows := []struct {
		name     string
		args     []string
		reason   string
		contract string
	}{
		{
			name:     "restore missing -identity",
			args:     []string{"restore", "-in", "shards", "-out", "out"},
			reason:   missingMsg,
			contract: usageRestore,
		},
		{
			name:     "restore -identity empty",
			args:     []string{"restore", "-identity", "", "-in", "shards", "-out", "out"},
			reason:   emptyMsg,
			contract: usageRestore,
		},
		{
			name:     "restore -identity=",
			args:     []string{"restore", "-identity=", "-in", "shards", "-out", "out"},
			reason:   emptyMsg,
			contract: usageRestore,
		},
		{
			name:     "verify missing -identity",
			args:     []string{"verify", "-in", "shards"},
			reason:   missingMsg,
			contract: usageVerify,
		},
		{
			name:     "verify -identity empty",
			args:     []string{"verify", "-identity", "", "-in", "shards"},
			reason:   emptyMsg,
			contract: usageVerify,
		},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
			}
			if !strings.Contains(stderr.String(), tt.reason) {
				t.Fatalf("stderr %q missing %q", stderr.String(), tt.reason)
			}
			assertContractOnStderr(t, stderr.String(), tt.contract)
		})
	}
}

func TestInteractiveIdentityNoTerminal(t *testing.T) {
	skipWindows(t)
	skipIfControllingTerminal(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	id, shards, out := mustSplitFixture(t)
	_ = id
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModePIN)

	t.Run("restore", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"restore", "-identity", pluginPath, "-in", shards, "-out", out}, &stdout, &stderr)
		if code == exitOK || code == exitUsage {
			t.Fatalf("exit = %d, want non-zero failure\nstderr: %s", code, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
		}
		if !strings.Contains(stderr.String(), pipeline.ErrNoPinTerminal.Error()) {
			t.Fatalf("stderr %q missing %q", stderr.String(), pipeline.ErrNoPinTerminal.Error())
		}
		assertAbsent(t, out)
		assertAbsent(t, out+".partial")
		if n := len(fakeplugin.Invocations(t)); n != 0 {
			t.Fatalf("plugin invocations = %d, want 0", n)
		}
	})

	t.Run("verify", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", pluginPath, "-in", shards}, &stdout, &stderr)
		if code == exitOK || code == exitUsage {
			t.Fatalf("exit = %d, want non-zero failure\nstderr: %s", code, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
		}
		if !strings.Contains(stderr.String(), pipeline.ErrNoPinTerminal.Error()) {
			t.Fatalf("stderr %q missing %q", stderr.String(), pipeline.ErrNoPinTerminal.Error())
		}
		if n := len(fakeplugin.Invocations(t)); n != 0 {
			t.Fatalf("plugin invocations = %d, want 0", n)
		}
	})
}

func TestAGEDEBUGPluginWarning(t *testing.T) {
	skipWindows(t)
	id, shards, out := mustSplitFixture(t)

	t.Setenv("AGEDEBUG", "")
	var todayOut, todayErr bytes.Buffer
	if code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &todayOut, &todayErr); code != exitOK {
		t.Fatalf("unset: exit = %d\nstderr: %s", code, todayErr.String())
	}
	if strings.Contains(todayErr.String(), ageDebugPluginWarning) {
		t.Fatalf("unset stderr has the plugin-debug warning: %q", todayErr.String())
	}

	out2 := filepath.Join(t.TempDir(), "out.bin")
	t.Setenv("AGEDEBUG", "plugin")
	var gotOut, gotErr bytes.Buffer
	if code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out2}, &gotOut, &gotErr); code != exitOK {
		t.Fatalf("set: exit = %d\nstderr: %s", code, gotErr.String())
	}
	got := gotErr.String()
	first, rest, ok := strings.Cut(got, "\n")
	if !ok {
		t.Fatalf("stderr missing newline: %q", got)
	}
	if first != ageDebugPluginWarning {
		t.Fatalf("first line = %q, want %q", first, ageDebugPluginWarning)
	}
	wantRest := strings.ReplaceAll(todayErr.String(), out, out2)
	if rest != wantRest {
		t.Fatalf("stderr after warning =\n%q\nwant\n%q", rest, wantRest)
	}

	name := "envtest"
	fakeplugin.Install(t, name)
	t.Setenv("AGEDEBUG", "plugin")
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModePIN)
	skipIfControllingTerminal(t)
	var pOut, pErr bytes.Buffer
	code := run([]string{"restore", "-identity", pluginPath, "-in", shards, "-out", filepath.Join(t.TempDir(), "no.bin")}, &pOut, &pErr)
	if code == exitOK {
		t.Fatal("plugin identity: exit 0")
	}
	pFirst, _, ok := strings.Cut(pErr.String(), "\n")
	if !ok || pFirst != ageDebugPluginWarning {
		t.Fatalf("plugin-identity first line = %q, want warning", pFirst)
	}
	if n := len(fakeplugin.Invocations(t)); n != 0 {
		t.Fatalf("plugin invocations = %d, want 0", n)
	}
}

func TestResolvedPluginPathOnStderr(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	dir := fakeplugin.Install(t, name)
	id, shards, out := mustSplitFixture(t)
	_ = id
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModeOK)
	testTerminal = stubTerm{}
	t.Cleanup(func() { testTerminal = nil })

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", pluginPath, "-in", shards, "-out", out}, &stdout, &stderr)
	if code == exitOK {
		t.Fatal("plugin-only v1 restore succeeded")
	}
	assertAbsent(t, out)
	assertAbsent(t, out+".partial")
	want := filepath.Join(dir, "age-plugin-"+name)
	if !filepath.IsAbs(want) {
		t.Fatalf("plugin path is relative: %q", want)
	}
	got := stderr.String()
	if strings.Count(got, want) != 1 {
		t.Fatalf("stderr %q: want the absolute plugin path once", got)
	}
	if !strings.Contains(got, "using "+want) {
		t.Fatalf("stderr %q missing %q", got, "using "+want)
	}
}

func TestHelpRepeatableIdentityRendering(t *testing.T) {
	const rendered = "--identity FILE [ --identity FILE ]"
	for _, cmd := range []string{"restore", "verify"} {
		help := commandHelp(t, []string{cmd, "-h"})
		if !strings.Contains(help, rendered) {
			t.Errorf("%s -h missing %q", cmd, rendered)
		}
		if !strings.Contains(help, "-identity may be repeated") {
			t.Errorf("%s -h missing repeatable-identity sentence", cmd)
		}
	}
	split := commandHelp(t, []string{"split", "-h"})
	if strings.Contains(split, rendered) {
		t.Error("split -h rendered a repeatable -identity")
	}
	keygen := commandHelp(t, []string{"keygen", "-h"})
	if strings.Contains(keygen, rendered) {
		t.Error("keygen -h rendered a repeatable -identity")
	}
}

func TestGoldenV1CLIStreams(t *testing.T) {
	id, shards, payloadLen := materialiseGoldenCLI(t)
	out := filepath.Join(t.TempDir(), "out.bin")

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("restore exit = %d\nstderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("restore stdout has %d bytes, want 0", stdout.Len())
	}
	wantErr := fmt.Sprintf("restored %d bytes to %s\n", payloadLen, out)
	if stderr.String() != wantErr {
		t.Fatalf("restore stderr = %q, want %q", stderr.String(), wantErr)
	}

	var vOut, vErr bytes.Buffer
	if code := run([]string{"verify", "-identity", id, "-in", shards}, &vOut, &vErr); code != exitOK {
		t.Fatalf("verify exit = %d\nstderr: %s", code, vErr.String())
	}
	if vErr.Len() != 0 {
		t.Fatalf("verify stderr has %d bytes, want 0", vErr.Len())
	}
	wantReport := fmt.Sprintf("manifest ok: k=3 n=5\n"+
		"shard-00 ok\nshard-01 ok\nshard-02 ok\nshard-03 ok\nshard-04 ok\n"+
		"usable 5 of 5, need 3\npayload ok: %d bytes\nresult: healthy\n", payloadLen)
	if vOut.String() != wantReport {
		t.Fatalf("verify stdout =\n%s\nwant\n%s", vOut.String(), wantReport)
	}
	lines := strings.Split(strings.TrimSuffix(vOut.String(), "\n"), "\n")
	if len(lines) != 9 {
		t.Fatalf("verify report has %d lines, want n+4=9", len(lines))
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(got)
	digest, err := os.ReadFile(filepath.Join("..", "..", "test", "golden", "v1-shardset", "payload.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	wantHex, _, ok := strings.Cut(strings.TrimSpace(string(digest)), "  ")
	if !ok || hex.EncodeToString(sum[:]) != wantHex {
		t.Fatalf("restore sha256 = %s, want %s", hex.EncodeToString(sum[:]), wantHex)
	}
}

func materialiseGoldenCLI(t *testing.T) (id, shards string, payloadLen int64) {
	t.Helper()
	dir := filepath.Join("..", "..", "test", "golden", "v1-shardset")
	data, err := os.ReadFile(filepath.Join(dir, "identity.bech32data"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] == '1' {
		t.Fatal("identity.bech32data is empty or begins with 1")
	}
	line := key.HRP + "1" + string(data) + "\n"
	id = filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(id, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	shards = t.TempDir()
	for _, name := range []string{"shard-00", "shard-01", "shard-02", "shard-03", "shard-04", "manifest.age"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shards, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "payload.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	_, length, ok := strings.Cut(strings.TrimSpace(string(raw)), "  ")
	if !ok {
		t.Fatal("payload.sha256: want '<hex>  <length>'")
	}
	if _, err := fmt.Sscanf(length, "%d", &payloadLen); err != nil {
		t.Fatal(err)
	}
	return id, shards, payloadLen
}
