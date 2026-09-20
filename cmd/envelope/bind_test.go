package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/pipeline"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestBindModeMatrix(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "id.txt")
	mustRun(t, "keygen", "-out", id)
	rec := mustRecipient(t, id)
	id2 := filepath.Join(dir, "id2.txt")
	mustRun(t, "keygen", "-out", id2)
	rec2 := mustRecipient(t, id2)
	bundle := filepath.Join(dir, "bundle.txt")
	mustRun(t, "bind", "-identity", id, "-recipient", rec, "-out", bundle)

	valid := []struct {
		name string
		args []string
		out  string
	}{
		{
			name: "create",
			args: []string{"bind", "-identity", id, "-recipient", rec, "-out", filepath.Join(t.TempDir(), "b.txt")},
		},
		{
			name: "add-recipient",
			args: []string{"bind", "-bundle", mustBindCreate(t, id, rec), "-add-recipient", rec2},
		},
		{
			name: "replace-identity",
			args: []string{"bind", "-bundle", mustBindCreate(t, id, rec), "-replace-identity", id2},
		},
	}
	for _, tt := range valid {
		t.Run("ok "+tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != exitOK {
				t.Fatalf("exit=%d want %d\nstderr=%q", code, exitOK, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
			}
			assertNoSecretBytes(t, stdout.Bytes(), stderr.Bytes())
		})
	}

	outPath := filepath.Join(dir, "never.txt")
	invalid := []struct {
		name string
		args []string
	}{
		{name: "no flags", args: []string{"bind"}},
		{name: "out and bundle", args: []string{"bind", "-out", outPath, "-bundle", bundle, "-identity", id}},
		{name: "bundle neither modify", args: []string{"bind", "-bundle", bundle}},
		{name: "add and replace", args: []string{"bind", "-bundle", bundle, "-add-recipient", rec2, "-replace-identity", id2}},
		{name: "out with add-recipient", args: []string{"bind", "-out", outPath, "-add-recipient", rec2}},
		{name: "positional", args: []string{"bind", "-identity", id, "-recipient", rec, "-out", outPath, usageMark}},
		{name: "only out", args: []string{"bind", "-out", outPath}},
		{name: "only identity", args: []string{"bind", "-identity", id}},
		{name: "out identity bundle", args: []string{"bind", "-out", outPath, "-identity", id, "-bundle", bundle}},
		{name: "bundle add identity", args: []string{"bind", "-bundle", bundle, "-add-recipient", rec2, "-identity", id}},
		{name: "bundle replace recipient", args: []string{"bind", "-bundle", bundle, "-replace-identity", id2, "-recipient", rec}},
	}
	for _, tt := range invalid {
		t.Run("bad "+tt.name, func(t *testing.T) {
			before, err := os.ReadFile(bundle)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("exit=%d want %d\nstdout=%q\nstderr=%q", code, exitUsage, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout has %d bytes, want 0: %q", stdout.Len(), stdout.String())
			}
			assertContractOnStderr(t, stderr.String(), usageBind)
			if _, err := os.Lstat(outPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid bind wrote -out")
			}
			got, err := os.ReadFile(bundle)
			if err != nil {
				t.Fatal(err)
			}
			assertSameBytes(t, got, before)
			if strings.Contains(stdout.String(), usageMark) || strings.Contains(stderr.String(), usageMark) {
				t.Errorf("marker echoed: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestBindCreateExistingOut(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "id.txt")
	mustRun(t, "keygen", "-out", id)
	rec := mustRecipient(t, id)
	existing := filepath.Join(dir, "exists.txt")
	want := []byte("do-not-touch\n")
	if err := os.WriteFile(existing, want, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"bind", "-identity", id, "-recipient", rec, "-out", existing}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit=%d want %d\nstderr=%q", code, exitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), key.ErrIdentityExists.Error()) {
		t.Fatalf("stderr %q missing %q", stderr.String(), key.ErrIdentityExists.Error())
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestBindNoSecretOnStreams(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "id.txt")
	mustRun(t, "keygen", "-out", id)
	rec := mustRecipient(t, id)
	bundle := filepath.Join(dir, "bundle.txt")
	var stdout, stderr bytes.Buffer
	code := run([]string{"bind", "-identity", id, "-recipient", rec, "-out", bundle}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit=%d want %d\nstderr=%q", code, exitOK, stderr.String())
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(data) {
		t.Fatal("bundle is not valid UTF-8")
	}
	loaded, err := key.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(loaded.Zero)
	b, err := key.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := loaded.DecryptBytes(b.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	for _, blob := range [][]byte{stdout.Bytes(), stderr.Bytes(), data} {
		if bytes.Contains(blob, seed) {
			t.Fatal("32-byte seed present on a stream or in the bundle")
		}
	}
	if hex.EncodeToString(seed) == hex.EncodeToString(b.MACKeyID) {
		t.Fatal("MACKeyID equals the seed")
	}
}

func TestBindHelpDocumentsModes(t *testing.T) {
	help := commandHelp(t, []string{"help", "bind"})
	for _, s := range []string{"-add-recipient", "-replace-identity", "0 plugin interactions", "never mints a seed"} {
		if !strings.Contains(help, s) {
			t.Errorf("help bind missing %q\n%s", s, help)
		}
	}
	root := commandHelp(t, []string{"help"})
	if !strings.Contains(root, "bind") {
		t.Fatal("envelope help does not list bind")
	}
	for _, line := range []string{usageBindCreate, usageBindAdd, usageBindReplace} {
		found := false
		for _, got := range strings.Split(root, "\n") {
			if strings.TrimSpace(got) == line {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("root help missing %q", line)
		}
	}
}

func TestBindAddRecipientOldSet(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "a.txt")
	other := filepath.Join(dir, "b.txt")
	mustRun(t, "keygen", "-out", id)
	mustRun(t, "keygen", "-out", other)
	rec := mustRecipient(t, id)
	recB := mustRecipient(t, other)
	bundle := filepath.Join(dir, "bundle.txt")
	mustRun(t, "bind", "-identity", id, "-recipient", rec, "-out", bundle)
	beforeID := macKeyIDLine(t, bundle)

	in := filepath.Join(dir, "in.bin")
	writeOpaque(t, in, 64)
	shards := filepath.Join(dir, "shards")
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	mustRun(t, "bind", "-bundle", bundle, "-add-recipient", recB)
	if macKeyIDLine(t, bundle) != beforeID {
		t.Fatal("mac_key_id changed")
	}

	out := filepath.Join(dir, "out.bin")
	mustRun(t, "restore", "-identity", id, "-in", shards, "-out", out)
	want, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)

	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "-identity", id, "-in", shards}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("verify exit=%d stderr=%q", code, stderr.String())
	}

	failOut := filepath.Join(dir, "fail.bin")
	code = run([]string{"restore", "-identity", other, "-in", shards, "-out", failOut}, &stdout, &stderr)
	if code == exitOK {
		t.Fatal("new recipient restored the old set")
	}
	assertAbsent(t, failOut)
}

func TestBindReplaceIdentityRestores(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "a.txt")
	mustRun(t, "keygen", "-out", id)
	rec := mustRecipient(t, id)
	bundle := filepath.Join(dir, "bundle.txt")
	mustRun(t, "bind", "-identity", id, "-recipient", rec, "-out", bundle)
	before, err := key.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	in := filepath.Join(dir, "in.bin")
	writeOpaque(t, in, 64)
	shards := filepath.Join(dir, "shards")
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	repl := filepath.Join(dir, "replacement.txt")
	data, err := os.ReadFile(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repl, data, 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "bind", "-bundle", bundle, "-replace-identity", repl)
	after, err := key.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Pin, before.Pin) {
		t.Fatal("replace-identity re-encrypted the pin")
	}
	if !bytes.Equal(after.MACKeyID, before.MACKeyID) {
		t.Fatal("replace-identity changed mac_key_id")
	}

	out := filepath.Join(dir, "out.bin")
	mustRun(t, "restore", "-identity", repl, "-in", shards, "-out", out)
	want, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestBindReplaceInterrupted(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "a.txt")
	other := filepath.Join(dir, "b.txt")
	mustRun(t, "keygen", "-out", id)
	mustRun(t, "keygen", "-out", other)
	rec := mustRecipient(t, id)
	bundle := filepath.Join(dir, "bundle.txt")
	mustRun(t, "bind", "-identity", id, "-recipient", rec, "-out", bundle)
	orig, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected rename failure")
	key.ReplaceRename = func(string, string) error { return injected }
	t.Cleanup(func() { key.ReplaceRename = nil })

	var stdout, stderr bytes.Buffer
	code := run([]string{"bind", "-bundle", bundle, "-replace-identity", other}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit=%d want %d\nstderr=%q", code, exitFailure, stderr.String())
	}
	got, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, orig)
	assertAbsent(t, bundle+".tmp")
}

func TestBindInteractionsCLI(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	prev := testTerminal
	testTerminal = stubTerm{}
	t.Cleanup(func() { testTerminal = prev })

	dir := t.TempDir()
	stub := writePluginIdentity(t, name, fakeplugin.ModeOK)
	id := filepath.Join(dir, "paper.txt")
	mustRun(t, "keygen", "-out", id)
	rec := mustRecipient(t, id)
	bundle := filepath.Join(dir, "bundle.txt")

	before := len(fakeplugin.Invocations(t))
	mustRun(t, "bind", "-identity", stub, "-recipient", rec, "-out", bundle)
	if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
		t.Fatalf("create started %d plugin processes, want 0", n)
	}

	repl := writePluginIdentity(t, name, fakeplugin.ModePIN)
	before = len(fakeplugin.Invocations(t))
	mustRun(t, "bind", "-bundle", bundle, "-replace-identity", repl)
	if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
		t.Fatalf("replace-identity started %d plugin processes, want 0", n)
	}

	pluginRec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	pluginBundle := filepath.Join(dir, "plugin-bundle.txt")
	mustRun(t, "bind", "-identity", stub, "-recipient", pluginRec, "-out", pluginBundle)
	got := observePipelineBindSet(t)
	other := filepath.Join(dir, "other.txt")
	mustRun(t, "keygen", "-out", other)
	recB := mustRecipient(t, other)
	mustRun(t, "bind", "-bundle", pluginBundle, "-add-recipient", recB)
	if *got != 1 {
		t.Fatalf("add-recipient Interactions = %d, want 1", *got)
	}
}

func TestBindEmptyFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bind", "-bundle", ""}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit=%d want %d\nstderr=%q", code, exitUsage, stderr.String())
	}
	assertContractOnStderr(t, stderr.String(), usageBind)
}

func mustRecipient(t *testing.T, identity string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"recipient", "-identity", identity}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("recipient exit=%d stderr=%q", code, stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

func macKeyIDLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "# envelope-mac-key-id: "
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatal("no mac-key-id line")
	return ""
}

func assertNoSecretBytes(t *testing.T, blobs ...[]byte) {
	t.Helper()
	for _, blob := range blobs {
		if bytes.Contains(blob, []byte(key.HRP+"1")) {
			t.Fatal("identity material on a bind stream")
		}
	}
}

func observePipelineBindSet(t *testing.T) *int {
	t.Helper()
	n := new(int)
	*n = -1
	pipeline.ObserveBindInteractions = func(got int) { *n = got }
	t.Cleanup(func() { pipeline.ObserveBindInteractions = nil })
	return n
}

func mustBindCreate(t *testing.T, identity, recipient string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle.txt")
	mustRun(t, "bind", "-identity", identity, "-recipient", recipient, "-out", out)
	return out
}
