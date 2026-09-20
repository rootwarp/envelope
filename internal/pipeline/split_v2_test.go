package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestSplitFRYK05WrapOKUnwrapFails(t *testing.T) {
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
	if err := os.WriteFile(in, []byte("fr-yk-05-a"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	encrypted := false
	testAtCiphertext = func([]byte) { encrypted = true }
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
		t.Fatal("err = nil, want pin unwrap failure")
	}
	if !encrypted {
		t.Fatal("payload encryption did not complete before S9")
	}
	got := err.Error()
	if !strings.Contains(got, "pin") {
		t.Fatalf("error %q does not name the pin", got)
	}
	if strings.Contains(got, "recipient") && !strings.Contains(got, "pin") {
		t.Fatalf("error %q attributes the failure to a recipient", got)
	}
	assertNoShardOrManifest(t, out)
	assertNoPartialIn(t, out)
}

func TestSplitFRYK05RecipientNeverAddIdentity(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
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
	if err := os.WriteFile(in, []byte("fr-yk-05-b"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       out,
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	log := fakeplugin.ProtocolLog(t)
	sawRecipient := false
	for _, line := range log {
		if strings.Contains(line, "recipient-v1") && strings.Contains(line, "add-identity") {
			t.Fatalf("recipient side sent add-identity: %q", line)
		}
		if strings.Contains(line, "add-recipient") {
			sawRecipient = true
		}
	}
	if !sawRecipient {
		t.Fatalf("recipient side sent no add-recipient: %v", log)
	}
}

func TestSplitPluginNativeEitherRestores(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
	pluginRec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	paper, paperRec := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{stub},
		Recipients:    []string{pluginRec, paperRec},
		OutPath:       bundle,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	payload := []byte("plugin-native-either")
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	shards := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		Recipients:   []string{pluginRec, paperRec},
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	outPlugin := filepath.Join(t.TempDir(), "plugin.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{bundle},
		InDirs:        []string{shards},
		OutPath:       outPlugin,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outPlugin)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, payload)

	outPaper := filepath.Join(t.TempDir(), "paper.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{paper, bundle},
		InDirs:        []string{shards},
		OutPath:       outPaper,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(outPaper)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, payload)
}

func TestSplitDuplicateRecipientOneStanza(t *testing.T) {
	path, rec := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("dup-stanza"), 0o600); err != nil {
		t.Fatal(err)
	}
	var n int
	testAtCiphertext = func(ct []byte) { n = ageStanzaCount(ct) }
	t.Cleanup(func() { testAtCiphertext = nil })

	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		Recipients:   []string{rec, rec, " " + rec + " "},
		InPath:       in,
		OutDir:       t.TempDir(),
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("payload stanzas = %d, want 1", n)
	}
}

func TestSplitBadRecipient(t *testing.T) {
	path, rec := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		rec  string
	}{
		{name: "passphrase", rec: "correct horse battery staple"},
		{name: "non-recipient", rec: "not-a-recipient"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			_, err := Split(context.Background(), SplitOptions{
				IdentityPath: bundle,
				Recipients:   []string{tt.rec},
				InPath:       in,
				OutDir:       out,
				K:            3,
				N:            5,
			}, io.Discard)
			if !errors.Is(err, ErrBadRecipient) {
				t.Fatalf("errors.Is(., ErrBadRecipient) = false: %v", err)
			}
			if !strings.Contains(err.Error(), `"`+tt.rec+`"`) {
				t.Fatalf("error %q does not quote %q", err.Error(), tt.rec)
			}
			if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("output directory was created")
			}
		})
	}
}

func TestSplitSolePluginWarningBeforePlugin(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
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
	if err := os.WriteFile(in, []byte("warn"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &warnCatch{t: t, baseline: len(fakeplugin.Invocations(t))}
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       t.TempDir(),
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, w); err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSuffix(fmtSolePluginWarning(rec), "\n")
	if !strings.Contains(w.buf.String(), want) {
		t.Fatalf("stderr %q missing %q", w.buf.String(), want)
	}
	if w.atWarn != 0 {
		t.Fatalf("plugin invocations at warning = %d, want 0", w.atWarn)
	}
}

func TestSplitDisjointRecipientWarns(t *testing.T) {
	path, rec := mustNativeID(t)
	otherPath, otherRec := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(t.TempDir(), "in.bin")
	payload := []byte("disjoint")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	shards := t.TempDir()
	var stderr bytes.Buffer
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		Recipients:   []string{otherRec},
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
	}, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "shares no string") {
		t.Fatalf("stderr %q missing disjoint warning", stderr.String())
	}

	out := filepath.Join(t.TempDir(), "out.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{otherPath, bundle},
		InDirs:        []string{shards},
		OutPath:       out,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, payload)
}

func TestSplitInteractionsV1ZeroV2Pin(t *testing.T) {
	skipWindows(t)
	t.Run("v1", func(t *testing.T) {
		got := observeSplitSet(t)
		out := t.TempDir()
		if _, err := Split(context.Background(), validOpts(t, out), io.Discard); err != nil {
			t.Fatal(err)
		}
		if *got != 0 {
			t.Fatalf("v1 Interactions = %d, want 0", *got)
		}
	})

	t.Run("v2 p=1", func(t *testing.T) {
		name := "envtest"
		fakeplugin.Install(t, name)
		stub := writePluginStub(t, name, fakeplugin.ModeOK)
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
		if err := os.WriteFile(in, []byte{1}, 0o600); err != nil {
			t.Fatal(err)
		}
		got := observeSplitSet(t)
		if _, err := Split(context.Background(), SplitOptions{
			IdentityPath: bundle,
			InPath:       in,
			OutDir:       t.TempDir(),
			K:            3,
			N:            5,
			Terminal:     stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if *got != 1 {
			t.Fatalf("v2 p=1 Interactions = %d, want 1", *got)
		}
	})

	t.Run("v2 p=2 first rejected", func(t *testing.T) {
		name := "envtest"
		fakeplugin.Install(t, name)
		stubs := []string{
			writePluginStub(t, name, fakeplugin.ModeIncorrectIdentity),
			writePluginStub(t, name, fakeplugin.ModeOK),
		}
		rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
		bundle := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: stubs,
			Recipients:    []string{rec},
			OutPath:       bundle,
			Terminal:      stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		in := filepath.Join(t.TempDir(), "in.bin")
		if err := os.WriteFile(in, []byte{1}, 0o600); err != nil {
			t.Fatal(err)
		}
		got := observeSplitSet(t)
		if _, err := Split(context.Background(), SplitOptions{
			IdentityPath: bundle,
			InPath:       in,
			OutDir:       t.TempDir(),
			K:            3,
			N:            5,
			Terminal:     stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if *got != 2 {
			t.Fatalf("v2 p=2 Interactions = %d, want 2", *got)
		}
	})
}

func TestSplitV1ParityGolden(t *testing.T) {
	dir := goldenV1Dir(t)
	idPath := materialiseGoldenIdentity(t, dir)
	inDir := copyGoldenShardSet(t, dir)
	outPath := filepath.Join(t.TempDir(), "payload.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{idPath},
		InDirs:        []string{inDir},
		OutPath:       outPath,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	resplit := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: idPath,
		InPath:       outPath,
		OutDir:       resplit,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	id, err := key.Load(idPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	blob, err := os.ReadFile(filepath.Join(resplit, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Open(blob, id, id)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != manifest.Version {
		t.Fatalf("Version = %d, want v1 %d", m.Version, manifest.Version)
	}
	if m.MACSource != 0 || len(m.MACKeyID) != 0 {
		t.Fatal("v1 resplit carried v2 MAC source fields")
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("mac_source")) || bytes.Contains(body, []byte("mac_key_id")) {
		t.Fatal("v1 body JSON contains mac source keys")
	}
	if m.MACSource == manifest.MACSourceScalar && m.Version == manifest.VersionPin {
		t.Fatal("MACSourceScalar written as a v2 source")
	}
}

func TestSplitV2NeverMACSourceScalar(t *testing.T) {
	path, rec := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("v2-source"), 0o600); err != nil {
		t.Fatal(err)
	}
	shards := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	set, err := key.LoadSet([]string{bundle}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	blob, err := os.ReadFile(filepath.Join(shards, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Open(blob, set, set)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != manifest.VersionPin {
		t.Fatalf("Version = %d, want v2", m.Version)
	}
	if m.MACSource != manifest.MACSourcePin {
		t.Fatalf("MACSource = %d, want pin (never scalar)", m.MACSource)
	}
	if m.MACSource == manifest.MACSourceScalar {
		t.Fatal("MACSourceScalar written as a v2 source")
	}
}

func TestSplitMACSourceDecidedBeforeIn(t *testing.T) {
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

	out := filepath.Join(t.TempDir(), "out")
	_, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       filepath.Join(t.TempDir(), "missing.bin"),
		OutDir:       out,
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, io.Discard)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v2 missing -in: errors.Is(., os.ErrNotExist) = false: %v", err)
	}
	if errors.Is(err, key.ErrInvalidIdentity) {
		t.Fatal("v2 missing -in took the v1 Load path")
	}
	if strings.Contains(err.Error(), "pin") {
		t.Fatalf("v2 missing -in unwrapped the pin: %v", err)
	}

	v1 := validOpts(t, filepath.Join(t.TempDir(), "v1out"))
	v1.InPath = filepath.Join(t.TempDir(), "missing.bin")
	_, err = Split(context.Background(), v1, io.Discard)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v1 missing -in: errors.Is(., os.ErrNotExist) = false: %v", err)
	}
}

func TestSplitNoRecipientFromIdentity(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	_, err := Split(context.Background(), SplitOptions{
		IdentityPath: stub,
		InPath:       in,
		OutDir:       out,
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, io.Discard)
	if err == nil {
		t.Fatal("split from a plugin identity with no recipient succeeded")
	}
	if errors.Is(err, key.ErrNoLocalRecipient) {
		t.Fatal("I-10: constructed a recipient from a plugin identity")
	}
	if n := len(fakeplugin.Invocations(t)); n != 0 {
		t.Fatalf("plugin invocations = %d, want 0", n)
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	src := filepath.Join(filepath.Dir(file), "split.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Recipient" {
			return true
		}
		t.Errorf("%s: identity .Recipient() (I-10)", fset.Position(call.Pos()))
		return true
	})
}

func TestSplitDoesNotRewriteBundle(t *testing.T) {
	path, rec := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	_, other := mustNativeID(t)
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("no-rewrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		Recipients:   []string{other},
		InPath:       in,
		OutDir:       t.TempDir(),
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, after, before)
}

func TestDocsSplitWithBundle(t *testing.T) {
	usage, err := os.ReadFile(filepath.Join("..", "..", "docs", "usage.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(usage)
	for _, needle := range []string{
		"split with a bundle",
		"Encryption does not need the card",
		"for this split only",
		"only one recipient (age1",
		"payload and manifest",
		"no passphrase path",
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
		"Card-free split",
		"≥ 1 MiB",
		"[YK1, YK2, paper]",
	} {
		if !strings.Contains(got, needle) {
			t.Errorf("docs/hardware-checklist.md missing %q", needle)
		}
	}
}

func TestSplitBindRestoreRoundTrip(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModeOK)
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

	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	shards := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: bundle,
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
		Terminal:     stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{3, 4} {
		if err := os.Remove(filepath.Join(shards, shardFileName(i))); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{bundle},
		InDirs:        []string{shards},
		OutPath:       out,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, payload)
}

type warnCatch struct {
	t        *testing.T
	buf      bytes.Buffer
	baseline int
	atWarn   int
}

func (w *warnCatch) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("only one recipient")) {
		w.atWarn = len(fakeplugin.Invocations(w.t)) - w.baseline
	}
	return w.buf.Write(p)
}

func fmtSolePluginWarning(rec string) string {
	return "only one recipient (" + rec + "): if that key is lost, reset or replaced by a firmware recall, this payload is gone. `envelope bind -add-recipient` adds a recovery recipient, but only for future splits.\n"
}

func observeSplitSet(t *testing.T) *int {
	t.Helper()
	n := new(int)
	*n = -1
	ObserveSplitInteractions = func(got int) { *n = got }
	t.Cleanup(func() { ObserveSplitInteractions = nil })
	return n
}

func ageStanzaCount(ct []byte) int {
	n := 0
	for _, line := range bytes.Split(ct, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("-> ")) {
			n++
		}
	}
	return n
}

func assertNoPartialIn(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".partial") || strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left %s", e.Name())
		}
	}
}
