package pipeline

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
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
	"unicode/utf8"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestBindCreateNative(t *testing.T) {
	path, rec := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	rep, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       out,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if rep == nil || rep.Path != out || rep.Identities != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.MACKeyID) != hex.EncodedLen(key.MACKeyIDLen) {
		t.Fatalf("MACKeyID len = %d, want %d", len(rep.MACKeyID), hex.EncodedLen(key.MACKeyIDLen))
	}
	if len(rep.Recipients) != 1 || rep.Recipients[0] != rec {
		t.Fatal("recorded recipients")
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", st.Mode().Perm())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(data) {
		t.Fatal("bundle is not valid UTF-8")
	}
	assertNoSeedIn(t, data, path, out)
}

func TestBindCreateExistingOut(t *testing.T) {
	path, rec := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	want := []byte("keep-me\n")
	if err := os.WriteFile(out, want, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       out,
	}, io.Discard)
	if !errors.Is(err, key.ErrIdentityExists) {
		t.Fatalf("errors.Is(., ErrIdentityExists) = false: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestBindCreateNoRecipient(t *testing.T) {
	path, _ := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	_, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		OutPath:       out,
	}, io.Discard)
	if !errors.Is(err, key.ErrBundleNoRecipient) {
		t.Fatalf("errors.Is(., ErrBundleNoRecipient) = false: %v", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrote a bundle with no recipient")
	}
}

func TestBindCreateBadRecipient(t *testing.T) {
	path, _ := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	_, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{"not-a-recipient"},
		OutPath:       out,
	}, io.Discard)
	if !errors.Is(err, ErrBadRecipient) {
		t.Fatalf("errors.Is(., ErrBadRecipient) = false: %v", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrote a bundle for a bad recipient")
	}
}

func TestBindAddRecipientNative(t *testing.T) {
	pathA, recA := mustNativeID(t)
	pathB, recB := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{pathA},
		Recipients:    []string{recA},
		OutPath:       out,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := key.ReadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	wantID := append([]byte(nil), before.MACKeyID...)

	rep, err := Bind(context.Background(), BindOptions{
		Mode:       BindAddRecipient,
		Recipients: []string{recB},
		BundlePath: out,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(mustReadMACKeyID(t, out), wantID) {
		t.Fatal("add-recipient changed mac_key_id")
	}
	if len(rep.Recipients) != 2 || rep.Recipients[0] != recA || rep.Recipients[1] != recB {
		t.Fatal("extended recipient set")
	}
	_ = pathB
}

func TestBindReplaceIdentityNative(t *testing.T) {
	pathA, recA := mustNativeID(t)
	pathB, _ := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{pathA},
		Recipients:    []string{recA},
		OutPath:       out,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := key.ReadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	wantID := append([]byte(nil), before.MACKeyID...)
	wantPin := append([]byte(nil), before.Pin...)
	wantRec := append([]string(nil), before.Recipients...)

	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindReplaceIdentity,
		IdentityPaths: []string{pathB},
		BundlePath:    out,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := key.ReadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(after.MACKeyID, wantID) {
		t.Fatal("replace-identity changed mac_key_id")
	}
	if !bytes.Equal(after.Pin, wantPin) {
		t.Fatal("replace-identity re-encrypted the pin")
	}
	if len(after.Recipients) != len(wantRec) || after.Recipients[0] != wantRec[0] {
		t.Fatal("replace-identity changed recipients")
	}
	bLine, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Identities) != 1 || after.Identities[0] != strings.TrimRight(string(bLine), "\n") {
		t.Fatal("replace-identity did not swap the identity line")
	}
}

func TestBindInteractions(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)

	t.Run("create 0", func(t *testing.T) {
		stub := writePluginStub(t, name, fakeplugin.ModeOK)
		_, rec := mustNativeID(t)
		out := filepath.Join(t.TempDir(), "bundle.txt")
		before := len(fakeplugin.Invocations(t))
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{stub},
			Recipients:    []string{rec},
			OutPath:       out,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
			t.Fatalf("create started %d plugin processes, want 0", n)
		}
		set := mustLoadBundle(t, out, stubTerm{})
		if set.Interactions() != 0 {
			t.Fatalf("Interactions after create load = %d, want 0", set.Interactions())
		}
	})

	t.Run("create 0 any p", func(t *testing.T) {
		stubs := []string{
			writePluginStub(t, name, fakeplugin.ModeOK),
			writePluginStub(t, name, fakeplugin.ModePIN),
		}
		_, rec := mustNativeID(t)
		out := filepath.Join(t.TempDir(), "bundle.txt")
		before := len(fakeplugin.Invocations(t))
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: stubs,
			Recipients:    []string{rec},
			OutPath:       out,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
			t.Fatalf("create p=2 started %d plugin processes, want 0", n)
		}
	})

	t.Run("replace-identity 0", func(t *testing.T) {
		stub := writePluginStub(t, name, fakeplugin.ModeOK)
		_, rec := mustNativeID(t)
		out := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{stub},
			Recipients:    []string{rec},
			OutPath:       out,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		repl := writePluginStub(t, name, fakeplugin.ModePIN)
		before := len(fakeplugin.Invocations(t))
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindReplaceIdentity,
			IdentityPaths: []string{repl},
			BundlePath:    out,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
			t.Fatalf("replace-identity started %d plugin processes, want 0", n)
		}
	})

	t.Run("replace-identity 0 any p", func(t *testing.T) {
		stub := writePluginStub(t, name, fakeplugin.ModeOK)
		_, rec := mustNativeID(t)
		out := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{stub},
			Recipients:    []string{rec},
			OutPath:       out,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		repl := []string{
			writePluginStub(t, name, fakeplugin.ModePIN),
			writePluginStub(t, name, fakeplugin.ModeOK),
		}
		before := len(fakeplugin.Invocations(t))
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindReplaceIdentity,
			IdentityPaths: repl,
			BundlePath:    out,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if n := len(fakeplugin.Invocations(t)) - before; n != 0 {
			t.Fatalf("replace-identity p=2 started %d plugin processes, want 0", n)
		}
	})

	t.Run("add-recipient 1", func(t *testing.T) {
		stub := writePluginStub(t, name, fakeplugin.ModeOK)
		pluginRec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
		out := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{stub},
			Recipients:    []string{pluginRec},
			OutPath:       out,
			Terminal:      stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		_, recB := mustNativeID(t)
		got := observeBindSet(t)
		if _, err := Bind(context.Background(), BindOptions{
			Mode:       BindAddRecipient,
			Recipients: []string{recB},
			BundlePath: out,
			Terminal:   stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if *got != 1 {
			t.Fatalf("add-recipient Interactions = %d, want 1", *got)
		}
	})

	t.Run("add-recipient p=2 first rejected", func(t *testing.T) {
		stubs := []string{
			writePluginStub(t, name, fakeplugin.ModeIncorrectIdentity),
			writePluginStub(t, name, fakeplugin.ModeOK),
		}
		pluginRec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
		out := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: stubs,
			Recipients:    []string{pluginRec},
			OutPath:       out,
			Terminal:      stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		_, recB := mustNativeID(t)
		got := observeBindSet(t)
		if _, err := Bind(context.Background(), BindOptions{
			Mode:       BindAddRecipient,
			Recipients: []string{recB},
			BundlePath: out,
			Terminal:   stubTerm{},
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if *got > 2 || *got < 1 {
			t.Fatalf("add-recipient p=2 Interactions = %d, want 1..2", *got)
		}
	})
}

func TestBindAddRecipientOldSetRestores(t *testing.T) {
	pathA, recA := mustNativeID(t)
	pathB, recB := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{pathA},
		Recipients:    []string{recA},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	beforeID := mustReadMACKeyID(t, bundle)

	in := filepath.Join(t.TempDir(), "in.bin")
	payload := []byte("bind-old-set-payload")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	shards := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: pathA,
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	if _, err := Bind(context.Background(), BindOptions{
		Mode:       BindAddRecipient,
		Recipients: []string{recB},
		BundlePath: bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(mustReadMACKeyID(t, bundle), beforeID) {
		t.Fatal("mac_key_id changed; readable without a card")
	}

	outA := filepath.Join(t.TempDir(), "a.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{pathA},
		InDirs:        []string{shards},
		OutPath:       outA,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outA)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, payload)

	rep, err := Verify(context.Background(), VerifyOptions{
		IdentityPaths: []string{pathA},
		InDirs:        []string{shards},
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if rep == nil || rep.Result != VerifyHealthy {
		t.Fatalf("verify after add-recipient: %+v err=%v", rep, err)
	}

	outB := filepath.Join(t.TempDir(), "b.bin")
	_, err = Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{pathB},
		InDirs:        []string{shards},
		OutPath:       outB,
	}, io.Discard)
	if err == nil {
		t.Fatal("new recipient restored the old set")
	}
	assertNoOutOrPartial(t, outB)
}

func TestBindReplaceIdentityRestores(t *testing.T) {
	pathA, recA := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{pathA},
		Recipients:    []string{recA},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := key.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	in := filepath.Join(t.TempDir(), "in.bin")
	payload := []byte("bind-replace-payload")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	shards := t.TempDir()
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: pathA,
		InPath:       in,
		OutDir:       shards,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	repl := filepath.Join(t.TempDir(), "replacement.txt")
	data, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repl, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindReplaceIdentity,
		IdentityPaths: []string{repl},
		BundlePath:    bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := key.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Pin, before.Pin) {
		t.Fatal("replace-identity re-encrypted the pin")
	}
	if !hmac.Equal(after.MACKeyID, before.MACKeyID) {
		t.Fatal("replace-identity changed mac_key_id")
	}

	out := filepath.Join(t.TempDir(), "out.bin")
	if _, err := Restore(context.Background(), RestoreOptions{
		IdentityPaths: []string{repl},
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

func TestBindAddRecipientUnusablePin(t *testing.T) {
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
	b, err := key.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	b.Pin = append([]byte(nil), b.Pin...)
	b.Pin[0] ^= 0xff
	if err := os.WriteFile(bundle, b.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	_, recB := mustNativeID(t)
	_, err = Bind(context.Background(), BindOptions{
		Mode:       BindAddRecipient,
		Recipients: []string{recB},
		BundlePath: bundle,
	}, io.Discard)
	if !errors.Is(err, key.ErrPinCorrupt) {
		t.Fatalf("errors.Is(., ErrPinCorrupt) = false: %v", err)
	}
	got, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
	if _, err := os.Lstat(bundle + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed add-recipient left a .tmp file")
	}
}

func TestBindReplaceInterrupted(t *testing.T) {
	pathA, recA := mustNativeID(t)
	pathB, _ := mustNativeID(t)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{pathA},
		Recipients:    []string{recA},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected rename failure")
	key.ReplaceRename = func(string, string) error { return injected }
	t.Cleanup(func() { key.ReplaceRename = nil })

	_, err = Bind(context.Background(), BindOptions{
		Mode:          BindReplaceIdentity,
		IdentityPaths: []string{pathB},
		BundlePath:    bundle,
	}, io.Discard)
	if !errors.Is(err, injected) {
		t.Fatalf("errors.Is(., injected) = false: %v", err)
	}
	got, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, orig)
	if _, err := os.Lstat(bundle + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("interrupted replace left a .tmp file")
	}
}

func TestBindReportMACKeyIDNotSeed(t *testing.T) {
	path, rec := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	rep, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       out,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	id, err := key.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	b, err := key.ReadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := id.DecryptBytes(b.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	if hex.EncodeToString(seed) == rep.MACKeyID {
		t.Fatal("MACKeyID is the seed")
	}
	if len(rep.MACKeyID) != 32 {
		t.Fatalf("MACKeyID len = %d, want 32 hex chars", len(rep.MACKeyID))
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, seed) {
		t.Fatal("bundle contains the 32-byte seed")
	}
}

func TestBindModifyDoesNotMintSeed(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	src := filepath.Join(filepath.Dir(file), "bind.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		switch fn.Name.Name {
		case "bindAddRecipient", "bindReplaceIdentity":
		default:
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "NewBundle" {
				t.Errorf("%s calls NewBundle (I-3)", fn.Name.Name)
			}
			id, ok := sel.X.(*ast.Ident)
			if ok && id.Name == "rand" && sel.Sel.Name == "Read" {
				t.Errorf("%s reads rand (I-3)", fn.Name.Name)
			}
			return true
		})
	}
}

func TestBindCanceledContext(t *testing.T) {
	path, rec := mustNativeID(t)
	out := filepath.Join(t.TempDir(), "bundle.txt")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Bind(ctx, BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{path},
		Recipients:    []string{rec},
		OutPath:       out,
	}, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(., context.Canceled) = false: %v", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled bind wrote a bundle")
	}
}

func mustNativeID(t *testing.T) (path, recipient string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "id.txt")
	if _, err := key.Create(path); err != nil {
		t.Fatal(err)
	}
	id, err := key.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	recipient, err = id.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	return path, recipient
}

func writePluginStub(t *testing.T, name string, mode fakeplugin.Mode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stub.txt")
	if err := os.WriteFile(path, []byte(fakeplugin.Identity(name, mode)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustLoadBundle(t *testing.T, path string, term Terminal) *key.Set {
	t.Helper()
	src := terminalSource(term)
	set, err := key.LoadSet([]string{path}, src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	return set
}

func observeBindSet(t *testing.T) *int {
	t.Helper()
	n := new(int)
	*n = -1
	ObserveBindInteractions = func(got int) { *n = got }
	t.Cleanup(func() { ObserveBindInteractions = nil })
	return n
}

func mustReadMACKeyID(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "# envelope-mac-key-id: "
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(prefix)) {
			id, err := hex.DecodeString(string(bytes.TrimSpace(line[len(prefix):])))
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
	}
	t.Fatal("no mac-key-id line")
	return nil
}

func assertNoSeedIn(t *testing.T, data []byte, identityPath, bundlePath string) {
	t.Helper()
	id, err := key.Load(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	b, err := key.ReadBundle(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := id.DecryptBytes(b.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	if bytes.Contains(data, seed) {
		t.Fatal("cleartext 32-byte seed present")
	}
}
