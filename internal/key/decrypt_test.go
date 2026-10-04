package key

import (
	"bytes"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

const decryptPlain = "set-decrypt-fixture"

func TestSetDecryptFatalThenWorkingPlugin(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	for _, modes := range [][]fakeplugin.Mode{
		{fakeplugin.ModeFatal, fakeplugin.ModeOK},
		{fakeplugin.ModeOK, fakeplugin.ModeFatal},
	} {
		set, paths := pluginSet(t, nil, name, modes...)
		before := set.Identities()
		got, err := set.DecryptBytes(ct)
		if err != nil {
			t.Fatalf("order %v: %v", modes, err)
		}
		if !bytes.Equal(got, []byte(uiPlain)) {
			t.Fatal("plaintext mismatch")
		}
		after := set.Identities()
		assertIdentitiesUnchanged(t, before, after)
		if len(paths) != 2 {
			t.Fatal("want two PLUGIN identity files")
		}
		if before[0].Kind() != KindPlugin || before[1].Kind() != KindPlugin {
			t.Fatal("THE test requires two plugin identities, not [fatal, x25519]")
		}
	}
}

func TestSetDecryptJoinedDiagnosisNamesSource(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)
	set, paths := pluginSet(t, nil, name, fakeplugin.ModeFatal, fakeplugin.ModeFatal)
	_, err := set.DecryptBytes(ct)
	if err == nil {
		t.Fatal("want joined failure")
	}
	if !errors.Is(err, ErrPluginFailed) {
		t.Fatalf("errors.Is(., ErrPluginFailed) = false: %v", err)
	}
	msg := err.Error()
	for _, p := range paths {
		if !strings.Contains(msg, p) {
			t.Fatalf("joined diagnosis missing source %q: %q", p, msg)
		}
	}
	if !strings.Contains(msg, "age-plugin-"+name) {
		t.Fatalf("joined diagnosis missing plugin name: %q", msg)
	}
	assertNoQuotedIdentityLine(t, err)
	if strings.Contains(msg, "\n\n") {
		t.Fatalf("joined diagnosis is a wall of text: %q", msg)
	}
}

func TestSetNativeSuccessSkipsPlugin(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	native, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Zero)
	plain := []byte(decryptPlain)
	ct, err := native.EncryptBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	nativePath := writeIdentityFile(t, native.age.String()+"\n")
	pluginPath := writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModePIN)+"\n")
	rec := &uiTerm{replies: []string{fakeplugin.PIN}}
	set, err := LoadSet([]string{pluginPath, nativePath}, rec.source())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	ids := set.Identities()
	if len(ids) != 2 || ids[0].Kind() != KindNative || ids[1].Kind() != KindPlugin {
		t.Fatal("want natives first")
	}
	got, err := set.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, plain)
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0 (plugin not attempted)", set.Interactions())
	}
	rec.mu.Lock()
	left := len(rec.replies)
	rec.mu.Unlock()
	if left != 1 {
		t.Fatal("plugin PIN invoked after native success")
	}
}

func TestSetDecryptPINAfterSuccessNeverInvoked(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)
	rec := &uiTerm{replies: []string{fakeplugin.PIN}}
	set, _ := pluginSet(t, rec.source(), name, fakeplugin.ModeOK, fakeplugin.ModePIN)
	before := set.Identities()
	got, err := set.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(uiPlain)) {
		t.Fatal("plaintext mismatch")
	}
	if set.Interactions() != 1 {
		t.Fatalf("Interactions = %d, want 1 (PIN identity not attempted)", set.Interactions())
	}
	rec.mu.Lock()
	left := len(rec.replies)
	rec.mu.Unlock()
	if left != 1 {
		t.Fatal("ModePIN after success was invoked")
	}
	assertPINNotLeaked(t, rec, err, fakeplugin.PIN)
	assertIdentitiesUnchanged(t, before, set.Identities())
}

func TestSetDecryptI13OneIdentityPerCall(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)
	set, _ := pluginSet(t, nil, name, fakeplugin.ModeFatal, fakeplugin.ModeOK)

	var lens []int
	orig := decryptAge
	WithDecrypt(func(r io.Reader, ids ...age.Identity) (io.Reader, error) {
		lens = append(lens, len(ids))
		return orig(r, ids...)
	})(set)

	if _, err := set.DecryptBytes(ct); err != nil {
		t.Fatal(err)
	}
	if len(lens) < 2 {
		t.Fatalf("Decrypt calls = %d, want ≥ 2", len(lens))
	}
	for i, n := range lens {
		if n != 1 {
			t.Fatalf("age.Decrypt #%d got %d identities, want 1", i, n)
		}
	}
}

func TestI13ProductionDecryptNeverSpreadsIdentities(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	keyRoot := filepath.Join(root, "internal", "key")
	var keyDecrypt int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ageName, ok := ageImportName(f)
		if !ok {
			return nil
		}
		inKey := path == keyRoot || strings.HasPrefix(path, keyRoot+string(filepath.Separator))
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Decrypt" {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != ageName {
				return true
			}
			// Crypt has its own calls. This count is the key package only.
			if inKey {
				keyDecrypt++
			}
			if call.Ellipsis != 0 {
				t.Errorf("%s: age.Decrypt spread", fset.Position(call.Pos()))
			}
			if len(call.Args) != 2 {
				t.Errorf("%s: age.Decrypt has %d args, want reader + one identity",
					fset.Position(call.Pos()), len(call.Args))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if keyDecrypt != 1 {
		t.Fatalf("internal/key age.Decrypt calls = %d, want 1", keyDecrypt)
	}
}

func TestSetInteractionsNativeZero(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	path := writeIdentityFile(t, id.age.String()+"\n")
	set, err := LoadSet([]string{path}, func() (Terminal, error) {
		t.Fatal("native decrypt opened a terminal")
		return nil, ErrNoTerminal
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	plain := []byte(decryptPlain)
	ct, err := id.EncryptBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := set.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, plain)
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0", set.Interactions())
	}

	bundled := &Set{ids: []*Identity{id}, bundle: true, ui: NewClientUI(nil)}
	got, err = bundled.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, plain)
	if bundled.Interactions() != 0 {
		t.Fatalf("bundle-loaded native Interactions = %d, want 0", bundled.Interactions())
	}
}

func TestSetInteractionsTable(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	tests := []struct {
		name  string
		modes []fakeplugin.Mode
		want  int
	}{
		{"n=1 success@0", []fakeplugin.Mode{fakeplugin.ModeOK}, 1},
		{"n=2 success@0", []fakeplugin.Mode{fakeplugin.ModeOK, fakeplugin.ModeFatal}, 1},
		{"n=2 success@1", []fakeplugin.Mode{fakeplugin.ModeFatal, fakeplugin.ModeOK}, 2},
		{"n=3 success@0", []fakeplugin.Mode{fakeplugin.ModeOK, fakeplugin.ModeFatal, fakeplugin.ModePIN}, 1},
		{"n=3 success@1", []fakeplugin.Mode{fakeplugin.ModeFatal, fakeplugin.ModeOK, fakeplugin.ModePIN}, 2},
		{"n=3 success@2", []fakeplugin.Mode{fakeplugin.ModeFatal, fakeplugin.ModeFatal, fakeplugin.ModeOK}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, _ := pluginSet(t, nil, name, tt.modes...)
			got, err := set.DecryptBytes(ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte(uiPlain)) {
				t.Fatal("plaintext mismatch")
			}
			if set.Interactions() != tt.want {
				t.Fatalf("Interactions = %d, want %d", set.Interactions(), tt.want)
			}
		})
	}
}

func TestSetInsertForeverThenOK(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)
	rec := &uiTerm{}
	set, _ := pluginSet(t, rec.source(), name, fakeplugin.ModeInsertForever, fakeplugin.ModeOK)

	got, err := set.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(uiPlain)) {
		t.Fatal("plaintext mismatch")
	}
	joined := set.ids[0].attempt.err
	if !errors.Is(joined, ErrInsertRounds) && !errors.Is(joined, age.ErrIncorrectIdentity) {
		t.Fatalf("first identity diagnosis = %v, want ErrInsertRounds or skip", joined)
	}
	offeredSkip := false
	for _, line := range rec.lines() {
		if strings.Contains(strings.ToLower(line), "skip") {
			offeredSkip = true
			break
		}
	}
	if errors.Is(joined, ErrInsertRounds) {
		if offeredSkip {
			t.Fatal("skip offered on a run that hit the insert cap")
		}
		return
	}
	if !offeredSkip {
		t.Fatal("skip not offered while another identity is untried")
	}
	// Cap isolation: last-identity InsertForever joins ErrInsertRounds.
	last, _ := pluginSet(t, (&uiTerm{}).source(), name, fakeplugin.ModeInsertForever)
	_, capErr := last.DecryptBytes(ct)
	if !errors.Is(capErr, ErrInsertRounds) {
		t.Fatalf("errors.Is(joined, ErrInsertRounds) = false: %v", capErr)
	}
}

func TestSetDecryptToOpenOncePerAttempt(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)
	set, _ := pluginSet(t, nil, name, fakeplugin.ModeFatal, fakeplugin.ModeOK)

	calls := 0
	open := func() io.Reader {
		calls++
		return bytes.NewReader(ct)
	}
	var dst bytes.Buffer
	n, err := set.DecryptTo(&dst, open)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("open calls = %d, want 2", calls)
	}
	if n != int64(len(uiPlain)) {
		t.Fatalf("n = %d, want %d", n, len(uiPlain))
	}
	if !bytes.Equal(dst.Bytes(), []byte(uiPlain)) {
		t.Fatal("plaintext mismatch")
	}
}

func TestSetDecryptToConsumedReaderFailsSecondAttempt(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)
	set, _ := pluginSet(t, nil, name, fakeplugin.ModeFatal, fakeplugin.ModeOK)

	r := bytes.NewReader(ct)
	openSame := func() io.Reader { return r }
	var dst bytes.Buffer
	_, err := set.DecryptTo(&dst, openSame)
	if err == nil {
		t.Fatal("reused consumed reader succeeded; open must return a fresh stream")
	}
	if dst.Len() != 0 {
		t.Fatalf("consumed retry wrote %d bytes, want 0", dst.Len())
	}

	n, err := set.DecryptTo(&dst, func() io.Reader { return bytes.NewReader(ct) })
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(uiPlain)) {
		t.Fatalf("fresh open n = %d, want %d", n, len(uiPlain))
	}
	if !bytes.Equal(dst.Bytes(), []byte(uiPlain)) {
		t.Fatal("plaintext mismatch")
	}
}

type failOnceWriter struct {
	buf    bytes.Buffer
	failed bool
}

func (w *failOnceWriter) Write(p []byte) (int, error) {
	if !w.failed {
		w.failed = true
		n, _ := w.buf.Write(p[:1])
		return n, io.ErrUnexpectedEOF
	}
	return w.buf.Write(p)
}

func TestDecryptToCopyFailureIsNotRetried(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Zero)
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Zero)
	plain := []byte("review-fixture")
	ct, err := crypt.EncryptBytes(plain, a.age.Recipient(), b.age.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	s := &Set{ids: []*Identity{a, b}}
	var dst failOnceWriter
	opens := 0
	n, err := s.DecryptTo(&dst, func() io.Reader {
		opens++
		return bytes.NewReader(ct)
	})
	if err == nil {
		t.Fatalf("write error was swallowed: returned n=%d, stored=%d, expected=%d", n, dst.buf.Len(), len(plain))
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("errors.Is(., io.ErrUnexpectedEOF) = false: %v", err)
	}
	if opens != 1 {
		t.Fatalf("open calls = %d, want 1", opens)
	}
	if n != 1 || dst.buf.Len() != 1 {
		t.Fatalf("n=%d stored=%d, want the single partial write", n, dst.buf.Len())
	}
}

func TestSetDecryptToChunkFailureIsTerminal(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Zero)
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Zero)
	plain := []byte("review-fixture")
	ct, err := crypt.EncryptBytes(plain, a.age.Recipient(), b.age.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	// The tail is the only chunk's Poly1305 tag. A header byte would fail
	// selection and be retried; a tag failure is reported on read, after the
	// header was accepted, and yields no plaintext.
	ct[len(ct)-1] ^= 0x01
	s := &Set{ids: []*Identity{a, b}}
	opens := 0
	var dst bytes.Buffer
	n, err := s.DecryptTo(&dst, func() io.Reader {
		opens++
		return bytes.NewReader(ct)
	})
	if err == nil {
		t.Fatal("err = nil, want chunk authentication error")
	}
	const chunkErr = "failed to decrypt and authenticate payload chunk"
	if strings.Count(err.Error(), chunkErr) != 1 {
		t.Fatalf("chunk error count = %d, want 1: %v", strings.Count(err.Error(), chunkErr), err)
	}
	if opens != 1 {
		t.Fatalf("open calls = %d, want 1", opens)
	}
	if n != 0 || dst.Len() != 0 {
		t.Fatalf("n=%d dst=%d, want 0 and empty", n, dst.Len())
	}
}

// fixedFileKey reports a caller-chosen file key for every stanza, so the
// header MAC fails instead of the identity being skipped as a non-match.
type fixedFileKey struct{ key []byte }

func (f fixedFileKey) Unwrap([]*age.Stanza) ([]byte, error) {
	return f.key, nil
}

func TestSetDecryptToHeaderMACFailureIsRetried(t *testing.T) {
	owner, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Zero)
	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	wrong := &Identity{native: fixedFileKey{key: fileKey}, kind: KindNative}
	plain := []byte("review-fixture")
	ct, err := crypt.EncryptBytes(plain, owner.age.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	s := &Set{ids: []*Identity{wrong, owner}}
	opens := 0
	var dst bytes.Buffer
	n, err := s.DecryptTo(&dst, func() io.Reader {
		opens++
		return bytes.NewReader(ct)
	})
	if err != nil {
		t.Fatal(err)
	}
	if opens != 2 {
		t.Fatalf("open calls = %d, want 2", opens)
	}
	if n != int64(len(plain)) {
		t.Fatalf("n = %d, want %d", n, len(plain))
	}
	assertSameBytes(t, dst.Bytes(), plain)
}

func TestSetDecryptNoTerminalStartsNoPlugin(t *testing.T) {
	skipWindows(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")
	path := writeIdentityFile(t, fakeplugin.Identity("envtest", fakeplugin.ModeOK)+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	_, err = set.DecryptBytes([]byte("age-stub"))
	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("errors.Is(., ErrNoTerminal) = false: %v", err)
	}
	var nf *plugin.NotFoundError
	if errors.As(err, &nf) {
		t.Fatal("plugin process was started")
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0", set.Interactions())
	}
}

func TestSetDecryptMalformedNotPluginFailed(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	set, _ := pluginSet(t, nil, name, fakeplugin.ModeOK)
	_, err := set.DecryptBytes([]byte("this is not age ciphertext"))
	if !errors.Is(err, crypt.ErrMalformedAge) {
		t.Fatalf("errors.Is(., ErrMalformedAge) = false: %v", err)
	}
	if errors.Is(err, ErrPluginFailed) {
		t.Fatal("malformed file classified as plugin failure")
	}
	if set.Interactions() != 0 {
		t.Fatalf("Unwrap ran on a refused file: Interactions = %d", set.Interactions())
	}
}

func TestSetDecryptNativeWrongIdentity(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Zero)
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Zero)
	ct, err := a.EncryptBytes([]byte(decryptPlain))
	if err != nil {
		t.Fatal(err)
	}
	path := writeIdentityFile(t, b.age.String()+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	_, err = set.DecryptBytes(ct)
	if !errors.Is(err, crypt.ErrWrongIdentity) {
		t.Fatalf("errors.Is(., ErrWrongIdentity) = false: %v", err)
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0", set.Interactions())
	}
}

func pluginSet(t *testing.T, term TerminalSource, name string, modes ...fakeplugin.Mode) (*Set, []string) {
	t.Helper()
	if term == nil {
		term = (&uiTerm{}).source()
	}
	paths := make([]string, len(modes))
	for i, m := range modes {
		paths[i] = writeIdentityFile(t, fakeplugin.Identity(name, m)+"\n")
	}
	set, err := LoadSet(paths, term)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	return set, paths
}

func assertIdentitiesUnchanged(t *testing.T, before, after []*Identity) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("Identities len before=%d after=%d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("Identities()[%d] pointer changed", i)
		}
		if before[i].Kind() != after[i].Kind() || before[i].Source() != after[i].Source() {
			t.Fatalf("Identities()[%d] reordered", i)
		}
	}
}

func ageImportName(f *ast.File) (string, bool) {
	for _, im := range f.Imports {
		path := strings.Trim(im.Path.Value, `"`)
		if path != "filippo.io/age" {
			continue
		}
		if im.Name != nil {
			if im.Name.Name == "_" {
				return "", false
			}
			return im.Name.Name, true
		}
		return "age", true
	}
	return "", false
}
