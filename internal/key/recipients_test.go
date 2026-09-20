package key

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestNewRecipientSetRecordsString(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)

	rs, err := NewRecipientSet(id)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Len() != 1 {
		t.Fatalf("Len = %d, want 1", rs.Len())
	}
	if name, ok := rs.SolePlugin(); ok || name != "" {
		t.Fatalf("SolePlugin = (%q, %v), want native", name, ok)
	}
	want, err := id.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	got := rs.Strings()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Strings = %d entries, want the identity recipient", len(got))
	}
	got[0] = "mutated"
	if rs.Strings()[0] == "mutated" {
		t.Fatal("Strings aliases the internal slice")
	}

	plain := []byte("recipient-set")
	ct, err := rs.EncryptBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := id.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)
}

func TestParseNativeRecipientsTwoEitherDecrypts(t *testing.T) {
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

	sa, err := a.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ParseNativeRecipients([]string{sa, sb, sa})
	if err != nil {
		t.Fatal(err)
	}
	if rs.Len() != 2 {
		t.Fatalf("Len = %d, want 2 after dedup", rs.Len())
	}
	got := rs.Strings()
	if got[0] != sa || got[1] != sb {
		t.Fatal("Strings reordered or dropped a native recipient")
	}

	plain := []byte("two-native")
	var ct bytes.Buffer
	if _, err := rs.Encrypt(&ct, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}

	out, err := a.DecryptBytes(ct.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)
	out, err = b.DecryptBytes(ct.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)

	other, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Zero)
	if _, err := other.DecryptBytes(ct.Bytes()); !errors.Is(err, crypt.ErrWrongIdentity) {
		t.Fatalf("third identity: errors.Is(., ErrWrongIdentity) = false")
	}
}

func TestParseRecipientsHRP(t *testing.T) {
	x, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.Zero)
	xs, err := x.RecipientString()
	if err != nil {
		t.Fatal(err)
	}

	h, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hs := h.Recipient().String()
	if !strings.HasPrefix(hs, "age1pq1") {
		t.Fatalf("hybrid recipient HRP is not age1pq")
	}

	name := "envtest"
	ps := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	if ps == "" {
		t.Fatal("plugin recipient encoding is empty")
	}

	ui := NewClientUI(nil)
	plain := []byte("hrp-table")

	t.Run("x25519", func(t *testing.T) {
		rs := mustParseRecipients(t, ui, xs)
		if _, ok := rs.rs[0].(*age.X25519Recipient); !ok {
			t.Fatalf("age1… classified as %T, want native X25519", rs.rs[0])
		}
		if _, ok := rs.SolePlugin(); ok {
			t.Fatal("X25519 SolePlugin")
		}
		if len(rs.plugins) != 0 {
			t.Fatalf("X25519 plugins = %q", rs.plugins)
		}
		ct, err := rs.EncryptBytes(plain)
		if err != nil {
			t.Fatal(err)
		}
		out, err := x.DecryptBytes(ct)
		if err != nil {
			t.Fatal(err)
		}
		assertSameBytes(t, out, plain)
	})

	t.Run("hybrid", func(t *testing.T) {
		rs := mustParseRecipients(t, ui, hs)
		if _, ok := rs.rs[0].(*age.HybridRecipient); !ok {
			t.Fatalf("age1pq classified as %T, want native hybrid not plugin pq", rs.rs[0])
		}
		if _, ok := rs.rs[0].(*plugin.Recipient); ok {
			t.Fatal("age1pq classified as plugin pq")
		}
		if name, ok := rs.SolePlugin(); ok || name == "pq" {
			t.Fatalf("hybrid SolePlugin = (%q, %v)", name, ok)
		}
		if len(rs.plugins) != 0 {
			t.Fatalf("hybrid classified as plugin %q", rs.plugins)
		}
		ct, err := rs.EncryptBytes(plain)
		if err != nil {
			t.Fatal(err)
		}
		r, err := age.Decrypt(bytes.NewReader(ct), h)
		if err != nil {
			t.Fatal(err)
		}
		out := readAll(t, r)
		assertSameBytes(t, out, plain)
	})

	t.Run("plugin", func(t *testing.T) {
		rs := mustParseRecipients(t, ui, ps)
		pr, ok := rs.rs[0].(*plugin.Recipient)
		if !ok {
			t.Fatalf("age1<name> classified as %T, want plugin", rs.rs[0])
		}
		if pr.Name() != name {
			t.Fatalf("plugin name = %q, want %q", pr.Name(), name)
		}
		got, ok := rs.SolePlugin()
		if !ok || got != name {
			t.Fatalf("SolePlugin = (%q, %v), want (%q, true)", got, ok, name)
		}
	})
}

func TestParseRecipientsDuplicateOneStanza(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	s, err := id.RecipientString()
	if err != nil {
		t.Fatal(err)
	}

	rs := mustParseRecipients(t, nil, s, s, " "+s+" ")
	if rs.Len() != 1 {
		t.Fatalf("Len = %d, want 1 after string dedup", rs.Len())
	}
	if rs.Strings()[0] != s {
		t.Fatal("recorded string is not the trimmed recipient")
	}

	ct, err := rs.EncryptBytes([]byte("dup-stanza"))
	if err != nil {
		t.Fatal(err)
	}
	n := stanzaCount(ct)
	if n != 1 {
		t.Fatalf("age header stanzas = %d, want 1", n)
	}
	out, err := id.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, []byte("dup-stanza"))
}

func TestParseRecipientsMixedSet(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)

	native, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Zero)
	ns, err := native.RecipientString()
	if err != nil {
		t.Fatal(err)
	}

	ui := NewClientUI(nil)
	ps := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	rs := mustParseRecipients(t, ui, ps, ns)
	if rs.Len() != 2 {
		t.Fatalf("Len = %d, want 2", rs.Len())
	}
	if _, ok := rs.SolePlugin(); ok {
		t.Fatal("mixed set is SolePlugin")
	}

	plain := []byte("mixed-set")
	ct, err := rs.EncryptBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := native.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)
	out, err = decryptPlugin(t, ui, name, fakeplugin.ModeOK, ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)

	labeled := fakeplugin.Recipient(name, fakeplugin.ModeLabels)
	lrs := mustParseRecipients(t, ui, labeled, ns)
	if _, err := lrs.EncryptBytes(plain); err == nil {
		t.Fatal("ModeLabels mixed with native: want incompatible recipients")
	} else if !strings.Contains(err.Error(), "incompatible") && !strings.Contains(err.Error(), "can't be mixed") {
		t.Fatalf("want a label-mix error, got %v", err)
	}
}

func TestParseRecipientsBad(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	s, err := id.RecipientString()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{name: "path", in: "identity.txt"},
		{name: "passphrase", in: "correct horse battery staple"},
		{name: "empty", in: ""},
		{name: "age1", in: "age1"},
		{name: "uppercase", in: strings.ToUpper(s)},
		{name: "embedded-whitespace", in: s[:len(s)/2] + " " + s[len(s)/2:]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRecipients([]string{tc.in}, NewClientUI(nil))
			if !errors.Is(err, ErrBadRecipient) {
				t.Fatalf("errors.Is(., ErrBadRecipient) = false: %v", err)
			}
			q := strconv.Quote(strings.TrimSpace(tc.in))
			if !strings.Contains(err.Error(), q) {
				t.Fatalf("error %q does not quote %s", err.Error(), q)
			}
		})
	}
}

func TestSolePlugin(t *testing.T) {
	native, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Zero)
	ns, err := native.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	name := "envtest"
	p1 := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	p2 := fakeplugin.Recipient(name, fakeplugin.ModePIN)
	ui := NewClientUI(nil)

	if got, ok := mustParseRecipients(t, ui, p1).SolePlugin(); !ok || got != name {
		t.Fatalf("one plugin: SolePlugin = (%q, %v)", got, ok)
	}
	if _, ok := mustParseRecipients(t, ui, p1, p2).SolePlugin(); ok {
		t.Fatal("(plugin, plugin) is SolePlugin")
	}
	if _, ok := mustParseRecipients(t, ui, p1, ns).SolePlugin(); ok {
		t.Fatal("(plugin, native) is SolePlugin")
	}
	if _, ok := mustParseRecipients(t, nil, ns).SolePlugin(); ok {
		t.Fatal("(native) is SolePlugin")
	}
}

func TestPluginIdentityRecipientAbsent(t *testing.T) {
	root := moduleRoot(t)
	needle := "plugin" + ".Identity" + ".Recipient()"
	cmd := exec.Command("git", "grep", "-nF", needle)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("I-10: %s appears in the tree:\n%s", needle, string(out))
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || len(bytes.TrimSpace(out)) != 0 {
		t.Fatalf("git grep %s: %v\n%s", needle, err, out)
	}

	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		pkgName, ok := pluginImportName(f)
		if !ok {
			return nil
		}
		returning := funcsReturningPluginIdentity(f, pkgName)
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			scope := pluginIDScope{
				pkg:       pkgName,
				names:     pluginIdentityNamesIn(fn, pkgName, returning),
				returning: returning,
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Recipient" {
					return true
				}
				if pluginIdentityReceiver(sel.X, scope) {
					t.Errorf("%s: plugin identity .Recipient() (I-10)", fset.Position(call.Pos()))
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoStanzaLenEqualsRecipientLen(t *testing.T) {
	root := moduleRoot(t)
	needles := []string{
		"len(" + "stanzas) == len(" + "recipients)",
		"len(" + "recipients) == len(" + "stanzas)",
		"len(" + "stanzas)==len(" + "recipients)",
		"len(" + "recipients)==len(" + "stanzas)",
	}
	for _, needle := range needles {
		cmd := exec.Command("git", "grep", "-nF", needle)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("tree assumes %s:\n%s", needle, out)
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 || len(bytes.TrimSpace(out)) != 0 {
			t.Fatalf("git grep %s: %v\n%s", needle, err, out)
		}
	}
}

func mustParseRecipients(t *testing.T, ui *ClientUI, strs ...string) *RecipientSet {
	t.Helper()
	rs, err := ParseRecipients(strs, ui)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func stanzaCount(ct []byte) int {
	n := 0
	for _, line := range bytes.Split(ct, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("-> ")) {
			n++
		}
	}
	return n
}

func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func pluginImportName(f *ast.File) (string, bool) {
	for _, im := range f.Imports {
		path, err := strconv.Unquote(im.Path.Value)
		if err != nil || path != "filippo.io/age/plugin" {
			continue
		}
		if im.Name != nil {
			return im.Name.Name, true
		}
		return "plugin", true
	}
	return "", false
}

func isPluginIdentityType(expr ast.Expr, pkgName string) bool {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return isPluginIdentityType(t.X, pkgName)
	case *ast.SelectorExpr:
		id, ok := t.X.(*ast.Ident)
		return ok && id.Name == pkgName && t.Sel.Name == "Identity"
	}
	return false
}

type pluginIDScope struct {
	pkg       string
	names     map[string]bool
	returning map[string]bool
}

func funcsReturningPluginIdentity(f *ast.File, pkgName string) map[string]bool {
	returning := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Type.Results == nil {
			continue
		}
		for _, field := range fn.Type.Results.List {
			if isPluginIdentityType(field.Type, pkgName) {
				returning[fn.Name.Name] = true
			}
		}
	}
	return returning
}

func pluginIdentityNamesIn(fn *ast.FuncDecl, pkgName string, returning map[string]bool) map[string]bool {
	names := map[string]bool{}
	collectTyped := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			if !isPluginIdentityType(field.Type, pkgName) {
				continue
			}
			for _, name := range field.Names {
				names[name.Name] = true
			}
		}
	}
	collectTyped(fn.Type.Params)
	collectTyped(fn.Type.Results)
	scope := pluginIDScope{pkg: pkgName, returning: returning}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			if isPluginIdentityType(n.Type, pkgName) {
				for _, name := range n.Names {
					names[name.Name] = true
				}
			}
		case *ast.AssignStmt:
			for _, rhs := range n.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok || !isPluginIdentityCall(call, scope) {
					continue
				}
				if len(n.Lhs) > 0 {
					if id, ok := n.Lhs[0].(*ast.Ident); ok {
						names[id.Name] = true
					}
				}
			}
		}
		return true
	})
	return names
}

func isPluginIdentityCall(call *ast.CallExpr, s pluginIDScope) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return s.returning[fun.Name]
	case *ast.SelectorExpr:
		id, ok := fun.X.(*ast.Ident)
		return ok && id.Name == s.pkg && fun.Sel.Name == "NewIdentity"
	}
	return false
}

func pluginIdentityReceiver(x ast.Expr, s pluginIDScope) bool {
	switch x := x.(type) {
	case *ast.Ident:
		return s.names[x.Name]
	case *ast.ParenExpr:
		return pluginIdentityReceiver(x.X, s)
	case *ast.CallExpr:
		return isPluginIdentityCall(x, s)
	}
	return false
}
