package key

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestPinHKDFGoldenVectors(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != seedLen {
		t.Fatalf("seed len = %d, want %d", len(seed), seedLen)
	}
	wantKey, err := hex.DecodeString("f80422dce67f577312578ac3317e5536f0e18dfbd9b89ff9600fee06c9bae78e")
	if err != nil {
		t.Fatal(err)
	}
	wantID, err := hex.DecodeString("cb25eb66eb9478a5ef3ab1af1490b261")
	if err != nil {
		t.Fatal(err)
	}
	if len(wantKey) != MACKeyLen {
		t.Fatalf("mac_key len = %d, want %d", len(wantKey), MACKeyLen)
	}
	if len(wantID) != MACKeyIDLen {
		t.Fatalf("mac_key_id len = %d, want %d", len(wantID), MACKeyIDLen)
	}

	gotKey, err := derivePinMACKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(gotKey)
	gotID, err := derivePinMACKeyID(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(gotID)

	if !hmac.Equal(gotKey, wantKey) {
		t.Errorf("mac_key mismatch: len got=%d want=%d, sha256 got=%x want=%x",
			len(gotKey), len(wantKey), sha256.Sum256(gotKey), sha256.Sum256(wantKey))
	}
	if !hmac.Equal(gotID, wantID) {
		t.Errorf("mac_key_id mismatch: len got=%d want=%d, sha256 got=%x want=%x",
			len(gotID), len(wantID), sha256.Sum256(gotID), sha256.Sum256(wantID))
	}
	if hmac.Equal(gotKey, gotID) {
		t.Fatal("mac_key equals mac_key_id; HKDF info strings must be distinct")
	}
	if hmac.Equal(gotKey[:MACKeyIDLen], gotID) {
		t.Fatal("mac_key prefix equals mac_key_id; HKDF info strings may have collapsed")
	}
}

func TestBundleStructHasNoSeed(t *testing.T) {
	rt := reflect.TypeOf(Bundle{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		if strings.Contains(name, "seed") {
			t.Fatalf("Bundle field %s names the seed", rt.Field(i).Name)
		}
	}
}

func TestNewBundleIsOnlySeedWriter(t *testing.T) {
	typ := reflect.TypeOf(NewBundle)
	bundlePtr := reflect.TypeOf((*Bundle)(nil))
	for i := 0; i < typ.NumIn(); i++ {
		if typ.In(i) == bundlePtr {
			t.Fatal("NewBundle takes *Bundle (I-3)")
		}
	}

	dir := filepath.Dir(testFile(t))
	fset := token.NewFileSet()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range ents {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if fn.Name.Name == "NewBundle" {
				continue
			}
			if !fn.Name.IsExported() && (fn.Recv == nil || !receiverIsBundle(fn)) {
				continue
			}
			if fn.Recv == nil && !fn.Name.IsExported() {
				continue
			}
			if callsRandRead(fn) && receiverIsBundle(fn) {
				t.Errorf("%s: *Bundle method mints a seed (I-3)", fn.Name.Name)
			}
			if fn.Name.IsExported() && fn.Recv == nil && callsRandRead(fn) && takesBundleParam(fn) {
				t.Errorf("%s: exported function takes *Bundle and reads rand (I-3)", fn.Name.Name)
			}
		}
	}
}

func TestWriteNewRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.txt")
	want := make([]byte, 32)
	if _, err := hex.Decode(want, []byte("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatal(err)
	}

	b, _ := mustNativeBundle(t)
	err := WriteNew(path, b)
	if !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("WriteNew existing: errors.Is(., ErrIdentityExists) = false: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestBundleNoCleartextSecret(t *testing.T) {
	b, id := mustNativeBundle(t)
	path := filepath.Join(t.TempDir(), "bundle.txt")
	if err := WriteNew(path, b); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := id.DecryptBytes(b.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	if bytes.Contains(data, seed) {
		t.Fatal("written bundle contains the 32-byte seed")
	}
	re := regexp.MustCompile(`[0-9a-fA-F]{64}`)
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("# envelope-mac-key-id:")) {
			continue
		}
		if re.Find(line) != nil {
			t.Fatalf("64-hex-char run outside mac-key-id: %q", line)
		}
	}
}

func TestBundleIsValidAgeIdentityFile(t *testing.T) {
	b, id := mustNativeBundle(t)
	data := b.Marshal()
	if !utf8.Valid(data) {
		t.Fatal("Marshal is not valid UTF-8")
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}
		if !bytes.Equal(line, []byte(id.age.String())) {
			t.Fatalf("non-# line is not an identity line: %q", line)
		}
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("ParseIdentities count = %d, want 1", len(ids))
	}
}

func TestBundlePluginIdentityRoundTrip(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	line := fakeplugin.Identity(name, fakeplugin.ModeOK)
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	rs, err := NewRecipientSet(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle([]string{line}, rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Identities) != 1 {
		t.Fatalf("Identities = %d, want 1", len(b.Identities))
	}
	pname, data, err := plugin.ParseIdentity(b.Identities[0])
	if err != nil {
		t.Fatal(err)
	}
	if plugin.EncodeIdentity(pname, data) != b.Identities[0] {
		t.Fatal("plugin identity did not round-trip through plugin.ParseIdentity")
	}
}

func TestBundleRoundTripByteIdentical(t *testing.T) {
	b, _ := mustNativeBundle(t)
	path := filepath.Join(t.TempDir(), "bundle.txt")
	if err := WriteNew(path, b); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got.Marshal(), want)
	assertSameBytes(t, got.Marshal(), b.Marshal())
}

func TestBundleRefusalMatrix(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	ident := id.age.String()
	rec, err := id.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	mac := strings.Repeat("a", 32)
	pin := base64.StdEncoding.EncodeToString([]byte("pin-fixture"))
	join := func(lines []string) []byte {
		return []byte(strings.Join(lines, "\n") + "\n")
	}

	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")

	cases := []struct {
		name string
		body []byte
		want error
	}{
		{"missing header", join([]string{fieldPrefix + macKeyIDField + ": " + mac, ident}), ErrBundleVersion},
		{"v2 header", join([]string{"# envelope-bundle: v2", fieldPrefix + macKeyIDField + ": " + mac, ident}), ErrBundleVersion},
		{"two spaces after colon", join([]string{bundleHeader, fieldPrefix + macKeyIDField + ":  " + mac, fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": " + pin, ident}), ErrBundleField},
		{"leading space before hash", join([]string{bundleHeader, " " + fieldPrefix + macKeyIDField + ": " + mac, fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": " + pin, ident}), ErrBundleField},
		{"unknown envelope field", join([]string{bundleHeader, "# envelope-foo: bar", fieldPrefix + macKeyIDField + ": " + mac, fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": " + pin, ident}), ErrBundleField},
		{"missing mac-key-id", join([]string{bundleHeader, fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": " + pin, ident}), ErrBundleField},
		{"30-hex mac-key-id", join([]string{bundleHeader, fieldPrefix + macKeyIDField + ": " + strings.Repeat("a", 30), fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": " + pin, ident}), ErrBundleField},
		{"uppercase-hex mac-key-id", join([]string{bundleHeader, fieldPrefix + macKeyIDField + ": " + strings.Repeat("A", 32), fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": " + pin, ident}), ErrBundleField},
		{"zero recipients", join([]string{bundleHeader, fieldPrefix + macKeyIDField + ": " + mac, fieldPrefix + pinField + ": " + pin, ident}), ErrBundleNoRecipient},
		{"zero identity lines", join([]string{bundleHeader, fieldPrefix + macKeyIDField + ": " + mac, fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": " + pin}), ErrInvalidIdentity},
		{"65 KiB file", bytes.Repeat([]byte("a"), 65<<10), ErrBundleTooLarge},
		{"non-base64 pin", join([]string{bundleHeader, fieldPrefix + macKeyIDField + ": " + mac, fieldPrefix + recipientField + ": " + rec, fieldPrefix + pinField + ": not-base64!!", ident}), ErrBundleField},
	}
	if len(cases) != 12 {
		t.Fatalf("refusal cases = %d, want 12", len(cases))
	}
	dir := t.TempDir()
	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name)
			if err := os.WriteFile(path, tt.body, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ReadBundle(path)
			if !errors.Is(err, tt.want) {
				t.Fatalf("errors.Is(., %v) = false: %v", tt.want, err)
			}
			for j, other := range cases {
				if other.want == tt.want {
					continue
				}
				if errors.Is(err, other.want) {
					t.Fatalf("case %d also matched sentinel of %q", i, cases[j].name)
				}
			}
			assertNoIdentityPrefix(t, err)
			if strings.Contains(strings.ToLower(err.Error()), "yubi"+"key") {
				t.Fatalf("D11: %q", err.Error())
			}
		})
	}
}

func TestNewBundleNoRecipient(t *testing.T) {
	skipWindows(t)
	dir := t.TempDir()
	line := fakeplugin.Identity("envtest", fakeplugin.ModeOK)
	empty, err := ParseRecipients(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle([]string{line}, empty)
	if !errors.Is(err, ErrBundleNoRecipient) {
		t.Fatalf("errors.Is(., ErrBundleNoRecipient) = false: %v", err)
	}
	if b != nil {
		t.Fatal("NewBundle returned a bundle")
	}
	msg := err.Error()
	if !strings.Contains(msg, "listing") {
		t.Fatalf("message does not point at the plugin listing: %q", msg)
	}
	if strings.Contains(strings.ToLower(msg), "yubi"+"key") {
		t.Fatalf("D11: %q", msg)
	}
	if strings.Contains(msg, "--list") {
		t.Fatalf("plugin-specific flag in internal message: %q", msg)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("wrote %d entries, want 0", len(ents))
	}
}

func TestAddRecipientsOneInteraction(t *testing.T) {
	skipWindows(t)
	b, set := mustPluginBundle(t)
	beforeID := append([]byte(nil), b.MACKeyID...)
	if set.Interactions() != 0 {
		t.Fatalf("Interactions before = %d, want 0", set.Interactions())
	}

	native, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Zero)
	ns, err := native.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	extra, err := ParseNativeRecipients([]string{ns})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddRecipients(set, extra); err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(b.MACKeyID, beforeID) {
		t.Fatal("AddRecipients changed MACKeyID")
	}
	if set.Interactions() != 1 {
		t.Fatalf("Interactions = %d, want 1", set.Interactions())
	}
}

func TestAddRecipientsTamperedPin(t *testing.T) {
	skipWindows(t)
	b, set := mustPluginBundle(t)
	if len(b.Pin) == 0 {
		t.Fatal("empty pin")
	}
	b.Pin = append([]byte(nil), b.Pin...)
	b.Pin[0] ^= 0xff
	native, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Zero)
	ns, err := native.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	extra, err := ParseNativeRecipients([]string{ns})
	if err != nil {
		t.Fatal(err)
	}
	err = b.AddRecipients(set, extra)
	if !errors.Is(err, ErrPinCorrupt) {
		t.Fatalf("errors.Is(., ErrPinCorrupt) = false: %v", err)
	}
}

func TestReplaceIdentitiesZeroInteractions(t *testing.T) {
	skipWindows(t)
	b, set := mustPluginBundle(t)
	beforeID := append([]byte(nil), b.MACKeyID...)
	beforePin := append([]byte(nil), b.Pin...)
	replacement := fakeplugin.Identity("envtest", fakeplugin.ModePIN)
	if err := b.ReplaceIdentities([]string{replacement}); err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(b.MACKeyID, beforeID) {
		t.Fatal("ReplaceIdentities changed MACKeyID")
	}
	if !bytes.Equal(b.Pin, beforePin) {
		t.Fatal("ReplaceIdentities changed Pin")
	}
	if len(b.Identities) != 1 || b.Identities[0] != replacement {
		t.Fatal("ReplaceIdentities did not swap the identity line")
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0", set.Interactions())
	}
}

func TestReplaceCrashSafe(t *testing.T) {
	b, _ := mustNativeBundle(t)
	path := filepath.Join(t.TempDir(), "bundle.txt")
	if err := WriteNew(path, b); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	id2, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id2.Zero)
	if err := b.ReplaceIdentities([]string{id2.age.String()}); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected rename failure")
	testReplaceRename = func(string, string) error { return injected }
	t.Cleanup(func() { testReplaceRename = nil })

	err = Replace(path, b)
	if !errors.Is(err, injected) {
		t.Fatalf("errors.Is(., injected) = false: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, orig)
}

func TestPinWrappedToRecordedRecipients(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Zero)
	c, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Zero)
	sa, err := a.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	sc, err := c.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ParseNativeRecipients([]string{sa, sc})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle([]string{a.age.String(), c.age.String()}, rs)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Recipients; len(got) != 2 || got[0] != sa || got[1] != sc {
		t.Fatal("recorded recipients are not the wrap set")
	}

	seedA, err := a.DecryptBytes(b.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seedA)
	seedC, err := c.DecryptBytes(b.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seedC)
	if len(seedA) != seedLen || !hmac.Equal(seedA, seedC) {
		t.Fatal("pin did not unwrap to the same 32-byte seed for each recorded recipient")
	}
	id, err := derivePinMACKeyID(seedA)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(id)
	if !hmac.Equal(id, b.MACKeyID) {
		t.Fatal("unwrapped seed does not re-derive MACKeyID")
	}

	other, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Zero)
	if _, err := other.DecryptBytes(b.Pin); !errors.Is(err, crypt.ErrWrongIdentity) {
		t.Fatalf("unrecorded identity: errors.Is(., ErrWrongIdentity) = false: %v", err)
	}
}

func mustNativeBundle(t *testing.T) (*Bundle, *Identity) {
	t.Helper()
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	rs, err := NewRecipientSet(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle([]string{id.age.String()}, rs)
	if err != nil {
		t.Fatal(err)
	}
	return b, id
}

func mustPluginBundle(t *testing.T) (*Bundle, *Set) {
	t.Helper()
	name := "envtest"
	fakeplugin.Install(t, name)
	ui := NewClientUI(nil)
	rs := mustParseRecipients(t, ui, fakeplugin.Recipient(name, fakeplugin.ModeOK))
	b, err := NewBundle([]string{fakeplugin.Identity(name, fakeplugin.ModeOK)}, rs)
	if err != nil {
		t.Fatal(err)
	}
	set, _ := pluginSet(t, nil, name, fakeplugin.ModeOK)
	return b, set
}

func testFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return file
}

func receiverIsBundle(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	return isBundleType(fn.Recv.List[0].Type)
}

func takesBundleParam(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		if isBundleType(field.Type) {
			return true
		}
	}
	return false
}

func isBundleType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.StarExpr:
		id, ok := t.X.(*ast.Ident)
		return ok && id.Name == "Bundle"
	case *ast.Ident:
		return t.Name == "Bundle"
	}
	return false
}

func callsRandRead(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Read" {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if ok && id.Name == "rand" {
			found = true
		}
		return true
	})
	return found
}
