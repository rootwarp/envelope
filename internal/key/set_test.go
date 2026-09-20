package key

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

var pluginNames = []string{"envtest", "envtest2"}

func TestLoadSetPluginOnly(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			path := writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModeOK)+"\n")
			set, err := LoadSet([]string{path}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Zero)
			ids := set.Identities()
			if len(ids) != 1 {
				t.Fatalf("len = %d, want 1", len(ids))
			}
			id := ids[0]
			if id.Kind() != KindPlugin {
				t.Fatalf("Kind = %v, want KindPlugin", id.Kind())
			}
			if id.PluginName() != name {
				t.Fatalf("PluginName = %q, want %q", id.PluginName(), name)
			}
			if id.Source() != path {
				t.Fatalf("Source = %q, want %q", id.Source(), path)
			}
			if !id.Interactive() || id.HasScalar() {
				t.Fatal("plugin identity: Interactive/HasScalar")
			}
			if !set.Interactive() {
				t.Fatal("Set.Interactive = false")
			}
			if set.HasPin() {
				t.Fatal("HasPin = true")
			}
			if set.BareFileIdentity() {
				t.Fatal("BareFileIdentity = true for a plugin line")
			}
			assertLoadStartsNoPlugin(t, path)
		})
	}
}

func TestLoadSetMixedNativeAndPlugin(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			native := nativeLine(t)
			pluginLine := fakeplugin.Identity(name, fakeplugin.ModeOK)
			path := writeIdentityFile(t, pluginLine+"\n"+native+"\n")
			set, err := LoadSet([]string{path}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Zero)
			ids := set.Identities()
			if len(ids) != 2 {
				t.Fatalf("len = %d, want 2 (the case Load rejects)", len(ids))
			}
			if ids[0].Kind() != KindNative || !ids[0].HasScalar() {
				t.Fatal("first identity is not native")
			}
			if ids[1].Kind() != KindPlugin || ids[1].PluginName() != name {
				t.Fatal("second identity is not the plugin")
			}
			if set.BareFileIdentity() {
				t.Fatal("BareFileIdentity = true for mixed file")
			}
			assertNoQuotedIdentityLine(t, nil)
		})
	}
}

func TestLoadSetCommentCoexists(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			native := nativeLine(t)
			body := "# operator comment\n\n" + native + "\n" + fakeplugin.Identity(name, fakeplugin.ModeOK) + "\n"
			path := writeIdentityFile(t, body)
			set, err := LoadSet([]string{path}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Zero)
			if len(set.Identities()) != 2 {
				t.Fatalf("len = %d, want 2", len(set.Identities()))
			}
		})
	}
}

func TestLoadSetNOSUCHLoads(t *testing.T) {
	skipWindows(t)
	line := fakeplugin.Identity("nosuch", fakeplugin.ModeOK)
	path := writeIdentityFile(t, line+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		assertNoQuotedIdentityLine(t, err)
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	if len(set.Identities()) != 1 || set.Identities()[0].Kind() != KindPlugin {
		t.Fatal("NOSUCH line did not load as a plugin identity")
	}
}

func TestLoadSetMalformedNoQuotedLine(t *testing.T) {
	skipWindows(t)
	cases := []struct {
		name string
		body string
	}{
		{"truncated plugin", PluginPrefix + "ENVTEST-1\n"},
		{"garbage remainder", fakeplugin.Identity("envtest", fakeplugin.ModeOK) + "\nnot-an-identity\n"},
		{"lowercase plugin prefix", "age-plugin-envtest-1qq\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := writeIdentityFile(t, tt.body)
			_, err := LoadSet([]string{path}, nil)
			if err == nil {
				t.Fatal("LoadSet: want error")
			}
			if !errors.Is(err, ErrInvalidIdentity) && !errors.Is(err, ErrNotSingleIdentity) {
				t.Fatalf("err = %v, want ErrInvalidIdentity or ErrNotSingleIdentity", err)
			}
			assertNoQuotedIdentityLine(t, err)
			if strings.Contains(err.Error(), tt.body) || strings.Contains(err.Error(), strings.TrimSpace(tt.body)) {
				t.Fatalf("error quotes the identity line: %q", err.Error())
			}
		})
	}
}

func TestLoadSetBundleUnsupported(t *testing.T) {
	skipWindows(t)
	body := "# envelope-bundle: v1\n" + fakeplugin.Identity("envtest", fakeplugin.ModeOK) + "\n"
	path := writeIdentityFile(t, body)
	_, err := LoadSet([]string{path}, nil)
	if !errors.Is(err, errBundleUnsupported) {
		t.Fatalf("errors.Is(., errBundleUnsupported) = false: %v", err)
	}
	assertNoQuotedIdentityLine(t, err)
}

func TestBareFileIdentity(t *testing.T) {
	skipWindows(t)
	native := nativeLine(t)
	one := writeIdentityFile(t, native+"\n")
	set, err := LoadSet([]string{one}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	if !set.BareFileIdentity() {
		t.Fatal("one native path: BareFileIdentity = false")
	}

	two := writeIdentityFile(t, native+"\n")
	set2, err := LoadSet([]string{one, two}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set2.Zero)
	if set2.BareFileIdentity() {
		t.Fatal("two paths: BareFileIdentity = true")
	}

	pluginPath := writeIdentityFile(t, fakeplugin.Identity("envtest", fakeplugin.ModeOK)+"\n")
	setP, err := LoadSet([]string{pluginPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(setP.Zero)
	if setP.BareFileIdentity() {
		t.Fatal("plugin line: BareFileIdentity = true")
	}

	mixed := writeIdentityFile(t, native+"\n"+nativeLine(t)+"\n")
	setM, err := LoadSet([]string{mixed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(setM.Zero)
	if setM.BareFileIdentity() {
		t.Fatal("two natives in one file: BareFileIdentity = true")
	}

	bundled := &Set{
		nPaths: 1,
		bundle: true,
		ids:    set.Identities(),
	}
	if bundled.BareFileIdentity() {
		t.Fatal("bundle metadata: BareFileIdentity = true")
	}
}

func TestLoadSetNativesFirst(t *testing.T) {
	skipWindows(t)
	pluginPath := writeIdentityFile(t, fakeplugin.Identity("envtest", fakeplugin.ModeOK)+"\n")
	nativePath := writeIdentityFile(t, nativeLine(t)+"\n")
	set, err := LoadSet([]string{pluginPath, nativePath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	ids := set.Identities()
	if len(ids) != 2 {
		t.Fatalf("len = %d, want 2", len(ids))
	}
	if ids[0].Kind() != KindNative {
		t.Fatal("natives are not first")
	}
	if ids[1].Kind() != KindPlugin {
		t.Fatal("plugins are not second")
	}
}

func TestLoadSetCommentOnly(t *testing.T) {
	path := writeIdentityFile(t, "# comment only\n\n")
	_, err := LoadSet([]string{path}, nil)
	if !errors.Is(err, ErrNotSingleIdentity) {
		t.Fatalf("errors.Is(., ErrNotSingleIdentity) = false: %v", err)
	}
	assertNoQuotedIdentityLine(t, err)
}

func TestLoadSetHybridNoZeroMAC(t *testing.T) {
	h, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := writeIdentityFile(t, h.String()+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	ids := set.Identities()
	if len(ids) != 1 {
		t.Fatalf("len = %d, want 1", len(ids))
	}
	id := ids[0]
	if id.Kind() != KindNative {
		t.Fatalf("Kind = %v, want KindNative", id.Kind())
	}
	if id.HasScalar() {
		t.Fatal("hybrid HasScalar = true")
	}
	if set.BareFileIdentity() {
		t.Fatal("hybrid BareFileIdentity = true")
	}
	mac, err := id.ManifestMACKey()
	if !errors.Is(err, ErrNoScalar) {
		t.Fatalf("ManifestMACKey: errors.Is(., ErrNoScalar) = false: %v", err)
	}
	if mac != nil {
		t.Fatal("ManifestMACKey returned a key for a hybrid identity")
	}
	s, err := id.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	want := h.Recipient().String()
	if s != want {
		t.Fatal("RecipientString did not match the hybrid recipient")
	}
}

func TestRecipientStringMissingNative(t *testing.T) {
	id := &Identity{kind: KindNative}
	s, err := id.RecipientString()
	if !errors.Is(err, errNoNativeRecipient) {
		t.Fatalf("errors.Is(., errNoNativeRecipient) = false: %v", err)
	}
	if s != "" {
		t.Fatalf("RecipientString = %q, want empty", s)
	}
}

func assertLoadStartsNoPlugin(t *testing.T, path string) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
}

func nativeLine(t *testing.T) string {
	t.Helper()
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	return id.age.String()
}

func writeIdentityFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertNoQuotedIdentityLine(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	prefix := "AGE-SECRET-KEY-" + "1"
	if strings.Contains(msg, prefix) || strings.Contains(msg, strings.ToLower(prefix)) {
		t.Fatal("error string contains identity prefix")
	}
	if strings.Contains(msg, PluginPrefix) {
		t.Fatalf("error string contains a plugin identity prefix: %q", msg)
	}
	if strings.Contains(msg, "exec:") || strings.Contains(msg, "executable file not found") {
		t.Fatalf("error string contains raw exec text: %q", msg)
	}
	if strings.Count(msg, "\"") >= 2 && (strings.Contains(msg, "AGE-") || strings.Contains(msg, "age1")) {
		t.Fatalf("error string looks like a quoted identity line: %q", msg)
	}
}
