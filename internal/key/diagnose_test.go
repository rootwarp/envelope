package key

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestErrPluginNotInstalled(t *testing.T) {
	skipWindows(t)
	line := fakeplugin.Identity("nosuch", fakeplugin.ModeOK)
	path := writeIdentityFile(t, line+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		assertNoQuotedIdentityLine(t, err)
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)

	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")
	ct := nativeCiphertext(t)
	err = usePlugin(t, set.Identities()[0], ct)
	if !errors.Is(err, ErrPluginNotInstalled) {
		t.Fatalf("errors.Is(., ErrPluginNotInstalled) = false: %v", err)
	}
	assertPluginSentinelExclusive(t, err, ErrPluginNotInstalled)
	msg := err.Error()
	if !strings.Contains(msg, "age-plugin-nosuch") {
		t.Fatalf("missing binary name: %q", msg)
	}
	if !strings.Contains(msg, "Homebrew") && !strings.Contains(msg, "cargo install") && !strings.Contains(msg, "Nix") {
		t.Fatalf("missing install channel: %q", msg)
	}
	assertNoQuotedIdentityLine(t, err)
}

func TestErrPluginFailed(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			fakeplugin.Install(t, name)
			path := writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModeFatal)+"\n")
			set, err := LoadSet([]string{path}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Zero)
			ct := encryptPlugin(t, name, fakeplugin.ModeOK)
			err = usePlugin(t, set.Identities()[0], ct)
			if !errors.Is(err, ErrPluginFailed) {
				t.Fatalf("errors.Is(., ErrPluginFailed) = false: %v", err)
			}
			assertPluginSentinelExclusive(t, err, ErrPluginFailed)
			assertNoQuotedIdentityLine(t, err)
			if strings.Contains(err.Error(), "\n") {
				t.Fatalf("plugin error was not collapsed to one line: %q", err.Error())
			}
		})
	}
}

func TestErrPluginProtocol(t *testing.T) {
	skipWindows(t)
	fakeplugin.Install(t, "envgarbage")
	path := writeIdentityFile(t, fakeplugin.Identity("envgarbage", fakeplugin.ModeOK)+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	ct := nativeCiphertext(t)
	err = usePlugin(t, set.Identities()[0], ct)
	if !errors.Is(err, ErrPluginProtocol) {
		t.Fatalf("errors.Is(., ErrPluginProtocol) = false: %v", err)
	}
	assertPluginSentinelExclusive(t, err, ErrPluginProtocol)
	assertNoQuotedIdentityLine(t, err)
	if strings.Contains(err.Error(), "exec:") {
		t.Fatalf("raw exec text: %q", err.Error())
	}
}

func TestErrIncorrectIdentityNoEnvelopeSentinel(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			fakeplugin.Install(t, name)
			path := writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModeIncorrectIdentity)+"\n")
			set, err := LoadSet([]string{path}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Zero)
			ct := encryptPlugin(t, name, fakeplugin.ModeOK)
			err = usePlugin(t, set.Identities()[0], ct)
			if !errors.Is(err, age.ErrIncorrectIdentity) {
				t.Fatalf("errors.Is(., ErrIncorrectIdentity) = false: %v", err)
			}
			for _, s := range []error{ErrPluginNotInstalled, ErrPluginFailed, ErrPluginProtocol, ErrNoScalar, ErrNoLocalRecipient} {
				if errors.Is(err, s) {
					t.Fatalf("no-stanza-match wrapped %v", s)
				}
			}
			assertNoQuotedIdentityLine(t, err)
		})
	}
}

func TestErrNoScalar(t *testing.T) {
	skipWindows(t)
	path := writeIdentityFile(t, fakeplugin.Identity("envtest", fakeplugin.ModeOK)+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	_, err = set.Identities()[0].ManifestMACKey()
	if !errors.Is(err, ErrNoScalar) {
		t.Fatalf("errors.Is(., ErrNoScalar) = false: %v", err)
	}
	assertPluginSentinelExclusive(t, err, ErrNoScalar)
	assertNoQuotedIdentityLine(t, err)
}

func TestErrNoLocalRecipient(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			path := writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModeOK)+"\n")
			set, err := LoadSet([]string{path}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Zero)
			s, err := set.Identities()[0].RecipientString()
			if !errors.Is(err, ErrNoLocalRecipient) {
				t.Fatalf("errors.Is(., ErrNoLocalRecipient) = false: %v", err)
			}
			if s != "" {
				t.Fatalf("RecipientString = %q, want empty", s)
			}
			if s == "<identity-based recipient>" {
				t.Fatal("RecipientString returned <identity-based recipient>")
			}
			assertPluginSentinelExclusive(t, err, ErrNoLocalRecipient)
			assertNoQuotedIdentityLine(t, err)
		})
	}
}

func TestRecipientStringPluginNeverIdentityBased(t *testing.T) {
	skipWindows(t)
	path := writeIdentityFile(t, fakeplugin.Identity("envtest", fakeplugin.ModeOK)+"\n")
	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	s, err := set.Identities()[0].RecipientString()
	if err == nil {
		t.Fatalf("RecipientString = %q, want error", s)
	}
	if strings.Contains(s, "identity-based recipient") {
		t.Fatalf("RecipientString leaked plugin.Identity.Recipient: %q", s)
	}
}

func TestOneLinePluginDebugFooter(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			fakeplugin.Install(t, name)
			rec := &uiTerm{}
			path := writeIdentityFile(t, fakeplugin.Identity(name, fakeplugin.ModeDebugFooter)+"\n")
			set, err := LoadSet([]string{path}, rec.source())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Zero)
			ct := encryptPlugin(t, name, fakeplugin.ModeOK)
			err = usePlugin(t, set.Identities()[0], ct)
			if !errors.Is(err, ErrPluginFailed) {
				t.Fatalf("errors.Is(., ErrPluginFailed) = false: %v", err)
			}
			msg := err.Error()
			if strings.Contains(msg, "\n") {
				t.Fatalf("multi-line plugin error was not one line: %q", msg)
			}
			if strings.Contains(msg, "https://") || strings.Contains(msg, "example.invalid") {
				t.Fatalf("URL footer survived oneLine: %q", msg)
			}
			if strings.Contains(msg, fakeplugin.DebugSecret) {
				t.Fatalf("secret-looking body in error: %q", msg)
			}
			if strings.Contains(rec.captured(), fakeplugin.DebugSecret) {
				t.Fatal("secret-looking body reached the terminal")
			}
			for _, line := range rec.lines() {
				if strings.Contains(line, fakeplugin.DebugSecret) {
					t.Fatal("secret-looking body reached a Notify line")
				}
			}
			assertNoQuotedIdentityLine(t, err)
		})
	}
}

func TestOneLineUnit(t *testing.T) {
	in := "incorrect PIN for this identity\n\n[please report this bug at https://example.invalid/issues]\n" + fakeplugin.DebugSecret
	got := oneLine(in)
	if strings.Contains(got, "\n") {
		t.Fatalf("oneLine still multi-line: %q", got)
	}
	if strings.Contains(got, "https://") {
		t.Fatalf("oneLine kept the URL: %q", got)
	}
	if strings.Contains(got, fakeplugin.DebugSecret) {
		t.Fatalf("oneLine kept the secret: %q", got)
	}
	if got != "incorrect PIN for this identity" {
		t.Fatalf("oneLine = %q", got)
	}
	long := strings.Repeat("a", oneLineMax+20)
	if len(oneLine(long)) != oneLineMax {
		t.Fatalf("oneLine cap = %d, want %d", len(oneLine(long)), oneLineMax)
	}
}

func TestDiagnoseMatrixNoQuotedIdentity(t *testing.T) {
	skipWindows(t)
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	_, err := LoadSet([]string{writeIdentityFile(t, PluginPrefix+"ENVTEST-1\n")}, nil)
	collect(err)
	_, err = LoadSet([]string{writeIdentityFile(t, "# envelope-bundle: v1\n")}, nil)
	collect(err)

	native := nativeLine(t)
	pluginLine := fakeplugin.Identity("envtest", fakeplugin.ModeOK)
	set, err := LoadSet([]string{writeIdentityFile(t, pluginLine+"\n"+native+"\n")}, nil)
	collect(err)
	if err == nil {
		t.Cleanup(set.Zero)
		_, err = set.Identities()[1].RecipientString()
		collect(err)
		_, err = set.Identities()[1].ManifestMACKey()
		collect(err)
	}

	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")
	nosuch, err := LoadSet([]string{writeIdentityFile(t, fakeplugin.Identity("nosuch", fakeplugin.ModeOK)+"\n")}, nil)
	collect(err)
	if err == nil {
		t.Cleanup(nosuch.Zero)
		collect(usePlugin(t, nosuch.Identities()[0], nativeCiphertext(t)))
	}

	for _, err := range errs {
		assertNoQuotedIdentityLine(t, err)
	}
}

func usePlugin(t *testing.T, id *Identity, ct []byte) error {
	t.Helper()
	if id.plugin == nil {
		t.Fatal("usePlugin: no plugin identity")
	}
	_, err := age.Decrypt(bytes.NewReader(ct), id.plugin)
	return diagnose(id, err)
}

func nativeCiphertext(t *testing.T) []byte {
	t.Helper()
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	ct, err := id.EncryptBytes([]byte("diagnose-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func assertPluginSentinelExclusive(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("errors.Is(., %v) = false: %v", want, err)
	}
	for _, other := range []error{
		ErrPluginNotInstalled, ErrPluginFailed, ErrPluginProtocol,
		ErrNoScalar, ErrNoLocalRecipient, age.ErrIncorrectIdentity,
		ErrInvalidIdentity, ErrNotSingleIdentity, exec.ErrNotFound,
	} {
		if other != want && errors.Is(err, other) {
			t.Fatalf("error also matched %v", other)
		}
	}
}
