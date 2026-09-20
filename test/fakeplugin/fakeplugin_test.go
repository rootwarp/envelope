package fakeplugin

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const payload = "fakeplugin-payload"

var pluginNames = []string{"envtest", "envtest2"}

func TestMain(m *testing.M) {
	if Dispatch() {
		return
	}
	os.Exit(m.Run())
}

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows support is TODO")
	}
}

func TestDispatchNoOp(t *testing.T) {
	if Dispatch() {
		t.Fatal("Dispatch returned true for the test binary")
	}
}

func TestFakePINLength(t *testing.T) {
	if len(PIN) < 6 {
		t.Fatalf("PIN is %d bytes; a RequestValue shorter than 6 would spin the real plugin's PIN loop", len(PIN))
	}
}

func TestInstallPATH(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AGEDEBUG", "plugin")
			dir := Install(t, name)
			if !filepath.IsAbs(dir) {
				t.Fatalf("Install returned relative directory %q", dir)
			}
			if got := os.Getenv("PATH"); got != dir {
				t.Fatalf("PATH = %q, want exactly %q", got, dir)
			}
			if got := os.Getenv("AGEDEBUG"); got != "" {
				t.Fatalf("AGEDEBUG = %q, want empty", got)
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			Install(t, name)
			ui := &plugin.ClientUI{}
			ct := encryptNative(t)
			missing := "nosuch"
			id := identity(t, missing, ModeOK, ui)
			_, err := decryptWith(ct, id)
			if err == nil {
				t.Fatal("Decrypt: want *plugin.NotFoundError")
			}
			var nf *plugin.NotFoundError
			if !errors.As(err, &nf) {
				t.Fatalf("want *plugin.NotFoundError, got %T: %v", err, err)
			}
			if nf.Name != missing {
				t.Fatalf("NotFoundError.Name = %q, want %q", nf.Name, missing)
			}
			if !errors.Is(err, exec.ErrNotFound) {
				t.Fatalf("want wrapped exec.ErrNotFound, got %v", err)
			}
		})
	}
}

func TestModes(t *testing.T) {
	skipWindows(t)
	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			Install(t, name)
			t.Run("ok", func(t *testing.T) { testModeOK(t, name) })
			t.Run("incorrect", func(t *testing.T) { testModeIncorrect(t, name) })
			t.Run("fatal", func(t *testing.T) { testModeFatal(t, name) })
			t.Run("pin", func(t *testing.T) { testModePIN(t, name) })
			t.Run("wrongPIN", func(t *testing.T) { testModeWrongPIN(t, name) })
			t.Run("insertForever", func(t *testing.T) { testModeInsertForever(t, name) })
			t.Run("labels", func(t *testing.T) { testModeLabels(t, name) })
		})
	}
}

func testModeOK(t *testing.T, name string) {
	t.Helper()
	ui := &plugin.ClientUI{}
	ct := encryptTo(t, recipient(t, name, ModeOK, ui))
	got, err := decryptWith(ct, identity(t, name, ModeOK, ui))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func testModeIncorrect(t *testing.T, name string) {
	t.Helper()
	ui := &plugin.ClientUI{}
	ct := encryptTo(t, recipient(t, name, ModeOK, ui))
	_, err := decryptWith(ct, identity(t, name, ModeIncorrectIdentity, ui))
	if err == nil {
		t.Fatal("Decrypt: want ErrIncorrectIdentity")
	}
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("want ErrIncorrectIdentity, got %v", err)
	}
}

func testModeFatal(t *testing.T, name string) {
	t.Helper()
	ui := &plugin.ClientUI{}
	ct := encryptTo(t, recipient(t, name, ModeOK, ui))
	_, err := decryptWith(ct, identity(t, name, ModeFatal, ui))
	if err == nil {
		t.Fatal("Decrypt: want a fatal error")
	}
	if errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("want a non-ErrIncorrectIdentity error, got %v", err)
	}
}

func testModePIN(t *testing.T, name string) {
	t.Helper()
	rec := &recordingUI{pin: PIN}
	ct := encryptTo(t, recipient(t, name, ModeOK, rec.ui()))
	got, err := decryptWith(ct, identity(t, name, ModePIN, rec.ui()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if rec.pinAsked != 1 {
		t.Fatalf("RequestValue called %d times, want 1", rec.pinAsked)
	}
	if !rec.lastSecret {
		t.Fatal("RequestValue secret=false, want true")
	}

	wrong := &recordingUI{pin: "000000"}
	_, err = decryptWith(ct, identity(t, name, ModePIN, wrong.ui()))
	if err == nil {
		t.Fatal("Decrypt with the wrong PIN: want error")
	}
	if errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("wrong PIN produced ErrIncorrectIdentity, want fatal: %v", err)
	}
}

func testModeWrongPIN(t *testing.T, name string) {
	t.Helper()
	rec := &recordingUI{pin: PIN}
	ct := encryptTo(t, recipient(t, name, ModeOK, rec.ui()))
	_, err := decryptWith(ct, identity(t, name, ModeWrongPIN, rec.ui()))
	if err == nil {
		t.Fatal("Decrypt: want a fatal wrong-PIN error")
	}
	if errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("want a fatal error, got ErrIncorrectIdentity: %v", err)
	}
	if !strings.Contains(err.Error(), "\n") {
		t.Fatalf("want a multi-line error body, got %q", err.Error())
	}
	if rec.pinAsked != 1 {
		t.Fatalf("RequestValue called %d times, want 1", rec.pinAsked)
	}
}

func testModeInsertForever(t *testing.T, name string) {
	t.Helper()
	rec := &recordingUI{confirmAnswers: []bool{true, true, false}}
	ct := encryptTo(t, recipient(t, name, ModeOK, rec.ui()))
	_, err := decryptWith(ct, identity(t, name, ModeInsertForever, rec.ui()))
	if err == nil {
		t.Fatal("Decrypt: want ErrIncorrectIdentity after Confirm answers no")
	}
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("want ErrIncorrectIdentity (skip), got %v", err)
	}
	if rec.confirms != 3 {
		t.Fatalf("Confirm called %d times, want 3 (loop, not a single prompt)", rec.confirms)
	}
}

func testModeLabels(t *testing.T, name string) {
	t.Helper()
	ui := &plugin.ClientUI{}
	labeled := recipient(t, name, ModeLabels, ui)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = age.Encrypt(io.Discard, labeled, x.Recipient())
	if err == nil {
		t.Fatal("Encrypt mixed labeled+X25519: want incompatible recipients")
	}
	if !strings.Contains(err.Error(), "incompatible") && !strings.Contains(err.Error(), "can't be mixed") {
		t.Fatalf("want a label-mix error, got %v", err)
	}

	ct := encryptTo(t, labeled)
	got, err := decryptWith(ct, identity(t, name, ModeOK, ui))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestInstallCopyFallback(t *testing.T) {
	skipWindows(t)
	old := link
	link = func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EXDEV}
	}
	t.Cleanup(func() { link = old })

	for _, name := range pluginNames {
		t.Run(name, func(t *testing.T) {
			Install(t, name)
			testModeOK(t, name)
		})
	}
}

func TestEnvGarbage(t *testing.T) {
	skipWindows(t)
	Install(t, garbageName)
	ui := &plugin.ClientUI{}

	ct := encryptNative(t)
	_, exitErr := decryptWith(ct, identity(t, garbageName, ModeOK, ui))
	if exitErr == nil {
		t.Fatal("identity-v1: want non-zero-exit error")
	}
	if errors.Is(exitErr, age.ErrIncorrectIdentity) {
		t.Fatalf("identity-v1: got ErrIncorrectIdentity, want a plugin-process error: %v", exitErr)
	}
	var nf *plugin.NotFoundError
	if errors.As(exitErr, &nf) {
		t.Fatalf("identity-v1: got *plugin.NotFoundError: %v", exitErr)
	}

	r := recipient(t, garbageName, ModeOK, ui)
	_, garbageErr := age.Encrypt(io.Discard, r)
	if garbageErr == nil {
		t.Fatal("recipient-v1: want protocol-garbage error")
	}
	if errors.Is(garbageErr, age.ErrIncorrectIdentity) {
		t.Fatalf("recipient-v1: got ErrIncorrectIdentity, want a protocol error: %v", garbageErr)
	}
	if errors.As(garbageErr, &nf) {
		t.Fatalf("recipient-v1: got *plugin.NotFoundError: %v", garbageErr)
	}
	if garbageErr.Error() == exitErr.Error() {
		t.Fatalf("exit and garbage errors are identical: %v", exitErr)
	}
}

func TestChildInheritsReplacedPATH(t *testing.T) {
	skipWindows(t)
	dir := Install(t, "envtest")
	cmd := exec.Command("/bin/sh", "-c", "printf %s \"$PATH\"")
	// nil Env inherits os.Environ, so t.Setenv("PATH") reaches the child
	// (cmd/envelope/streams_test.go, signal_test.go).
	cmd.Env = nil
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != dir {
		t.Fatalf("child PATH = %q, want %q", out, dir)
	}
}

type recordingUI struct {
	pin            string
	pinAsked       int
	lastSecret     bool
	confirmAnswers []bool
	confirms       int
}

func (r *recordingUI) ui() *plugin.ClientUI {
	return &plugin.ClientUI{
		RequestValue: func(name, prompt string, secret bool) (string, error) {
			r.pinAsked++
			r.lastSecret = secret
			return r.pin, nil
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			i := r.confirms
			r.confirms++
			if i < len(r.confirmAnswers) {
				return r.confirmAnswers[i], nil
			}
			return false, nil
		},
	}
}

func identity(t *testing.T, name string, m Mode, ui *plugin.ClientUI) *plugin.Identity {
	t.Helper()
	s := Identity(name, m)
	if s == "" {
		t.Fatal("Identity: empty encoding")
	}
	id, err := plugin.NewIdentity(s, ui)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func recipient(t *testing.T, name string, m Mode, ui *plugin.ClientUI) *plugin.Recipient {
	t.Helper()
	s := Recipient(name, m)
	if s == "" {
		t.Fatal("Recipient: empty encoding")
	}
	r, err := plugin.NewRecipient(s, ui)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func encryptTo(t *testing.T, rs ...age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encryptNative(t *testing.T) []byte {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return encryptTo(t, id.Recipient())
}

func decryptWith(ct []byte, ids ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ct), ids...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
