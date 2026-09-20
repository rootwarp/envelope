package key

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

const uiPlain = "client-ui-fixture"

func TestNewClientUIAssignsCallbacks(t *testing.T) {
	srcs := []TerminalSource{
		nil,
		func() (Terminal, error) { return &uiTerm{}, nil },
		func() (Terminal, error) { panic("TerminalSource invoked") },
	}
	for _, src := range srcs {
		ui := NewClientUI(src)
		if ui == nil {
			t.Fatal("NewClientUI returned nil")
		}
		if ui.DisplayMessage == nil || ui.RequestValue == nil || ui.Confirm == nil || ui.WaitTimer == nil {
			t.Fatal("NewClientUI left a callback nil")
		}
	}

	var z ClientUI
	if z.DisplayMessage != nil || z.RequestValue != nil || z.Confirm != nil || z.WaitTimer != nil {
		t.Fatal("zero-value ClientUI has callbacks")
	}
}

func TestZeroClientUIUnusable(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	var z ClientUI
	id, err := plugin.NewIdentity(fakeplugin.Identity(name, fakeplugin.ModeInsertForever), &z.ClientUI)
	if err != nil {
		t.Fatal(err)
	}
	_, err = decryptWith(ct, id)
	if err == nil {
		t.Fatal("zero-value ClientUI decrypted")
	}
	if errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatal("zero-value Confirm is nil; client answers fail, want a fatal error")
	}
}

func TestClientUIPIN(t *testing.T) {
	skipWindows(t)
	if len(fakeplugin.PIN) < 6 {
		t.Fatalf("PIN is %d bytes; a RequestValue shorter than 6 would spin the real plugin's PIN loop", len(fakeplugin.PIN))
	}
	name := "envtest"
	fakeplugin.Install(t, name)
	rec := &uiTerm{replies: []string{fakeplugin.PIN}}
	ui := NewClientUI(rec.source())
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	var got []byte
	err := runAttempt(ui, name, "id", false, func() error {
		var err error
		got, err = decryptPlugin(t, ui, name, fakeplugin.ModePIN, ct)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(uiPlain)) {
		t.Fatal("plaintext mismatch")
	}
	assertPINNotLeaked(t, rec, err, fakeplugin.PIN)
}

func TestClientUIInsertForever(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	rec := &uiTerm{}
	ui := NewClientUI(rec.source())
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	start := time.Now()
	err := runAttempt(ui, name, "id", false, func() error {
		_, err := decryptPlugin(t, ui, name, fakeplugin.ModeInsertForever, ct)
		ui.mu.Lock()
		rounds, hit := ui.rounds, ui.hitCap
		ui.mu.Unlock()
		if rounds != InsertRoundCap {
			t.Fatalf("yes rounds = %d, want %d", rounds, InsertRoundCap)
		}
		if !hit {
			t.Fatal("insert cap was not hit")
		}
		return err
	})
	elapsed := time.Since(start)
	if elapsed < insertRetryDelay/2 {
		t.Fatalf("rounds 2 and 3 were immediate: %v", elapsed)
	}
	if !errors.Is(err, ErrInsertRounds) {
		t.Fatalf("errors.Is(., ErrInsertRounds) = false: %v", err)
	}
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("errors.Is(., ErrIncorrectIdentity) = false: %v", err)
	}

	inserts := 0
	for _, line := range rec.lines() {
		if strings.Contains(strings.ToLower(line), "skip") {
			t.Fatalf("skip offered on last identity: %q", line)
		}
		if strings.Contains(line, "insert") {
			inserts++
		}
	}
	if inserts != InsertRoundCap {
		t.Fatalf("insert prompts = %d, want %d", inserts, InsertRoundCap)
	}

	msg := err.Error()
	if !strings.Contains(msg, "age-plugin-") {
		t.Fatalf("ErrInsertRounds missing age-plugin-: %q", msg)
	}
	if !strings.Contains(msg, name) {
		t.Fatalf("ErrInsertRounds missing plugin name %q: %q", name, msg)
	}
	low := strings.ToLower(msg)
	deviceWord := "yubi" + "key"
	for _, w := range []string{deviceWord, "serial", "device"} {
		if strings.Contains(low, w) {
			t.Fatalf("ErrInsertRounds contains %q: %q", w, msg)
		}
	}
}

func TestClientUIInsertForeverThenOK(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	ui := NewClientUI((&uiTerm{}).source())
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	err := runAttempt(ui, name, "first", false, func() error {
		_, err := decryptPlugin(t, ui, name, fakeplugin.ModeInsertForever, ct)
		return err
	})
	if !errors.Is(err, ErrInsertRounds) {
		t.Fatalf("first identity: errors.Is(., ErrInsertRounds) = false: %v", err)
	}
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("first identity: errors.Is(., ErrIncorrectIdentity) = false: %v", err)
	}

	var got []byte
	err = runAttempt(ui, name, "second", false, func() error {
		var err error
		got, err = decryptPlugin(t, ui, name, fakeplugin.ModeOK, ct)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(uiPlain)) {
		t.Fatal("second identity: plaintext mismatch")
	}
}

func TestClientUIMoreUntriedOffersSkip(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	rec := &uiTerm{}
	ui := NewClientUI(rec.source())
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	err := runAttempt(ui, name, "first", true, func() error {
		_, err := decryptPlugin(t, ui, name, fakeplugin.ModeInsertForever, ct)
		return err
	})
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("errors.Is(., ErrIncorrectIdentity) = false: %v", err)
	}
	if errors.Is(err, ErrInsertRounds) {
		t.Fatal("skip answered no at the cap")
	}
	found := false
	for _, line := range rec.lines() {
		if strings.Contains(strings.ToLower(line), "skip") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("skip not offered while another identity is untried")
	}
}

func TestWaitTimerSlowTouch(t *testing.T) {
	if testing.Short() {
		t.Skip("age WaitTimer is hardcoded at 5s")
	}
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	rec := &uiTerm{waitCh: make(chan string, 8)}
	ui := NewClientUI(rec.source())
	ct := encryptPlugin(t, name, fakeplugin.ModeOK)

	err := runAttempt(ui, name, "id", false, func() error {
		_, err := decryptPlugin(t, ui, name, fakeplugin.ModeSlowTouch, ct)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Channel/atomic: WaitTimer runs on age's goroutine (never a plain bool).
	if rec.waitN.Load() < 1 {
		t.Fatal("WaitTimer line did not reach the terminal")
	}
	found := false
	for _, line := range rec.lines() {
		if strings.Contains(line, "waiting on") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("WaitTimer line did not reach the terminal")
	}
}

func TestClientUINoTerminalStartsNoPlugin(t *testing.T) {
	skipWindows(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")
	var opened atomic.Int32
	ui := NewClientUI(func() (Terminal, error) {
		opened.Add(1)
		return nil, ErrNoTerminal
	})
	var unwrapped atomic.Int32
	err := runAttempt(ui, "envtest", "id.txt", false, func() error {
		unwrapped.Add(1)
		id, ierr := plugin.NewIdentity(fakeplugin.Identity("envtest", fakeplugin.ModeOK), &ui.ClientUI)
		if ierr != nil {
			return ierr
		}
		_, derr := decryptWith([]byte("age-stub"), id)
		return derr
	})
	if err != ErrNoTerminal {
		t.Fatalf("ErrNoTerminal was not returned unchanged: %v", err)
	}
	if opened.Load() == 0 {
		t.Fatal("TerminalSource was not invoked")
	}
	if unwrapped.Load() != 0 {
		t.Fatal("plugin unwrap ran")
	}
	var nf *plugin.NotFoundError
	if errors.As(err, &nf) {
		t.Fatal("plugin process was started")
	}
}

func runAttempt(ui *ClientUI, name, source string, more bool, fn func() error) error {
	ui.beginAttempt(name, source, more)
	if _, err := ui.terminal(); err != nil {
		return err
	}
	err := fn()
	return errors.Join(err, ui.endAttempt())
}

func encryptPlugin(t *testing.T, name string, m fakeplugin.Mode) []byte {
	t.Helper()
	r, err := plugin.NewRecipient(fakeplugin.Recipient(name, m), &plugin.ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, uiPlain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decryptPlugin(t *testing.T, ui *ClientUI, name string, m fakeplugin.Mode, ct []byte) ([]byte, error) {
	t.Helper()
	id, err := plugin.NewIdentity(fakeplugin.Identity(name, m), &ui.ClientUI)
	if err != nil {
		t.Fatal(err)
	}
	return decryptWith(ct, id)
}

func decryptWith(ct []byte, id age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

type uiTerm struct {
	mu       sync.Mutex
	notifies []string
	replies  []string
	err      error
	out      bytes.Buffer
	waitN    atomic.Int32
	waitCh   chan string
}

func (r *uiTerm) source() TerminalSource {
	return func() (Terminal, error) { return r, nil }
}

func (r *uiTerm) Notify(line string) {
	r.mu.Lock()
	r.notifies = append(r.notifies, line)
	r.out.WriteString(line + "\n")
	ch := r.waitCh
	r.mu.Unlock()
	if strings.Contains(line, "waiting on") {
		r.waitN.Add(1)
		if ch != nil {
			select {
			case ch <- line:
			default:
			}
		}
	}
}

func (r *uiTerm) ReadLine(prompt string, secret bool) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.out.WriteString(prompt)
	if r.err != nil {
		return "", r.err
	}
	if len(r.replies) == 0 {
		return "", errors.New("no reply")
	}
	line := r.replies[0]
	r.replies = r.replies[1:]
	if !secret {
		r.out.WriteString(line + "\n")
	}
	return line, nil
}

func (r *uiTerm) Close() error { return nil }

func (r *uiTerm) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.notifies))
	copy(out, r.notifies)
	return out
}

func (r *uiTerm) captured() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.String()
}

func assertPINNotLeaked(t *testing.T, rec *uiTerm, err error, pin string) {
	t.Helper()
	if strings.Contains(rec.captured(), pin) {
		t.Fatal("PIN appeared in a captured writer")
	}
	for _, line := range rec.lines() {
		if strings.Contains(line, pin) {
			t.Fatal("PIN appeared in a Notify line")
		}
	}
	if err != nil && strings.Contains(err.Error(), pin) {
		t.Fatal("PIN appeared in an error")
	}
}

var _ Terminal = (*uiTerm)(nil)
