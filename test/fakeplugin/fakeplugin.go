// Package fakeplugin is a re-exec'd fake age plugin for tests.
//
// Install uses t.Setenv, which forbids t.Parallel in that test and its parents.
// PATH is replaced, not prepended, so a developer's real plugin cannot satisfy
// the lookup. A RequestValue returning a constant shorter than 6 bytes would
// spin the real plugin's unbounded PIN loop forever, so fake PINs must be at
// least 6 bytes.
package fakeplugin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const (
	garbageName  = "envgarbage"
	garbageExit  = 9
	pluginPrefix = "age-plugin-"
	// PIN is ≥ 6 bytes: a shorter constant would spin the real plugin's PIN loop.
	PIN            = "424242"
	labelExclusive = "envelope-exclusive"
	// DebugSecret is a secret-looking token ModeDebugFooter appends after its URL footer.
	DebugSecret = "file-key=00envelope-secret-body"

	// invocationsEnv is the absolute path of the file Dispatch appends to.
	// Install sets it so a re-exec'd plugin records itself; production never sets it.
	invocationsEnv = "ENVELOPE_FAKEPLUGIN_INVOCATIONS"
	// protocolEnv is the absolute path of the file handlers append commands to.
	protocolEnv = "ENVELOPE_FAKEPLUGIN_PROTOCOL"
	// pidsEnv is the absolute path of the file Dispatch appends PIDs to.
	pidsEnv = "ENVELOPE_FAKEPLUGIN_PIDS"
)

// link is os.Link; tests replace it to force the copy fallback.
var link = os.Link

type Mode byte

const (
	ModeOK                Mode = iota + 1
	ModeIncorrectIdentity      // no file-key → age.ErrIncorrectIdentity
	ModeFatal                  // error stanza, not ErrIncorrectIdentity
	ModePIN                    // RequestValue(secret) then unwrap
	ModeWrongPIN               // fatal, multi-line body
	ModeInsertForever          // Confirm loop until the client answers no
	ModeSlowTouch              // sleeps 6 s so WaitTimer fires
	ModeLabels                 // RecipientWithLabels; refuses to mix with unlabeled recipients
	ModeDebugFooter            // error stanza: multi-line Debug footer with URL
)

// Dispatch returns false unless argv[0] is age-plugin-<name>. When it is, it
// runs the plugin and calls os.Exit.
func Dispatch() bool {
	base := filepath.Base(os.Args[0])
	if !strings.HasPrefix(base, pluginPrefix) {
		return false
	}
	recordInvocation()
	name := strings.TrimPrefix(base, pluginPrefix)
	if name == "" {
		return false
	}
	if name == garbageName {
		runGarbage()
		return true
	}
	os.Exit(runPlugin(name))
	return true
}

// Install hardlinks (or copies, on EXDEV) the test binary into a fresh
// absolute directory and replaces PATH with it. execabs refuses a relative
// PATH entry.
func Install(t *testing.T, name string) string {
	t.Helper()
	if name == "" {
		t.Fatal("Install: empty plugin name")
	}
	dir, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("Install: plugin directory is relative: %q", dir)
	}
	ex, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, pluginPrefix+name)
	if err := link(ex, dst); err != nil {
		if err := copyExecutable(ex, dst); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	// AGEDEBUG=plugin tees both protocol directions to stderr, including PIN and file key.
	t.Setenv("AGEDEBUG", "")
	logPath := filepath.Join(dir, "invocations.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(invocationsEnv, logPath)
	protoPath := filepath.Join(dir, "protocol.log")
	if err := os.WriteFile(protoPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(protocolEnv, protoPath)
	pidPath := filepath.Join(dir, "pids.log")
	if err := os.WriteFile(pidPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(pidsEnv, pidPath)
	return dir
}

func recordInvocation() {
	p := os.Getenv(invocationsEnv)
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "%s\n", os.Args[0])
	_ = f.Close()
	recordPID()
}

func recordPID() {
	p := os.Getenv(pidsEnv)
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Close()
}

// Invocations returns the absolute plugin paths Dispatch recorded for this
// Install. Empty when no age-plugin-* process started.
func Invocations(t *testing.T) []string {
	t.Helper()
	return readLogLines(t, os.Getenv(invocationsEnv))
}

// PIDs returns the plugin process IDs Dispatch recorded for this Install.
func PIDs(t *testing.T) []int {
	t.Helper()
	var out []int
	for _, line := range readLogLines(t, os.Getenv(pidsEnv)) {
		pid, err := strconv.Atoi(line)
		if err != nil || pid <= 0 {
			continue
		}
		out = append(out, pid)
	}
	return out
}

// ProtocolLog returns the age plugin commands this Install recorded
// ("recipient-v1 add-recipient", "identity-v1 add-identity", …).
func ProtocolLog(t *testing.T) []string {
	t.Helper()
	return readLogLines(t, os.Getenv(protocolEnv))
}

func readLogLines(t *testing.T, p string) []string {
	t.Helper()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// Identity encodes m in the bech32 payload of an AGE-PLUGIN-<NAME>-1… string.
func Identity(name string, m Mode) string {
	return plugin.EncodeIdentity(name, []byte{byte(m)})
}

// Recipient encodes m in the bech32 payload of an age1<name>1… string.
func Recipient(name string, m Mode) string {
	return plugin.EncodeRecipient(name, []byte{byte(m)})
}

func runGarbage() {
	for _, a := range os.Args[1:] {
		if a == "--age-plugin=identity-v1" {
			os.Exit(garbageExit)
		}
	}
	_, _ = os.Stdout.Write([]byte("this is not the age plugin protocol\n"))
	os.Exit(0)
}

func runPlugin(name string) int {
	p, err := plugin.New(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		recordProtocol("add-recipient")
		return fakeRecipient{name: name, mode: modeOf(data)}, nil
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		recordProtocol("add-identity")
		return fakeRecipient{name: name, mode: modeOf(data)}, nil
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		recordProtocol("add-identity")
		return fakeIdentity{name: name, mode: modeOf(data), p: p}, nil
	})
	return p.Main()
}

func pluginState() string {
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "--age-plugin=") {
			return strings.TrimPrefix(a, "--age-plugin=")
		}
	}
	return ""
}

func recordProtocol(cmd string) {
	p := os.Getenv(protocolEnv)
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	state := pluginState()
	if state == "" {
		_, _ = fmt.Fprintf(f, "%s\n", cmd)
	} else {
		_, _ = fmt.Fprintf(f, "%s %s\n", state, cmd)
	}
	_ = f.Close()
}

func modeOf(data []byte) Mode {
	if len(data) == 0 {
		return ModeOK
	}
	return Mode(data[0])
}

func wrap(fileKey []byte) []byte {
	out := make([]byte, len(fileKey))
	for i, b := range fileKey {
		out[i] = b ^ 0x5a
	}
	return out
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

type fakeRecipient struct {
	name string
	mode Mode
}

var _ age.RecipientWithLabels = fakeRecipient{}

func (r fakeRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

func (r fakeRecipient) WrapWithLabels(fileKey []byte) ([]*age.Stanza, []string, error) {
	st := []*age.Stanza{{Type: r.name, Body: wrap(fileKey)}}
	if r.mode == ModeLabels {
		return st, []string{labelExclusive}, nil
	}
	return st, nil, nil
}

type fakeIdentity struct {
	name string
	mode Mode
	p    *plugin.Plugin
}

func (i fakeIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	switch i.mode {
	case ModeIncorrectIdentity:
		return nil, age.ErrIncorrectIdentity
	case ModeFatal:
		return nil, errors.New("no card present")
	case ModePIN:
		got, err := i.p.RequestValue("enter PIN", true)
		if err != nil {
			return nil, err
		}
		if got != PIN {
			return nil, errors.New("invalid PIN")
		}
	case ModeWrongPIN:
		if _, err := i.p.RequestValue("enter PIN", true); err != nil {
			return nil, err
		}
		return nil, errors.New("incorrect PIN for this identity\n2 tries remaining")
	case ModeDebugFooter:
		return nil, errors.New("incorrect PIN for this identity\n\n[please report this bug at https://example.invalid/issues]\n" + DebugSecret)
	case ModeInsertForever:
		for {
			yes, err := i.p.Confirm("insert the card", "plugged in", "skip")
			if err != nil {
				return nil, err
			}
			if !yes {
				return nil, age.ErrIncorrectIdentity
			}
		}
	case ModeSlowTouch:
		time.Sleep(6 * time.Second)
	}
	for _, s := range stanzas {
		if s.Type != i.name {
			continue
		}
		return wrap(s.Body), nil
	}
	return nil, age.ErrIncorrectIdentity
}
