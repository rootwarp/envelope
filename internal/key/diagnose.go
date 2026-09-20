package key

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/rootwarp/envelope/internal/crypt"

	_ "golang.org/x/sys/execabs" // NFR-YK-01: pin the execabs module edge as direct
)

const oneLineMax = 240

var (
	ErrPluginNotInstalled = errors.New("age plugin binary is not installed")
	ErrPluginFailed       = errors.New("age plugin failed")
	ErrPluginProtocol     = errors.New("age plugin protocol error")
	ErrNoScalar           = errors.New("identity has no X25519 scalar")
	ErrNoLocalRecipient   = errors.New("plugin identity has no local recipient string")
)

// diagnose attaches an Envelope sentinel at the call site. Plugin-supplied
// text may be surfaced but is never the error identity, and is collapsed to
// one line. age's line-quoting parse error is never wrapped.
func diagnose(id *Identity, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if id != nil && id.kind == KindPlugin {
		id.attempt.mu.Lock()
		attempted := id.attempt.attempted
		unwrapErr := id.attempt.err
		id.attempt.mu.Unlock()
		if !attempted {
			return crypt.ErrMalformedAge
		}
		if unwrapErr == nil {
			return err
		}
		err = unwrapErr
	}
	if errors.Is(err, age.ErrIncorrectIdentity) {
		return err
	}
	var nf *plugin.NotFoundError
	if errors.As(err, &nf) {
		name := nf.Name
		if id != nil && id.pluginName != "" {
			name = id.pluginName
		}
		return fmt.Errorf("%w: age-plugin-%s is not installed; install it with Homebrew, Nix, your distro package, or cargo install",
			ErrPluginNotInstalled, name)
	}
	name := ""
	if id != nil {
		name = id.pluginName
	}
	if pluginProtocol(err) {
		if name == "" {
			return ErrPluginProtocol
		}
		return fmt.Errorf("%w: age-plugin-%s", ErrPluginProtocol, name)
	}
	if id != nil && id.kind == KindPlugin {
		msg := oneLine(err.Error())
		if name == "" {
			return fmt.Errorf("%w: %s", ErrPluginFailed, msg)
		}
		if id.source != "" {
			return fmt.Errorf("%w: age-plugin-%s (%s): %s", ErrPluginFailed, name, id.source, msg)
		}
		return fmt.Errorf("%w: age-plugin-%s: %s", ErrPluginFailed, name, msg)
	}
	return err
}

// ResolvePlugin returns the absolute path of age-plugin-<name> as first on
// PATH. execabs (blank-imported above) blocks a relative-directory hijack;
// an absolute one is still possible, which is why the caller names this path
// on stderr the first time a plugin would launch (NFR-YK-04).
func ResolvePlugin(name string) (string, error) {
	if name == "" {
		return "", exec.ErrNotFound
	}
	return exec.LookPath("age-plugin-" + name)
}

func pluginProtocol(err error) bool {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// Age client diagnostics, not plugin prose: error-stanza bodies are a
	// plain fmt.Errorf("%s", body) and do not contain these strings.
	msg := err.Error()
	for _, needle := range []string{
		"couldn't start plugin",
		"failed to read line",
		"malformed stanza",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// oneLine is the first line, trimmed, length-capped. A wrong PIN surfaces
// format!("{:?}", …) of a Rust error whose Debug appends a blank line and a
// bracketed bug-report URL.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > oneLineMax {
		s = s[:oneLineMax]
	}
	return s
}
