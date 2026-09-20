package pipeline

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/rootwarp/envelope/internal/key"
)

// Terminal is the operator-facing I/O an interactive identity needs.
// cmd/envelope may not import internal/key (D7), so this alias is the injection type.
type Terminal = key.Terminal

// ErrNoPinTerminal is the FR-YK-13 refusal: no controlling terminal, and this
// identity would need to prompt. The /dev/tty open failing is the detection.
// Never block, never retry, never fall back to stdin — which may be the payload.
var ErrNoPinTerminal = errors.New("this identity needs a PIN and there is no terminal to ask on")

// testOpenTerminal, when set, replaces key.OpenTerminal for the production
// source. Tests force a missing or present terminal without a real /dev/tty.
var testOpenTerminal func() (Terminal, error)

func terminalSource(t Terminal) key.TerminalSource {
	if t != nil {
		return func() (key.Terminal, error) { return t, nil }
	}
	if testOpenTerminal != nil {
		return testOpenTerminal
	}
	return key.OpenTerminal
}

func nativeScalar(s *key.Set) *key.Identity {
	if s == nil {
		return nil
	}
	for _, id := range s.Identities() {
		if id.Kind() == key.KindNative && id.HasScalar() {
			return id
		}
	}
	return nil
}

func firstIdentityPath(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

// identitySource is the path named in Phase 1's "no identity matched the file: <path>".
// LoadSet hoists natives first, so argv[0] can be a plugin while the opener is a later native.
func identitySource(s *key.Set, paths []string) string {
	if id := nativeScalar(s); id != nil {
		if src := id.Source(); src != "" {
			return src
		}
	}
	if s != nil {
		for _, id := range s.Identities() {
			if src := id.Source(); src != "" {
				return src
			}
		}
	}
	return firstIdentityPath(paths)
}

// refuseInteractiveWithoutTerminal fails closed before a plugin process starts
// (FR-YK-13). A native identity with a scalar never opens the terminal, so a
// mixed set still restores a v1 shard set with zero plugin interactions.
func refuseInteractiveWithoutTerminal(s *key.Set, src key.TerminalSource) error {
	if s == nil || !s.Interactive() {
		return nil
	}
	if nativeScalar(s) != nil {
		return nil
	}
	if src == nil {
		return ErrNoPinTerminal
	}
	t, err := src()
	if err != nil || t == nil {
		return ErrNoPinTerminal
	}
	_ = t.Close()
	return nil
}

func noteFirstPlugin(s *key.Set, status io.Writer) {
	if s == nil || status == nil {
		return
	}
	for _, id := range s.Identities() {
		if id.Kind() != key.KindPlugin {
			continue
		}
		path, err := key.ResolvePlugin(id.PluginName())
		if err != nil {
			return
		}
		if !filepath.IsAbs(path) {
			abs, aerr := filepath.Abs(path)
			if aerr != nil {
				return
			}
			path = abs
		}
		fmt.Fprintln(status, "using "+path)
		return
	}
}
