package key

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

const bundleHeaderPrefix = "# envelope-bundle:"

// Set is one run's ordered identity list plus the pin, if a bundle carried one.
// Order is the decrypt order: native identities first (no process, no card, no
// prompt), then plugin identities in -identity order.
type Set struct {
	ids    []*Identity
	pin    *pinSource
	ui     *ClientUI
	term   TerminalSource
	nPaths int
	bundle bool
}

// pinSource is filled by YK-11. HasPin is false until then.
type pinSource struct{}

type attemptState struct {
	mu        sync.Mutex
	attempted bool
	err       error
}

// LoadSet reads each path, routing AGE-PLUGIN- lines to plugin.NewIdentity and
// the remainder to age.ParseIdentities in one call so its diagnostics stay
// intact. plugin.NewIdentity starts no process. A path whose first non-empty
// line is the bundle header is recognised and refused until YK-11.
func LoadSet(paths []string, term TerminalSource) (*Set, error) {
	s := &Set{
		term:   term,
		ui:     NewClientUI(term),
		nPaths: len(paths),
	}
	var natives, plugins []*Identity
	for _, path := range paths {
		n, p, err := s.loadPath(path)
		if err != nil {
			return nil, err
		}
		natives = append(natives, n...)
		plugins = append(plugins, p...)
	}
	s.ids = append(natives, plugins...)
	if len(s.ids) == 0 {
		return nil, ErrNotSingleIdentity
	}
	return s, nil
}

func (s *Set) loadPath(path string) (natives, plugins []*Identity, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if isBundle(data) {
		s.bundle = true
		return nil, nil, errBundleUnsupported
	}

	var rest bytes.Buffer
	var pluginLines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, PluginPrefix) {
			pluginLines = append(pluginLines, line)
			continue
		}
		rest.WriteString(line)
		rest.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}

	ui := &s.ui.ClientUI
	for _, line := range pluginLines {
		p, err := plugin.NewIdentity(line, ui)
		if err != nil {
			// plugin.ParseIdentity may quote the line; never wrap or return it.
			return nil, nil, ErrInvalidIdentity
		}
		plugins = append(plugins, &Identity{
			plugin:     p,
			kind:       KindPlugin,
			pluginName: p.Name(),
			source:     path,
		})
	}

	if hasNonComment(rest.Bytes()) {
		ids, err := age.ParseIdentities(bytes.NewReader(rest.Bytes()))
		if err != nil {
			// age quotes the identity line; never wrap or return that error.
			return nil, nil, ErrInvalidIdentity
		}
		for _, id := range ids {
			n, err := nativeIdentity(id, path)
			if err != nil {
				return nil, nil, err
			}
			natives = append(natives, n)
		}
	}
	return natives, plugins, nil
}

func nativeIdentity(id age.Identity, path string) (*Identity, error) {
	x25519, ok := id.(*age.X25519Identity)
	if !ok {
		return &Identity{native: id, kind: KindNative, source: path}, nil
	}
	n, err := newIdentity(x25519)
	if err != nil {
		return nil, err
	}
	n.source = path
	return n, nil
}

func isBundle(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		return strings.HasPrefix(strings.TrimSpace(line), bundleHeaderPrefix)
	}
	return false
}

func hasNonComment(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return true
	}
	return false
}

func (s *Set) Identities() []*Identity {
	out := make([]*Identity, len(s.ids))
	copy(out, s.ids)
	return out
}

func (s *Set) Interactive() bool {
	for _, id := range s.ids {
		if id.Interactive() {
			return true
		}
	}
	return false
}

func (s *Set) HasPin() bool { return s.pin != nil }

// BareFileIdentity is the FR-YK-03 boolean: exactly one path, exactly one
// native X25519 identity, no bundle metadata. The caller still has to check
// there is no -recipient flag.
func (s *Set) BareFileIdentity() bool {
	if s == nil || s.nPaths != 1 || s.bundle || len(s.ids) != 1 {
		return false
	}
	id := s.ids[0]
	return id.kind == KindNative && id.hasScalar
}

func (s *Set) Zero() {
	if s == nil {
		return
	}
	for _, id := range s.ids {
		id.Zero()
	}
}
