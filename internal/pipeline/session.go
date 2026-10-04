package pipeline

import (
	"context"
	"errors"
	"io"

	"github.com/rootwarp/envelope/internal/key"
)

// session owns everything whose lifetime is one command and closes it once.
// It does not own a file transaction, format decisions, or anything in key
// beyond constructing the set.
type session struct {
	ctx    context.Context
	status io.Writer
	deps   deps
	term   Terminal
	owned  bool
	keys   *key.Set
}

// deps is one run's seams. The zero value is production: the real terminal
// opener and no context capture. Tests set deps on the command options.
type deps struct {
	openTerminal func() (Terminal, error)
	captureCtx   func(context.Context)
	// Restore reads testWrapDst, not this field. The signal-test build copies it out.
	wrapDst func(context.Context, io.Writer) io.Writer
}

func (d deps) withDefaults() deps {
	base := defaultDeps()
	if d.openTerminal != nil {
		base.openTerminal = d.openTerminal
	}
	if d.captureCtx != nil {
		base.captureCtx = d.captureCtx
	}
	if d.wrapDst != nil {
		base.wrapDst = d.wrapDst
	}
	return base
}

func newSession(ctx context.Context, injected Terminal, d deps, status io.Writer) *session {
	if ctx == nil {
		ctx = context.Background()
	}
	d = d.withDefaults()
	s := &session{
		ctx:    ctx,
		status: status,
		deps:   d,
		term:   injected,
	}
	if d.captureCtx != nil {
		d.captureCtx(ctx)
	}
	return s
}

// source hands key a borrowed handle. key never owns the terminal: the
// session opened it, or the caller did and passed it in.
func (s *session) source() key.TerminalSource {
	return func() (key.Terminal, error) {
		if err := s.resolve(); err != nil {
			return nil, err
		}
		return key.Borrow(s.term)()
	}
}

func (s *session) loadKeys(paths []string) (*key.Set, error) {
	set, err := key.LoadSet(paths, s.source(), key.WithContext(s.ctx))
	if err != nil {
		return nil, err
	}
	s.keys = set
	return set, nil
}

// loadFiles is loadKeys for a file this command already read.
func (s *session) loadFiles(fs []*key.IdentityFile) (*key.Set, error) {
	set, err := key.LoadFiles(fs, s.source(), key.WithContext(s.ctx))
	if err != nil {
		return nil, err
	}
	s.keys = set
	return set, nil
}

// requireTerminal resolves the run's one handle. It closes nothing.
func (s *session) requireTerminal() error {
	if s == nil {
		return key.ErrNoTerminal
	}
	return s.resolve()
}

func (s *session) resolve() error {
	if s.term != nil {
		return nil
	}
	open := s.deps.openTerminal
	if open == nil {
		open = key.OpenTerminal
	}
	t, err := open()
	if err != nil {
		return err
	}
	if t == nil {
		return key.ErrNoTerminal
	}
	s.term = t
	s.owned = true
	return nil
}

// Close zeros the key set and closes the terminal this session opened.
// A second call closes nothing. A borrowed handle is never closed.
func (s *session) Close() error {
	if s == nil {
		return nil
	}
	if s.keys != nil {
		s.keys.Zero()
	}
	if !s.owned || s.term == nil {
		return nil
	}
	s.owned = false
	return errors.Join(s.term.Close())
}
