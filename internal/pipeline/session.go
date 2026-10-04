package pipeline

import (
	"context"
	"errors"
	"io"

	"github.com/rootwarp/envelope/internal/filetxn"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
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
// opener, the real rename, remove and directory sync, and no observation.
type deps struct {
	openTerminal func() (Terminal, error)
	captureCtx   func(context.Context)

	// wrapDst wraps the restore decrypt destination. The zero value writes
	// plaintext straight to the file.
	wrapDst func(context.Context, io.Writer) io.Writer

	// wrapManifestOpener wraps the opener chooseManifest uses. The zero value
	// opens each blob as-is.
	wrapManifestOpener func(manifest.Opener) manifest.Opener

	// atLoadShard runs at the start of every shard open. The zero value does
	// nothing.
	atLoadShard func(path string)

	// atReconstruct runs after the survivor count and before reconstruction.
	// The zero value does nothing.
	atReconstruct func(shards [][]byte)

	// atJoin observes the joined ciphertext. The zero value does nothing.
	atJoin func(ct []byte, outSize int64)

	// observeOpen receives the identity-side Unwrap count after openShardSet
	// finishes, before the key set is zeroed on a failed return. The zero
	// value records nothing.
	observeOpen func(int)

	// observeRun receives the identity-side Unwrap count at the end of Restore
	// or Verify, and of a failed openShardSet, before the key set is zeroed.
	// The zero value records nothing.
	observeRun func(int)

	// txn is copied into filetxn.Begin. The transaction stays with the writer.
	// The zero value is production: os.Rename, os.Remove, and a directory sync
	// that tolerates EINVAL and ENOTSUP.
	txn filetxn.Options
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
	if d.wrapManifestOpener != nil {
		base.wrapManifestOpener = d.wrapManifestOpener
	}
	if d.atLoadShard != nil {
		base.atLoadShard = d.atLoadShard
	}
	if d.atReconstruct != nil {
		base.atReconstruct = d.atReconstruct
	}
	if d.atJoin != nil {
		base.atJoin = d.atJoin
	}
	if d.observeOpen != nil {
		base.observeOpen = d.observeOpen
	}
	if d.observeRun != nil {
		base.observeRun = d.observeRun
	}
	if d.txn.Rename != nil {
		base.txn.Rename = d.txn.Rename
	}
	if d.txn.Remove != nil {
		base.txn.Remove = d.txn.Remove
	}
	if d.txn.SyncDir != nil {
		base.txn.SyncDir = d.txn.SyncDir
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
