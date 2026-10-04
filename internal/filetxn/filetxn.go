// Package filetxn tracks which paths one filesystem operation created and
// whether that operation committed, so cleanup removes only those paths.
//
// Create always uses O_WRONLY|O_CREATE|O_EXCL and takes the mode as a
// parameter. The transaction performs no chmod and owns no write tail.
// Directories are not transactional: mkdirAllDurable stays outside.
package filetxn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Options supplies the seams a writer already has. The zero value uses
// os.Rename, os.Remove, and a directory sync that tolerates EINVAL and
// ENOTSUP from the sync itself.
type Options struct {
	Rename  func(oldpath, newpath string) error
	Remove  func(name string) error
	SyncDir func(dir string) error
}

// Txn is one operation's record of the paths it created and whether it
// committed.
type Txn struct {
	dir       string
	opts      Options
	created   []string
	committed bool
}

// ErrNotOwned is returned by Commit when from was not created by this
// transaction. Nothing was renamed.
var ErrNotOwned = errors.New("commit source was not created by this transaction")

// Begin starts a transaction whose directory sync targets dir. dir is not
// created.
func Begin(dir string, o Options) *Txn {
	return &Txn{dir: dir, opts: o}
}

// Create opens path with O_WRONLY|O_CREATE|O_EXCL and perm. The path is
// owned only when the error is nil. A failure is returned unchanged.
func (t *Txn) Create(path string, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return nil, err
	}
	t.created = append(t.created, path)
	return f, nil
}

// Owns reports whether Create returned a nil error for path.
func (t *Txn) Owns(path string) bool {
	for _, created := range t.created {
		if created == path {
			return true
		}
	}
	return false
}

// Commit renames from onto to. The rename is the commit point: ctx is
// checked immediately before it, a cancellation renames nothing and returns
// ctx.Err(), and a directory-sync failure after a successful rename is
// returned unchanged with the transaction already committed. Commit does
// not remove a file. from must be owned by this transaction.
func (t *Txn) Commit(ctx context.Context, from, to string) error {
	if !t.Owns(from) {
		return ErrNotOwned
	}
	rename := os.Rename
	if t.opts.Rename != nil {
		rename = t.opts.Rename
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rename(from, to); err != nil {
		return err
	}
	t.committed = true
	return t.SyncDir()
}

// Done marks a direct-final create as the commit. Abort after Done removes
// nothing.
func (t *Txn) Done() {
	t.committed = true
}

// SyncDir fsyncs the directory passed to Begin. EINVAL and ENOTSUP from the
// sync are tolerated: they mean the filesystem has no directory-sync
// operation. An open error is returned unchanged.
func (t *Txn) SyncDir() error {
	if t.opts.SyncDir != nil {
		return tolerateDirSync(t.opts.SyncDir(t.dir))
	}
	d, err := os.Open(t.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return tolerateDirSync(d.Sync())
}

func tolerateDirSync(err error) error {
	if err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

// Abort removes every owned path, in reverse creation order, when the
// transaction has not committed. A committed transaction is left unchanged.
// ErrNotExist is ignored. Each other removal failure is joined as
// "could not remove %s: %w".
func (t *Txn) Abort() error {
	if t.committed {
		return nil
	}
	remove := os.Remove
	if t.opts.Remove != nil {
		remove = t.opts.Remove
	}
	var errs []error
	for i := len(t.created) - 1; i >= 0; i-- {
		path := t.created[i]
		if err := remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("could not remove %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}
