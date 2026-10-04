package pipeline

import (
	"context"
	"encoding/hex"
	"errors"
	"io"

	"github.com/rootwarp/envelope/internal/key"
)

type BindMode int

const (
	BindCreate BindMode = iota + 1
	BindAddRecipient
	BindReplaceIdentity
)

type BindOptions struct {
	Mode          BindMode
	IdentityPaths []string // create: the stub files; replace: the new stub files
	Recipients    []string
	BundlePath    string // the two modify modes
	OutPath       string // create
	Terminal      Terminal
	deps          deps
}

// SetTestRename replaces os.Rename when this bind publishes the bundle.
// A nil function is production. Tests outside this package use it;
// in-package tests set deps.
func (o *BindOptions) SetTestRename(fn func(oldpath, newpath string) error) {
	if fn == nil {
		return
	}
	o.deps.txn.Rename = fn
}

// SetTestObserveBind receives the pin-unwrap count from add-recipient.
// A nil function is production, which records nothing. Tests outside this
// package use it; in-package tests set deps.
func (o *BindOptions) SetTestObserveBind(fn func(int)) {
	if fn == nil {
		return
	}
	o.deps.observeBind = fn
}

type BindReport struct {
	Path       string
	Recipients []string
	MACKeyID   string // hex, non-secret
	Identities int
}

// ErrBadRecipient is a usage error at bind (exit 2): the string is not a
// bech32 age recipient.
var ErrBadRecipient = key.ErrBadRecipient

var errBindMode = errors.New("bind mode is not valid")

func Bind(ctx context.Context, opts BindOptions, status io.Writer) (*BindReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = status
	switch opts.Mode {
	case BindCreate:
		return bindCreate(ctx, opts)
	case BindAddRecipient:
		return bindAddRecipient(ctx, opts)
	case BindReplaceIdentity:
		return bindReplaceIdentity(ctx, opts)
	default:
		return nil, errBindMode
	}
}

func bindCreate(ctx context.Context, opts BindOptions) (*BindReport, error) {
	lines, err := readIdentityLines(opts.IdentityPaths)
	if err != nil {
		return nil, err
	}
	// Wrap talks to the plugin client through ClientUI; a nil UI panics
	// even when encryption to a plugin recipient is card-free.
	sess := newSession(ctx, opts.Terminal, opts.deps, nil)
	defer sess.Close()
	ui := key.NewClientUI(sess.source())
	defer ui.Close() // Wrap may prompt on the borrowed handle; this only drops the UI cache. The session closes the fd.
	rs, err := key.ParseRecipients(opts.Recipients, ui)
	if err != nil {
		return nil, err
	}
	b, err := key.NewBundle(lines, rs)
	if err != nil {
		return nil, err
	}
	// WriteNew's O_EXCL create is the commit. A cancel seen before it
	// returns without creating OutPath.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := key.WriteNew(opts.OutPath, b); err != nil {
		return nil, err
	}
	return bindReport(opts.OutPath, b), nil
}

func bindAddRecipient(ctx context.Context, opts BindOptions) (*BindReport, error) {
	// One read. Stat stays first so a missing bundle still reports "stat …",
	// and the pin unwrap cannot observe a file that replaced this one.
	f, err := key.ReadBundleFile(opts.BundlePath)
	defer f.Zero()
	if err != nil {
		return nil, err
	}
	b, err := f.Bundle()
	if err != nil {
		return nil, err
	}
	extra, err := key.ParseRecipients(opts.Recipients, nil)
	if err != nil {
		return nil, err
	}
	if extra.Len() == 0 {
		return nil, key.ErrBundleNoRecipient
	}
	combined := make([]string, 0, len(b.Recipients)+extra.Len())
	combined = append(combined, b.Recipients...)
	combined = append(combined, extra.Strings()...)
	if _, err := key.ParseRecipients(combined, nil); err != nil {
		return nil, err
	}

	sess := newSession(ctx, opts.Terminal, opts.deps, nil)
	defer sess.Close()
	set, err := sess.loadFiles([]*key.IdentityFile{f})
	if err != nil {
		return nil, err
	}
	if err := refuseInteractiveWithoutTerminal(set, sess); err != nil {
		return nil, err
	}
	if err := b.AddRecipients(set, extra); err != nil {
		return nil, err
	}
	if sess.deps.observeBind != nil {
		sess.deps.observeBind(set.Interactions())
	}
	if err := key.Replace(ctx, opts.BundlePath, b, sess.deps.txn); err != nil {
		return nil, err
	}
	return bindReport(opts.BundlePath, b), nil
}

func bindReplaceIdentity(ctx context.Context, opts BindOptions) (*BindReport, error) {
	b, err := key.ReadBundle(opts.BundlePath)
	if err != nil {
		return nil, err
	}
	lines, err := readIdentityLines(opts.IdentityPaths)
	if err != nil {
		return nil, err
	}
	if err := b.ReplaceIdentities(lines); err != nil {
		return nil, err
	}
	if err := key.Replace(ctx, opts.BundlePath, b, opts.deps.txn); err != nil {
		return nil, err
	}
	return bindReport(opts.BundlePath, b), nil
}

func bindReport(path string, b *key.Bundle) *BindReport {
	return &BindReport{
		Path:       path,
		Recipients: append([]string(nil), b.Recipients...),
		MACKeyID:   hex.EncodeToString(b.MACKeyID),
		Identities: len(b.Identities),
	}
}

func readIdentityLines(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, key.ErrInvalidIdentity
	}
	var lines []string
	for _, path := range paths {
		got, err := identityLinesFromFile(path)
		if err != nil {
			return nil, err
		}
		if len(got) == 0 {
			return nil, key.ErrInvalidIdentity
		}
		lines = append(lines, got...)
	}
	return lines, nil
}

func identityLinesFromFile(path string) ([]string, error) {
	f, err := key.ReadIdentityFile(path)
	defer f.Zero()
	if err != nil {
		return nil, err
	}
	return f.Lines()
}
