package pipeline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

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

// ObserveBindInteractions receives the pin-unwrap count from add-recipient,
// before Zero. Tests assert interaction counts with it.
var ObserveBindInteractions func(int)

func Bind(ctx context.Context, opts BindOptions, status io.Writer) (*BindReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = status
	switch opts.Mode {
	case BindCreate:
		return bindCreate(opts)
	case BindAddRecipient:
		return bindAddRecipient(opts)
	case BindReplaceIdentity:
		return bindReplaceIdentity(opts)
	default:
		return nil, errBindMode
	}
}

func bindCreate(opts BindOptions) (*BindReport, error) {
	lines, err := readIdentityLines(opts.IdentityPaths)
	if err != nil {
		return nil, err
	}
	// Wrap talks to the plugin client through ClientUI; a nil UI panics
	// even when encryption to a plugin recipient is card-free.
	ui := key.NewClientUI(terminalSource(opts.Terminal))
	rs, err := key.ParseRecipients(opts.Recipients, ui)
	if err != nil {
		return nil, err
	}
	b, err := key.NewBundle(lines, rs)
	if err != nil {
		return nil, err
	}
	if err := key.WriteNew(opts.OutPath, b); err != nil {
		return nil, err
	}
	return bindReport(opts.OutPath, b), nil
}

func bindAddRecipient(opts BindOptions) (*BindReport, error) {
	b, err := key.ReadBundle(opts.BundlePath)
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

	src := terminalSource(opts.Terminal)
	set, err := key.LoadSet([]string{opts.BundlePath}, src)
	if err != nil {
		return nil, err
	}
	defer set.Zero()
	if err := refuseInteractiveWithoutTerminal(set, src); err != nil {
		return nil, err
	}
	if err := b.AddRecipients(set, extra); err != nil {
		return nil, err
	}
	if ObserveBindInteractions != nil {
		ObserveBindInteractions(set.Interactions())
	}
	if err := key.Replace(opts.BundlePath, b); err != nil {
		return nil, err
	}
	return bindReport(opts.BundlePath, b), nil
}

func bindReplaceIdentity(opts BindOptions) (*BindReport, error) {
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
	if err := key.Replace(opts.BundlePath, b); err != nil {
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
