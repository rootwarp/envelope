// Package pipeline owns split/restore/keygen filesystem layout, modes, and ordering.
package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rootwarp/envelope/internal/erasure"
	"github.com/rootwarp/envelope/internal/filetxn"
	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

type SplitOptions struct {
	IdentityPath string
	Recipients   []string // public recipient strings, never an age type
	InPath       string
	OutDir       string
	K, N         int
	Terminal     Terminal
	deps         deps
}

// SplitReport carries counts, indices and paths only. No field may ever hold
// payload bytes.
type SplitReport struct {
	OutDir        string
	K, N          int
	CiphertextLen int64
	StripeLen     int64
}

// ValidateKN is erasure.Validate, exported so cmd can map (k, n) failures
// to usage without importing erasure (D3).
func ValidateKN(k, n int) error {
	return erasure.Validate(k, n)
}

// ObserveSplitInteractions receives the identity-side Unwrap count after Split
// returns, before Zero. Tests assert v1=0 / v2=p·q with it.
var ObserveSplitInteractions func(int)

func Split(ctx context.Context, opts SplitOptions, status io.Writer) (*SplitReport, error) {
	// Validate before any filesystem call so a bad (k, n) cannot leave a
	// half-created directory.
	if err := ValidateKN(opts.K, opts.N); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sess := newSession(ctx, opts.Terminal, opts.deps, status)
	defer sess.Close()

	// One read for this path. v1's MAC identity is the scalar parsed into the
	// set; a second Load would hold another copy of it.
	f, err := key.ReadIdentityFile(opts.IdentityPath)
	defer f.Zero()
	if err != nil {
		return nil, err
	}
	set, err := sess.loadFiles([]*key.IdentityFile{f})
	if err != nil {
		return nil, err
	}
	if ObserveSplitInteractions != nil {
		defer func() { ObserveSplitInteractions(set.Interactions()) }()
	}

	// One invocation-level boolean, decided before -in or -out is touched.
	v1 := set.BareFileIdentity() && len(opts.Recipients) == 0

	var (
		macKey   []byte
		macKeyID []byte
		rs       *key.RecipientSet
	)
	if v1 {
		id := set.Identities()[0]
		macKey, err = id.ManifestMACKey()
		if err != nil {
			return nil, err
		}
		defer func() {
			// Best-effort: hkdf.Key returns a fresh slice the GC may already have copied.
			clear(macKey)
		}()
		rs, err = key.NewRecipientSet(id)
		if err != nil {
			return nil, err
		}
	} else {
		recStrs := opts.Recipients
		if len(recStrs) == 0 {
			recStrs = set.RecordedRecipients()
		}
		if len(recStrs) == 0 {
			// LoadSet accepts files Load rejects (two identities, a hybrid, …).
			// Single is Load's parser, so those sentinels stay Load's.
			id, err := f.Single()
			if err != nil {
				return nil, err
			}
			id.Zero()
			return nil, key.ErrNoPin
		}
		ui := key.NewClientUI(sess.source())
		defer ui.Close() // Wrap may prompt on the borrowed handle; this only drops the UI cache. The session closes the fd.
		rs, err = key.ParseRecipients(recStrs, ui)
		if err != nil {
			return nil, err
		}
	}

	warnSolePluginRecipient(rs, status)
	warnDisjointRecipients(opts.Recipients, set.RecordedRecipients(), status)

	if entries, err := os.ReadDir(opts.OutDir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrOutDirNotEmpty, opts.OutDir)
	}
	if err := mkdirAllDurable(opts.OutDir, 0o700, sess.deps.txn); err != nil {
		return nil, err
	}
	// 0700 &^ umask is 0700 for every realistic umask; Chmod is belt, kept
	// for symmetry with the 0644 writes that umask can actually degrade.
	if err := os.Chmod(opts.OutDir, 0o700); err != nil {
		return nil, err
	}

	// The transaction removes only what it created. Error paths deliberately
	// do not abort, so a crash between the shards and the manifest still
	// leaves the shards. Restore aborts until Commit publishes its partial.
	txn := filetxn.Begin(opts.OutDir, sess.deps.txn)

	in, err := os.Open(opts.InPath)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	var buf bytes.Buffer
	var ciphertextLen int64
	if testInjectCiphertext != nil {
		buf.Write(testInjectCiphertext())
		ciphertextLen = int64(buf.Len())
	} else {
		ciphertextLen, err = rs.Encrypt(&buf, ctxReader(ctx, in))
		if err != nil {
			return nil, err
		}
	}
	if err := abortCanceledSplit(ctx, txn); err != nil {
		return nil, err
	}
	if testAtCiphertext != nil {
		testAtCiphertext(buf.Bytes())
	}

	// reedsolomon's ErrShortData names neither the parameter nor the file. Envelope's own
	// message names both numbers. erasure.Split carries ErrCiphertextTooShort as the
	// backstop so the rule holds even if a future caller skips this check.
	if ciphertextLen < int64(opts.K) {
		return nil, fmt.Errorf("ciphertext is %d bytes, shorter than k=%d", ciphertextLen, opts.K)
	}

	if !v1 {
		// This is the only point where the pin may be unwrapped: after the
		// payload is encrypted to the recorded recipients and before the
		// first shard is written. Abort removes only paths this call created,
		// and nothing has been created yet.
		if err := refuseInteractiveWithoutTerminal(set, sess); err != nil {
			_ = txn.Abort()
			return nil, err
		}
		macKey, err = set.KeyFor(manifest.VersionPin, manifest.MACSourcePin)
		if err != nil {
			_ = txn.Abort()
			return nil, pinErr(err)
		}
		defer clear(macKey)
		macKeyID, err = set.KeyIDFor(manifest.VersionPin, manifest.MACSourcePin)
		if err != nil {
			_ = txn.Abort()
			return nil, pinErr(err)
		}
	}

	enc, err := erasure.New(opts.K, opts.N)
	if err != nil {
		return nil, err
	}
	shards, stripeLen, err := enc.Split(buf.Bytes())
	if err != nil {
		return nil, err
	}

	digests := make([][]byte, opts.N)
	for i, shard := range shards {
		if testBeforeShardWrite != nil {
			testBeforeShardWrite(i)
		}
		if err := abortCanceledSplit(ctx, txn); err != nil {
			return nil, err
		}
		d, err := writeShard(txn, opts.OutDir, i, shard)
		if err != nil {
			return nil, err
		}
		digests[i] = d
	}

	fields := manifest.Fields{
		Version:       manifest.Version,
		K:             opts.K,
		N:             opts.N,
		CiphertextLen: ciphertextLen,
		StripeLen:     stripeLen,
		Digests:       digests,
	}
	if !v1 {
		fields.Version = manifest.VersionPin
		fields.MACSource = manifest.MACSourcePin
		fields.MACKeyID = macKeyID
	}
	sealed, err := manifest.Seal(fields, macKey, rs)
	if err != nil {
		return nil, err
	}

	if err := abortCanceledSplit(ctx, txn); err != nil {
		return nil, err
	}
	if err := txn.SyncDir(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDirSync, opts.OutDir, err)
	}

	// Commit marker: a crash between the last shard and this write leaves
	// unusable ciphertext, never a false success. The marker is published by
	// rename after the tmp file is synced. This return does not abort.
	if testFailManifestWrite != nil {
		if err := testFailManifestWrite(); err != nil {
			return nil, err
		}
	}
	manPath := filepath.Join(opts.OutDir, "manifest.age")
	tmpPath := manPath + ".tmp"
	if err := writeExclusive(txn, tmpPath, bytes.NewReader(sealed), nil); err != nil {
		return nil, err
	}
	// Commit checks ctx immediately before the rename. A cancellation aborts
	// and removes only paths this call created. A rename or directory-sync
	// failure does not: the shards stay.
	if err := txn.Commit(ctx, tmpPath, manPath); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			_ = txn.Abort()
			return nil, err
		}
		if _, statErr := os.Lstat(tmpPath); errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s: %w", ErrDirSync, opts.OutDir, err)
		}
		return nil, err
	}

	if status != nil {
		fmt.Fprintf(status, "encrypted %d bytes\n", ciphertextLen)
		fmt.Fprintf(status, "wrote %d shards to %s\n", opts.N, opts.OutDir)
	}

	return &SplitReport{
		OutDir:        opts.OutDir,
		K:             opts.K,
		N:             opts.N,
		CiphertextLen: ciphertextLen,
		StripeLen:     stripeLen,
	}, nil
}

// testFailManifestWrite, when set, runs after shards are on disk and before
// manifest.age is created. Tests inject a crash in that window.
var testFailManifestWrite func() error

// testAtCiphertext observes the ciphertext after Encrypt. Tests record its
// SHA-256 to assert Join used the manifest length.
var testAtCiphertext func([]byte)

// testInjectCiphertext, when set, replaces crypt.Encrypt. Tests inject a
// closeless age stream so Split records the short counted length.
var testInjectCiphertext func() []byte

// testBeforeShardWrite runs at the start of each shard write. Tests cancel ctx
// after the first shard to prove incomplete output is removed.
var testBeforeShardWrite func(i int)

const solePluginWarningFmt = "only one recipient (%s): if that key is lost, reset or replaced by a firmware recall, this payload is gone. `envelope bind -add-recipient` adds a recovery recipient, but only for future splits.\n"

func warnSolePluginRecipient(rs *key.RecipientSet, status io.Writer) {
	if status == nil || rs == nil {
		return
	}
	if _, ok := rs.SolePlugin(); !ok {
		return
	}
	strs := rs.Strings()
	if len(strs) != 1 {
		return
	}
	fmt.Fprintf(status, solePluginWarningFmt, strs[0])
}

func warnDisjointRecipients(chosen, recorded []string, status io.Writer) {
	if status == nil || len(chosen) == 0 || len(recorded) == 0 {
		return
	}
	if sharesRecipient(chosen, recorded) {
		return
	}
	fmt.Fprintln(status, "recipient set shares no string with the bundle; a bundle identity will not restore this payload")
}

func sharesRecipient(a, b []string) bool {
	seen := make(map[string]struct{}, len(b))
	for _, s := range b {
		seen[s] = struct{}{}
	}
	for _, s := range a {
		if _, ok := seen[s]; ok {
			return true
		}
	}
	return false
}

func pinErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, key.ErrPinCorrupt) || errors.Is(err, key.ErrNoPin) || errors.Is(err, key.ErrAmbiguousPin) {
		return err
	}
	return fmt.Errorf("identity bundle pin: %w", err)
}

func abortCanceledSplit(ctx context.Context, txn *filetxn.Txn) error {
	if err := ctx.Err(); err != nil {
		_ = txn.Abort()
		return err
	}
	return nil
}

func shardFileName(i int) string {
	return fmt.Sprintf("shard-%02d", i)
}

func writeShard(txn *filetxn.Txn, dir string, i int, data []byte) ([]byte, error) {
	h := erasure.NewDigest()
	path := filepath.Join(dir, shardFileName(i))
	if err := writeExclusive(txn, path, bytes.NewReader(data), h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func writeExclusive(txn *filetxn.Txn, path string, r io.Reader, extra io.Writer) error {
	// O_EXCL: never truncate a file that appeared after the empty-dir listing.
	// The manifest rename is the commit; this path stays owned until then so
	// a cancel can still remove it.
	f, err := txn.Create(path, 0o644)
	if err != nil {
		return err
	}
	w := io.Writer(f)
	if extra != nil {
		w = io.MultiWriter(f, extra)
	}
	_, copyErr := io.Copy(w, r)
	if copyErr != nil {
		f.Close()
		return copyErr
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// 0644 &^ umask degrades under umask 0027/0077; Chmod is the call that fires.
	return os.Chmod(path, 0o644)
}

func mkdirAllDurable(path string, perm os.FileMode, txn filetxn.Options) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil
	}
	st, err := os.Stat(path)
	if err == nil {
		if st.IsDir() {
			return nil
		}
		return fmt.Errorf("mkdir %s: not a directory", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	if parent != path {
		if err := mkdirAllDurable(parent, perm, txn); err != nil {
			return err
		}
	}
	if err := os.Mkdir(path, perm); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return filetxn.Begin(parent, txn).SyncDir()
}

var (
	ErrOutDirNotEmpty   = errors.New("output directory is not empty")
	ErrPartialExists    = errors.New("a .partial file from a previous run is present")
	ErrNoManifest       = errors.New("no manifest.age in the shard directory")
	ErrStaleManifest    = errors.New("no shard matched the manifest")
	ErrDirSync          = errors.New("output written but directory could not be synced")
	ErrManifestTooLarge = errors.New("manifest.age exceeds size limit")
)
