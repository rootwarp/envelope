package key

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

// identityFileMaxBytes is age.ParseIdentities' own read limit. A tighter cap
// would refuse identity files age itself would parse in full.
const identityFileMaxBytes = 16 << 20 // 16 MiB

// ErrIdentityTooLarge is an identity file over identityFileMaxBytes.
// The file is refused before it is read.
var ErrIdentityTooLarge = errors.New("identity file exceeds size limit")

// IdentityFile holds one identity file's bytes. Those bytes are secret.
// Every caller that owns an IdentityFile must Zero it.
type IdentityFile struct {
	Path string
	data []byte
}

// ReadIdentityFile opens path, fstats, and only then reads.
//
// Open runs before the size check so a missing path reports "open …",
// matching Load, LoadSet, and Recipient. That order is load-bearing for
// the error text. A size over the cap returns before any read, with a nil
// buffer. One slice, sized from the fstat result, receives the read;
// io.ReadAll would abandon earlier chunks that still hold the secret
// after Zero. A one-byte read after that slice catches growth past the
// fstat size. Growth returns ErrIdentityTooLarge with a non-nil empty
// buffer, after the bytes already read are cleared, so it is not the
// fstat refusal. Callers still Zero the file. Zero is safe on a nil file.
func ReadIdentityFile(path string) (*IdentityFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > identityFileMaxBytes {
		return &IdentityFile{Path: path}, ErrIdentityTooLarge
	}

	buf := make([]byte, int(fi.Size()))
	got := 0
	for got < len(buf) {
		n, err := f.Read(buf[got:])
		got += n
		if err != nil {
			if err == io.EOF {
				break
			}
			clear(buf)
			return nil, err
		}
		if n == 0 {
			break
		}
	}

	// Growth past the size we allocated. The extra byte is not part of the
	// buffer Zero will see, so clear it here.
	var extra [1]byte
	n, err := f.Read(extra[:])
	if n > 0 {
		clear(buf)
		clear(extra[:])
		return &IdentityFile{Path: path, data: buf[:0]}, ErrIdentityTooLarge
	}
	if err != nil && err != io.EOF {
		clear(buf)
		return nil, err
	}
	return &IdentityFile{Path: path, data: buf[:got]}, nil
}

// IsBundle reports whether the held bytes start with an identity-bundle header.
func (f *IdentityFile) IsBundle() bool {
	if f == nil {
		return false
	}
	return isBundle(f.data)
}

// Bundle parses the held bytes as a v1 identity bundle. The 64 KiB cap is
// the same rule ReadBundle enforces before reading.
func (f *IdentityFile) Bundle() (*Bundle, error) {
	if f == nil {
		return nil, ErrInvalidIdentity
	}
	b, err := parseBundle(f.data)
	if err != nil {
		return nil, err
	}
	b.Path = f.Path
	return b, nil
}

// Single parses the bytes the way Load does: exactly one X25519 identity.
func (f *IdentityFile) Single() (*Identity, error) {
	if f == nil {
		return nil, ErrInvalidIdentity
	}
	data := f.data
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		if nonCommentLines(data) == 0 {
			return nil, ErrNotSingleIdentity
		}
		// age quotes the identity line; never return or wrap that error.
		return nil, ErrInvalidIdentity
	}
	if len(ids) != 1 {
		return nil, ErrNotSingleIdentity
	}
	x25519, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, ErrNotX25519
	}
	return newIdentity(x25519)
}

// Lines returns the non-empty, non-comment lines, in order.
func (f *IdentityFile) Lines() ([]string, error) {
	if f == nil {
		return nil, ErrInvalidIdentity
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(f.data))
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

// Zero clears the secret bytes. It is safe on a nil file and on a second call.
func (f *IdentityFile) Zero() {
	if f == nil {
		return
	}
	clear(f.data)
	f.data = nil
}

// LoadFiles is LoadSet without the read. The caller owns fs and must Zero
// each file; LoadFiles does not, because the caller may still parse them.
func LoadFiles(fs []*IdentityFile, term TerminalSource, opts ...SetOption) (*Set, error) {
	s := prepareSet(term, len(fs), opts...)
	var natives, plugins []*Identity
	for _, f := range fs {
		var err error
		natives, plugins, err = s.takeFile(f, natives, plugins)
		if err != nil {
			return nil, err
		}
	}
	return s.finish(natives, plugins)
}

func zeroIdentities(groups ...[]*Identity) {
	for _, ids := range groups {
		for _, id := range ids {
			id.Zero()
		}
	}
}
