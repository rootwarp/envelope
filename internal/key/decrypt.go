package key

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"

	"filippo.io/age"

	"github.com/rootwarp/envelope/internal/crypt"
)

// decryptAge is the single production call site for age.Decrypt in this
// package. Tests replace it to assert every call receives one identity.
var decryptAge = func(r io.Reader, ids ...age.Identity) (io.Reader, error) {
	if len(ids) != 1 {
		return nil, errors.New("age.Decrypt must receive exactly one identity")
	}
	return age.Decrypt(r, ids[0])
}

func decryptOne(r io.Reader, id age.Identity) (io.Reader, error) {
	return decryptAge(r, id)
}

// pluginIdentity records Unwrap's outcome so diagnose can tell three cases
// apart: age refused the file before consulting any identity (not attempted
// → crypt.ErrMalformedAge); the plugin refused (attempted, err →
// ErrPluginFailed / ErrPluginNotInstalled / ErrPluginProtocol); the plugin
// unwrapped and the payload failed later (attempted, no err → the payload
// error, unchanged). Classification is by that outcome, never by call count
// and never by matching the plugin's prose.
type pluginIdentity struct {
	inner age.Identity
	st    *attemptState
	n     *atomic.Int32
}

var _ age.Identity = (*pluginIdentity)(nil)

func (p *pluginIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	p.st.mu.Lock()
	p.st.attempted = true
	p.st.mu.Unlock()
	if p.n != nil {
		p.n.Add(1)
	}
	fileKey, err := p.inner.Unwrap(stanzas)
	p.st.mu.Lock()
	p.st.err = err
	p.st.mu.Unlock()
	return fileKey, err
}

// DecryptBytes tries each identity in its own age.Decrypt call, in Set order,
// and returns the first success. The identity that succeeded is discarded;
// manifest opening uses decryptBytes so the MAC key can follow that identity.
func (s *Set) DecryptBytes(blob []byte) ([]byte, error) {
	plain, _, err := s.decryptBytes(blob)
	return plain, err
}

// decryptBytes is DecryptBytes plus the identity whose attempt succeeded.
// eachIdentity returns nil only after the last attempt it ran succeeded, so
// the identity captured in that closure is the one that opened the blob.
// decryptHdr continues only on ErrIncorrectIdentity and returns any other
// error immediately (age.go:361-371); for hardware plugins the ordinary
// backup case — a second key in a drawer — is that other kind and is fatal
// without this loop. Failures are joined so one identity cannot suppress the rest.
func (s *Set) decryptBytes(blob []byte) ([]byte, *Identity, error) {
	if int64(len(blob)) > crypt.MaxBytes {
		return nil, nil, crypt.ErrBlobTooLarge
	}
	var (
		plain  []byte
		opener *Identity
	)
	err := s.eachIdentity(func(id *Identity, ageID age.Identity) error {
		var err error
		if id.kind == KindPlugin {
			plain, err = decryptPluginBytes(blob, ageID)
		} else {
			plain, err = crypt.DecryptBytes(blob, ageID)
		}
		if err != nil {
			return err
		}
		opener = id
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return plain, opener, nil
}

// DecryptTo streams a payload in two phases. Selection tries identities until
// one yields a reader; the copy to dst runs only after that, and only once.
// The boundary is that reader rather than the first byte written: a chunk
// that fails authentication emits nothing, but the same ciphertext fails
// under every identity, so a later attempt cannot succeed and must not append
// a second plaintext after a partial write. open is called once per attempt
// because a reader handed to a rejected header has already been consumed.
func (s *Set) DecryptTo(dst io.Writer, open func() io.Reader) (int64, error) {
	var payload io.Reader
	err := s.eachIdentity(func(id *Identity, ageID age.Identity) error {
		var err error
		if id.kind == KindPlugin {
			payload, err = decryptOne(open(), ageID)
		} else {
			payload, err = crypt.Open(open(), ageID)
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	return io.Copy(dst, payload)
}

// Interactions returns the number of Unwrap attempts made through plugin
// identities in this run — the identity side only. A Wrap also spawns a
// plugin process and calls no Unwrap, so this is deliberately not "processes
// spawned": it is the same quantity the interaction-budget line announces, which is why a
// test may compare the two. Tests assert budgets with it; no production path
// may branch on it.
func (s *Set) Interactions() int {
	if s == nil {
		return 0
	}
	return int(s.interactions.Load())
}

func (s *Set) eachIdentity(try func(*Identity, age.Identity) error) error {
	if s == nil || len(s.ids) == 0 {
		return crypt.ErrWrongIdentity
	}
	var errs []error
	for i, id := range s.ids {
		ageID := id.unwrapIdentity()
		if ageID == nil {
			errs = append(errs, crypt.ErrWrongIdentity)
			continue
		}
		id.resetAttempt()
		if id.kind == KindPlugin {
			// The gate runs before the attempt is begun and before the terminal is resolved.
			if cerr := s.ctxErr(); cerr != nil {
				errs = append(errs, cerr)
				return errors.Join(errs...)
			}
			if s.ui == nil {
				errs = append(errs, ErrNoTerminal)
				continue
			}
			// moreUntried drives skip-vs-insert: offer skip while another
			// identity remains; wait on the last.
			s.ui.beginAttempt(id.pluginName, id.source, i < len(s.ids)-1)
			if _, err := s.ui.terminal(); err != nil {
				_ = s.ui.endAttempt()
				errs = append(errs, err)
				continue
			}
		}
		err := try(id, ageID)
		if id.kind == KindPlugin {
			classified := diagnose(id, err)
			insertErr := s.ui.endAttempt()
			id.attempt.mu.Lock()
			id.attempt.err = errors.Join(id.attempt.err, insertErr)
			id.attempt.mu.Unlock()
			err = errors.Join(classified, insertErr)
		}
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func decryptPluginBytes(blob []byte, id age.Identity) ([]byte, error) {
	r, err := decryptOne(bytes.NewReader(blob), id)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(r, crypt.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(plain)) > crypt.MaxBytes {
		return nil, crypt.ErrBlobTooLarge
	}
	return plain, nil
}

func (id *Identity) unwrapIdentity() age.Identity {
	if id == nil {
		return nil
	}
	if id.plugin != nil {
		return id.plugin
	}
	if id.age != nil {
		return id.age
	}
	return id.native
}

func (id *Identity) resetAttempt() {
	id.attempt.mu.Lock()
	id.attempt.attempted = false
	id.attempt.err = nil
	id.attempt.mu.Unlock()
}
