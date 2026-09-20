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
// package. Tests replace it to assert I-13: every call receives one identity.
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
// and returns the first success. decryptHdr continues only on
// ErrIncorrectIdentity and returns any other error immediately
// (age.go:361-371); for hardware plugins the ordinary backup case — a second
// key in a drawer — is that other kind and is fatal without this loop.
// Failures are joined so one identity cannot suppress the rest.
func (s *Set) DecryptBytes(blob []byte) ([]byte, error) {
	if int64(len(blob)) > crypt.MaxBytes {
		return nil, crypt.ErrBlobTooLarge
	}
	var plain []byte
	err := s.eachIdentity(func(id *Identity, ageID age.Identity) error {
		var err error
		if id.kind == KindPlugin {
			plain, err = decryptPluginBytes(blob, ageID)
			return err
		}
		plain, err = crypt.DecryptBytes(blob, ageID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// DecryptTo streams a payload. open is called once per attempt: a reader
// handed to a failed age.Decrypt has already been consumed past the header.
func (s *Set) DecryptTo(dst io.Writer, open func() io.Reader) (int64, error) {
	var n int64
	err := s.eachIdentity(func(id *Identity, ageID age.Identity) error {
		src := open()
		if id.kind == KindPlugin {
			r, err := decryptOne(src, ageID)
			if err != nil {
				return err
			}
			var copyErr error
			n, copyErr = io.Copy(dst, r)
			return copyErr
		}
		var err error
		n, err = crypt.Decrypt(dst, src, ageID)
		return err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Interactions returns the number of Unwrap attempts made through plugin
// identities in this run — the identity side only. A Wrap also spawns a
// plugin process and calls no Unwrap, so this is deliberately not "processes
// spawned": it is the same quantity §6.3's budget announces, which is why a
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
