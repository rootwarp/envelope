package key

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"filippo.io/age/plugin"
)

// InsertRoundCap is the number of times Confirm answers yes to an insert
// prompt for one identity. The next answer is no, not fail.
const InsertRoundCap = 3

const insertRetryDelay = time.Second

// ErrInsertRounds is returned by endAttempt when Confirm answered no because
// the insert-round cap was reached. The error's message names the plugin
// binary, not a device.
var ErrInsertRounds = errors.New("gave up waiting for age-plugin after 3 attempts")

// ClientUI is Envelope's plugin UI. NewClientUI is the only constructor and it
// assigns all four callbacks unconditionally, so Confirm is never nil: a nil or
// erroring callback makes the client answer fail, not unsupported
// (plugin/client.go:362-364), which turns "the card isn't plugged in" into a
// fatal error and makes the plugin's own retry path unreachable.
//
// Affirmative insert rounds are capped at InsertRoundCap. At the cap the UI
// answers no, not fail: no becomes Ok(None) and age.ErrIncorrectIdentity, so
// remaining identities are still tried.
type ClientUI struct {
	plugin.ClientUI

	term TerminalSource
	mu   sync.Mutex // WaitTimer runs on age's goroutine (plugin/client.go:392-397)
	cur  attemptInfo

	rounds int
	hitCap bool

	got    Terminal
	gotErr error
	termOK bool
}

type attemptInfo struct {
	name        string
	source      string
	moreUntried bool
}

// NewClientUI returns a ClientUI with DisplayMessage, RequestValue, Confirm
// and WaitTimer all set. A nil source fails closed as ErrNoTerminal on first use.
func NewClientUI(term TerminalSource) *ClientUI {
	u := &ClientUI{term: term}
	u.DisplayMessage = u.displayMessage
	u.RequestValue = u.requestValue
	u.Confirm = u.confirm
	u.WaitTimer = u.waitTimer
	return u
}

// beginAttempt brackets one identity's Unwrap. moreUntried makes Confirm offer
// skip and default toward it; on the last identity the insert prompt is waited on.
func (u *ClientUI) beginAttempt(name, source string, moreUntried bool) {
	u.mu.Lock()
	u.cur = attemptInfo{name: name, source: source, moreUntried: moreUntried}
	u.rounds = 0
	u.hitCap = false
	u.mu.Unlock()
	_, _ = u.terminal()
}

// endAttempt returns ErrInsertRounds when this attempt hit the insert cap.
func (u *ClientUI) endAttempt() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	name := u.cur.name
	hit := u.hitCap
	u.cur = attemptInfo{}
	u.rounds = 0
	u.hitCap = false
	if hit {
		return errInsertRounds(name)
	}
	return nil
}

func (u *ClientUI) terminal() (Terminal, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.termOK {
		return u.got, u.gotErr
	}
	u.termOK = true
	if u.term == nil {
		u.gotErr = ErrNoTerminal
		return nil, u.gotErr
	}
	t, err := u.term()
	if err != nil {
		u.gotErr = err
		return nil, err
	}
	if t == nil {
		u.gotErr = ErrNoTerminal
		return nil, u.gotErr
	}
	u.got = t
	return t, nil
}

func (u *ClientUI) displayMessage(_, message string) error {
	t, err := u.terminal()
	if err != nil {
		return err
	}
	t.Notify(message)
	return nil
}

func (u *ClientUI) requestValue(_ string, prompt string, secret bool) (string, error) {
	t, err := u.terminal()
	if err != nil {
		return "", err
	}
	// Value is returned only to the caller (age writes it as the ok stanza body).
	s, err := t.ReadLine(prompt, secret)
	if err != nil {
		return "", err
	}
	return s, nil
}

func (u *ClientUI) confirm(_, prompt, yes, no string) (bool, error) {
	t, err := u.terminal()
	if err != nil {
		return false, err
	}

	u.mu.Lock()
	more := u.cur.moreUntried
	round := u.rounds
	u.mu.Unlock()

	if more {
		t.Notify(confirmLine(prompt, yes, no, true))
		return false, nil
	}
	if round >= InsertRoundCap {
		u.mu.Lock()
		u.hitCap = true
		u.mu.Unlock()
		return false, nil
	}

	t.Notify(confirmLine(prompt, yes, no, false))
	// Back-off only; the cap is the bound, so drop the delay before the cap.
	if round > 0 {
		time.Sleep(insertRetryDelay)
	}

	u.mu.Lock()
	u.rounds++
	u.mu.Unlock()
	return true, nil
}

func (u *ClientUI) waitTimer(name string) {
	u.mu.Lock()
	t := u.got
	u.mu.Unlock()
	if t == nil {
		return
	}
	t.Notify("waiting on age-plugin-" + name + "...")
}

func confirmLine(prompt, yes, no string, offerSkip bool) string {
	if offerSkip && no != "" {
		return prompt + " (" + yes + " / " + no + ")"
	}
	return prompt
}

func errInsertRounds(name string) error {
	return &insertRoundsError{name: name}
}

type insertRoundsError struct {
	name string
}

func (e *insertRoundsError) Error() string {
	return fmt.Sprintf("gave up waiting for age-plugin-%s after %d attempts", e.name, InsertRoundCap)
}

func (e *insertRoundsError) Unwrap() error {
	return ErrInsertRounds
}
