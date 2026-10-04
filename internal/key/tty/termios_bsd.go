//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package tty

import "golang.org/x/sys/unix"

// Same split as golang.org/x/term.
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
