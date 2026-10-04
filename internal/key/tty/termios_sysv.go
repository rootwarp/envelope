//go:build aix || linux || solaris

package tty

import "golang.org/x/sys/unix"

// Same split as golang.org/x/term.
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)
