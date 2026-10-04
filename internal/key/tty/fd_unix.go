//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package tty

import (
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

// dupFD duplicates fd close-on-exec, under ForkLock so a plugin started
// between the dup and the flag cannot inherit the tty.
func dupFD(fd int) (int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	nfd, err := syscall.Dup(fd)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(nfd)
	return nfd, nil
}

func closeFD(fd int) error { return syscall.Close(fd) }

// disableEcho is the termios change x/term's ReadPassword makes, without the
// read it is bundled with there, so ReadLine can order it against restore.
func disableEcho(fd int) error {
	t, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return err
	}
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	t.Iflag |= unix.ICRNL
	return unix.IoctlSetTermios(fd, ioctlWriteTermios, t)
}

func readSecretFD(fd int) ([]byte, error) { return readSecretLine(fdReader(fd)) }

type fdReader int

func (r fdReader) Read(b []byte) (int, error) {
	n, err := unix.Read(int(r), b)
	if n < 0 {
		n = 0
	}
	if n == 0 && err == nil && len(b) > 0 {
		return 0, io.EOF
	}
	return n, err
}
