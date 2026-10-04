package tty

import (
	"os"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// openPTY returns a pty master and its slave's path. The master is never
// put in blocking mode (no Fd call), so read deadlines work on it.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	var n int
	ptyControl(t, m, func(fd int) error {
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return err
		}
		n, err = unix.IoctlGetInt(fd, unix.TIOCGPTN)
		return err
	})
	return m, "/dev/pts/" + strconv.Itoa(n)
}
