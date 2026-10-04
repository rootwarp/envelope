package tty

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY returns a pty master and its slave's path: posix_openpt, grantpt,
// unlockpt and ptsname as the three ioctls libc makes for them. The master is
// never put in blocking mode (no Fd call), so read deadlines work on it.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	var name [128]byte
	ptyControl(t, m, func(fd int) error {
		if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
			return err
		}
		if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
			return err
		}
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0])))
		if errno != 0 {
			return errno
		}
		return nil
	})
	n := bytes.IndexByte(name[:], 0)
	if n <= 0 {
		t.Fatal("TIOCPTYGNAME returned no name")
	}
	return m, string(name[:n])
}
