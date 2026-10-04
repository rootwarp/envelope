//go:build unix

package tty

import "syscall"

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
