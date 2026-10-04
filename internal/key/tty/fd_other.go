//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package tty

func dupFD(int) (int, error) { return -1, errUnavailable }

func closeFD(int) error { return nil }

func disableEcho(int) error { return errUnavailable }

func readSecretFD(int) ([]byte, error) { return nil, errUnavailable }
