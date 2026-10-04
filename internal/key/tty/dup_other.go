//go:build !unix

package tty

func dupFD(int) (int, error) { return -1, errUnavailable }

func closeFD(int) error { return nil }
