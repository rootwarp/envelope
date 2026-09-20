//go:build !windows

package tty

import "os"

// Open opens /dev/tty. A failed open is the non-TTY detection.
func Open() (*Terminal, error) {
	// O_RDWR: the prompt is written to the same handle it is read from, so it
	// still appears when stdout is redirected.
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Terminal{f: f}, nil
}
