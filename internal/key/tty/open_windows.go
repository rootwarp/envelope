//go:build windows

package tty

func Open() (*Terminal, error) {
	return nil, errUnavailable
}
