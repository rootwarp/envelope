//go:build unix

package fakeplugin

import (
	"syscall"
	"testing"
)

// LivePIDs returns recorded plugin PIDs that still exist. Envelope does not
// own these processes; tests use this to assert none survived an interrupt.
func LivePIDs(t *testing.T) []int {
	t.Helper()
	var live []int
	for _, pid := range PIDs(t) {
		if err := syscall.Kill(pid, 0); err == nil {
			live = append(live, pid)
		}
	}
	return live
}
