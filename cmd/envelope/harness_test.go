package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

// TestMain is the package's only TestMain. OsExiter is set once here, never
// from run, so a library os.Exit fails the suite with the code (FR-P2-03).
func TestMain(m *testing.M) {
	if fakeplugin.Dispatch() {
		return
	}
	cli.OsExiter = func(code int) { panic(fmt.Sprintf("urfave reached os.Exit(%d)", code)) }
	// Inherited AGEDEBUG=plugin would write a warning on every run() stderr,
	// including help. Tests that need the warning call t.Setenv themselves.
	_ = os.Setenv("AGEDEBUG", "")
	os.Exit(m.Run())
}

func TestDispatchNoOp(t *testing.T) {
	if fakeplugin.Dispatch() {
		t.Fatal("Dispatch returned true for the test binary")
	}
}
