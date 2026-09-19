package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/urfave/cli/v3"
)

// TestMain is the package's only TestMain. OsExiter is set once here, never
// from run, so a library os.Exit fails the suite with the code (FR-P2-03).
func TestMain(m *testing.M) {
	cli.OsExiter = func(code int) { panic(fmt.Sprintf("urfave reached os.Exit(%d)", code)) }
	os.Exit(m.Run())
}
