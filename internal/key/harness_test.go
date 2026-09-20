package key

import (
	"os"
	"runtime"
	"testing"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestMain(m *testing.M) {
	if fakeplugin.Dispatch() {
		return
	}
	os.Exit(m.Run())
}

func TestDispatchNoOp(t *testing.T) {
	if fakeplugin.Dispatch() {
		t.Fatal("Dispatch returned true for the test binary")
	}
}

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows support is TODO")
	}
}
