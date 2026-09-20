package key

import (
	"os"
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
