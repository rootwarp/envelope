package key

import "testing"

func TestNilTerminalOwner(t *testing.T) {
	var none *Set
	none.Zero()
	none.Zero()
	(&Set{}).Zero()
	if err := (*ClientUI)(nil).Close(); err != nil {
		t.Fatalf("nil UI close: %v", err)
	}
}
