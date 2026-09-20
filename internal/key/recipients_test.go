package key

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rootwarp/envelope/internal/crypt"
)

func TestNewRecipientSetRecordsString(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)

	rs, err := NewRecipientSet(id)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Len() != 1 {
		t.Fatalf("Len = %d, want 1", rs.Len())
	}
	want, err := id.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	got := rs.Strings()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Strings = %d entries, want the identity recipient", len(got))
	}
	got[0] = "mutated"
	if rs.Strings()[0] == "mutated" {
		t.Fatal("Strings aliases the internal slice")
	}

	plain := []byte("recipient-set")
	ct, err := rs.EncryptBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := id.DecryptBytes(ct)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)
}

func TestParseNativeRecipientsTwoEitherDecrypts(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Zero)
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Zero)

	sa, err := a.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ParseNativeRecipients([]string{sa, sb, sa})
	if err != nil {
		t.Fatal(err)
	}
	if rs.Len() != 2 {
		t.Fatalf("Len = %d, want 2 after dedup", rs.Len())
	}
	got := rs.Strings()
	if got[0] != sa || got[1] != sb {
		t.Fatal("Strings reordered or dropped a native recipient")
	}

	plain := []byte("two-native")
	var ct bytes.Buffer
	if _, err := rs.Encrypt(&ct, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}

	out, err := a.DecryptBytes(ct.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)
	out, err = b.DecryptBytes(ct.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, out, plain)

	other, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Zero)
	if _, err := other.DecryptBytes(ct.Bytes()); !errors.Is(err, crypt.ErrWrongIdentity) {
		t.Fatalf("third identity: errors.Is(., ErrWrongIdentity) = false")
	}
}
