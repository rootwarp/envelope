package key

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/curve25519"

	"github.com/rootwarp/envelope/internal/key/bech32"
)

func TestCreateRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	want := make([]byte, 32)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Create(path)
	if !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("Create existing: errors.Is(., ErrIdentityExists) = false")
	}
	if errors.Is(err, ErrNotSingleIdentity) || errors.Is(err, ErrNotX25519) || errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("Create existing: error matched a different sentinel")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)
}

func TestLoadRejectsTwoIdentities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	before := []byte(a.String() + "\n" + b.String() + "\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrNotSingleIdentity)
}

func TestLoadRejectsZeroIdentities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	before := []byte("# comment only\n\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrNotSingleIdentity)
}

func TestLoadRejectsNonX25519(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	h, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	before := []byte(h.String() + "\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrNotX25519)
}

func TestLoadRejectsLeadingSpace(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	assertLoadRejectsInvalid(t, []byte(" "+id.String()+"\n"))
}

func TestLoadRejectsBOM(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(id.String() + "\n")
	before := append([]byte{0xEF, 0xBB, 0xBF}, line...)
	assertLoadRejectsInvalid(t, before)
}

func TestLowercasedIdentityRejected(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(id.String())
	if _, err := age.ParseX25519Identity(lower); err == nil {
		t.Fatal("age.ParseX25519Identity accepted a lowercased identity")
	}
	assertLoadRejectsInvalid(t, []byte(lower+"\n"))
}

func TestManifestMACKeyGoldenVector(t *testing.T) {
	scalar, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("d68f03cfc36c743aed580a53bf0cfd2b6a87d3c236a8440da0a8e89b73dd5b62")
	if err != nil {
		t.Fatal(err)
	}
	if len(scalar) != ScalarLen {
		t.Fatalf("scalar len = %d, want %d", len(scalar), ScalarLen)
	}
	if len(want) != MACKeyLen {
		t.Fatalf("want len = %d, want %d", len(want), MACKeyLen)
	}

	var id Identity
	copy(id.scalar[:], scalar)
	got, err := id.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MACKeyLen {
		t.Fatalf("got len = %d, want %d", len(got), MACKeyLen)
	}
	if !hmac.Equal(got, want) {
		t.Errorf("MAC key mismatch: len got=%d want=%d, sha256 got=%x want=%x",
			len(got), len(want), sha256.Sum256(got), sha256.Sum256(want))
	}
}

func TestScalarRoundTrip(t *testing.T) {
	src, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(src.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := scalarFrom(id.age)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(decoded[:], id.scalar[:]) {
		t.Errorf("loaded scalar mismatch: sha256 got=%x want=%x",
			sha256.Sum256(decoded[:]), sha256.Sum256(id.scalar[:]))
	}

	derived, err := curve25519.X25519(decoded[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	hrp, recKey, err := bech32.Decode(id.age.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if hrp != "age" {
		t.Errorf("recipient hrp = %q, want %q", hrp, "age")
	}
	if len(recKey) != 32 {
		t.Fatalf("recipient key len = %d, want 32", len(recKey))
	}
	if !hmac.Equal(derived, recKey) {
		t.Errorf("recipient key material mismatch: len got=%d want=%d, sha256 got=%x want=%x",
			len(derived), len(recKey), sha256.Sum256(derived), sha256.Sum256(recKey))
	}

	reencoded := testBech32Encode(HRP, decoded[:])
	rebuilt, err := age.ParseX25519Identity(reencoded)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("scalar-round-trip")
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, src.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := age.Decrypt(&ct, rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, plain)
}

func scalarFromString(s string) (out [ScalarLen]byte, err error) {
	hrp, data, err := bech32.Decode(strings.TrimSpace(s))
	if err != nil {
		return out, err
	}
	return acceptScalar(hrp, data)
}

func TestHRPMismatch(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = scalarFromString(strings.ToLower(id.String()))
	assertSentinel(t, err, ErrHRPMismatch)
}

func TestScalarLength(t *testing.T) {
	short := testBech32Encode(HRP, make([]byte, ScalarLen-1))
	_, err := scalarFromString(short)
	assertSentinel(t, err, ErrScalarLength)
}

func TestCreatedIdentityAcceptedByAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	if _, err := Create(path); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("ParseIdentities count = %d, want 1", len(ids))
	}
	if _, ok := ids[0].(*age.X25519Identity); !ok {
		t.Fatalf("ParseIdentities type = %T, want *age.X25519Identity", ids[0])
	}

	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func assertLoadRejectsInvalid(t *testing.T, before []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	assertLoadRejects(t, dir, path, before, ErrInvalidIdentity)
}

func assertLoadRejects(t *testing.T, dir, path string, before []byte, want error) {
	t.Helper()
	_, err := Load(path)
	if !errors.Is(err, want) {
		t.Fatalf("errors.Is(., %v) = false", want)
	}
	for _, other := range []error{ErrIdentityExists, ErrNotSingleIdentity, ErrNotX25519, ErrInvalidIdentity, ErrScalarLength, ErrHRPMismatch} {
		if other != want && errors.Is(err, other) {
			t.Fatalf("error also matched %v", other)
		}
	}
	assertNoIdentityPrefix(t, err)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, before)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("dir entries = %d, want 1 (no extra output)", len(entries))
	}
}

func assertNoIdentityPrefix(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	// Split at runtime so tracked files never contain the contiguous FR-24 needle.
	prefix := "AGE-SECRET-KEY-" + "1"
	msg := err.Error()
	if strings.Contains(msg, prefix) || strings.Contains(msg, strings.ToLower(prefix)) {
		t.Fatal("error string contains identity prefix")
	}
}

func assertSameBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	off := -1
	for i := 0; i < min(len(got), len(want)); i++ {
		if got[i] != want[i] {
			off = i
			break
		}
	}
	t.Errorf("payload mismatch: len got=%d want=%d, first diff at %d, sha256 got=%x want=%x",
		len(got), len(want), off, sha256.Sum256(got), sha256.Sum256(want))
}

func assertSentinel(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("errors.Is(., %v) = false", want)
	}
	for _, other := range []error{ErrIdentityExists, ErrNotSingleIdentity, ErrNotX25519, ErrInvalidIdentity, ErrScalarLength, ErrHRPMismatch} {
		if other != want && errors.Is(err, other) {
			t.Fatalf("error also matched %v", other)
		}
	}
	assertNoIdentityPrefix(t, err)
}

func testBech32Encode(hrp string, data []byte) string {
	values := testBits8to5(data)
	hrpLower := strings.ToLower(hrp)
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var b strings.Builder
	b.WriteString(hrpLower)
	b.WriteByte('1')
	for _, v := range values {
		b.WriteByte(charset[v])
	}
	for _, v := range testBech32Checksum(hrpLower, values) {
		b.WriteByte(charset[v])
	}
	s := b.String()
	if strings.ToLower(hrp) != hrp {
		return strings.ToUpper(s)
	}
	return s
}

func testBits8to5(data []byte) []byte {
	var ret []byte
	acc := uint32(0)
	bits := byte(0)
	for _, value := range data {
		acc = acc<<8 | uint32(value)
		bits += 8
		for bits >= 5 {
			bits -= 5
			ret = append(ret, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		ret = append(ret, byte(acc<<(5-bits))&31)
	}
	return ret
}

func testBech32Checksum(hrp string, data []byte) []byte {
	values := append(testHRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := testPolymod(values) ^ 1
	ret := make([]byte, 6)
	for i := range ret {
		ret[i] = byte(mod>>uint(5*(5-i))) & 31
	}
	return ret
}

func testHRPExpand(hrp string) []byte {
	h := []byte(strings.ToLower(hrp))
	ret := make([]byte, 0, len(h)*2+1)
	for _, c := range h {
		ret = append(ret, c>>5)
	}
	ret = append(ret, 0)
	for _, c := range h {
		ret = append(ret, c&31)
	}
	return ret
}

func testPolymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk & 0x1ffffff) << 5
		chk ^= uint32(v)
		for i := range gen {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}
