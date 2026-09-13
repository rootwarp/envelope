package manifest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"filippo.io/age"

	"github.com/rootwarp/envelope/internal/crypt"
	"github.com/rootwarp/envelope/internal/key"
)

func TestMACInputGoldenVector(t *testing.T) {
	// M0.3 measured vector; this test is the frozen wire format.
	want, err := hex.DecodeString("00000001000000030000000500000000001000000000000000055556000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 188 {
		t.Fatalf("golden macInput len = %d, want 188", len(want))
	}
	macKey, err := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	if err != nil {
		t.Fatal(err)
	}
	if len(macKey) != MACLen {
		t.Fatalf("mac key len = %d, want %d", len(macKey), MACLen)
	}
	wantMAC, err := hex.DecodeString("b8122203093f5e00c4f8bc529214a387b3206db4b5960f62b68a74ceb831cc84")
	if err != nil {
		t.Fatal(err)
	}
	if len(wantMAC) != MACLen {
		t.Fatalf("golden MAC len = %d, want %d", len(wantMAC), MACLen)
	}

	got, err := golden35().macInput()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 188 {
		t.Fatalf("macInput len = %d, want 188", len(got))
	}
	if !hmac.Equal(got, want) {
		t.Errorf("macInput mismatch: len got=%d want=%d, sha256 got=%x want=%x",
			len(got), len(want), sha256.Sum256(got), sha256.Sum256(want))
	}

	h := hmac.New(sha256.New, macKey)
	h.Write(got)
	tag := h.Sum(nil)
	if !hmac.Equal(tag, wantMAC) {
		t.Errorf("HMAC mismatch: len got=%d want=%d, sha256 got=%x want=%x",
			len(tag), len(wantMAC), sha256.Sum256(tag), sha256.Sum256(wantMAC))
	}
}

func TestMACInputLength(t *testing.T) {
	for _, n := range []int{2, 4, 5, 16, 256} {
		t.Run("n="+strconv.Itoa(n), func(t *testing.T) {
			in, err := shaped(1, n).macInput()
			if err != nil {
				t.Fatal(err)
			}
			want := 28 + 32*n
			if len(in) != want {
				t.Errorf("len(macInput) = %d, want %d", len(in), want)
			}
		})
	}
}

func TestMACInputFieldOffsets(t *testing.T) {
	m := Manifest{
		Version:       0x01020304,
		K:             3,
		N:             5,
		CiphertextLen: 0x1112131415161718,
		StripeLen:     0x2122232425262728,
		Digests:       make([][]byte, 5),
		MAC:           make([]byte, MACLen),
	}
	for i := range m.Digests {
		d := make([]byte, DigestLen)
		for j := range d {
			d[j] = byte(0xa0 + i)
		}
		m.Digests[i] = d
	}

	in, err := m.macInput()
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 28+32*m.N {
		t.Fatalf("macInput len = %d, want %d", len(in), 28+32*m.N)
	}
	if v := binary.BigEndian.Uint32(in[0:4]); v != m.Version {
		t.Errorf("version@0 = %d, want %d", v, m.Version)
	}
	if v := binary.BigEndian.Uint32(in[4:8]); v != uint32(m.K) {
		t.Errorf("k@4 = %d, want %d", v, m.K)
	}
	if v := binary.BigEndian.Uint32(in[8:12]); v != uint32(m.N) {
		t.Errorf("n@8 = %d, want %d", v, m.N)
	}
	if v := binary.BigEndian.Uint64(in[12:20]); v != uint64(m.CiphertextLen) {
		t.Errorf("ciphertext_len@12 = %d, want %d", v, m.CiphertextLen)
	}
	if v := binary.BigEndian.Uint64(in[20:28]); v != uint64(m.StripeLen) {
		t.Errorf("stripe_len@20 = %d, want %d", v, m.StripeLen)
	}
	for i, d := range m.Digests {
		off := 28 + 32*i
		got := in[off : off+DigestLen]
		if !hmac.Equal(got, d) {
			t.Errorf("digests[%d]@%d mismatch: len got=%d want=%d, sha256 got=%x want=%x",
				i, off, len(got), len(d), sha256.Sum256(got), sha256.Sum256(d))
		}
	}
}

func TestValidateShape(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Manifest)
	}{
		{"len(Digests)!=N", func(m *Manifest) { m.Digests = m.Digests[:len(m.Digests)-1] }},
		{"31-byte digest", func(m *Manifest) { m.Digests[0] = m.Digests[0][:31] }},
		{"33-byte digest", func(m *Manifest) { m.Digests[0] = append(append([]byte{}, m.Digests[0]...), 0x00) }},
		{"len(MAC)!=32", func(m *Manifest) { m.MAC = m.MAC[:31] }},
		{"K<1", func(m *Manifest) { m.K = 0 }},
		{"K negative", func(m *Manifest) { m.K = -1 }},
		{"N<=K", func(m *Manifest) {
			m.N = m.K
			m.Digests = m.Digests[:m.N]
		}},
		{"N>256", func(m *Manifest) {
			m.K = 1
			m.N = 257
			m.Digests = make([][]byte, 257)
			for i := range m.Digests {
				m.Digests[i] = make([]byte, DigestLen)
			}
		}},
		{"negative CiphertextLen", func(m *Manifest) { m.CiphertextLen = -1 }},
		{"negative StripeLen", func(m *Manifest) { m.StripeLen = -1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := golden35()
			tt.mod(m)
			if err := m.validateShape(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("validateShape: errors.Is(., ErrMalformed) = false")
			}
			in, err := m.macInput()
			if in != nil {
				t.Errorf("macInput slice len = %d, want nil", len(in))
			}
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("macInput: errors.Is(., ErrMalformed) = false")
			}
		})
	}
}

func TestStripeLen(t *testing.T) {
	tests := []struct {
		ciphertextLen int64
		k             int
		want          int64
	}{
		{0, 3, 0},
		{0, 1, 0},
		{1, 3, 1},
		{2, 3, 1},
		{3, 3, 1},
		{4, 3, 2},
		{9, 3, 3},
		{10, 3, 4},
		{100, 7, 15},
		{1048576, 3, 349526},
		{1, 1, 1},
		{10, 1, 10},
	}
	for _, tt := range tests {
		got := StripeLen(tt.ciphertextLen, tt.k)
		if got != tt.want {
			t.Errorf("StripeLen(%d, %d) = %d, want %d", tt.ciphertextLen, tt.k, got, tt.want)
		}
	}
}

func golden35() *Manifest {
	digests := make([][]byte, 5)
	b := byte(0)
	for i := range digests {
		d := make([]byte, DigestLen)
		for j := range d {
			d[j] = b
			b++
		}
		digests[i] = d
	}
	return &Manifest{
		Version:       Version,
		K:             3,
		N:             5,
		CiphertextLen: 1048576,
		StripeLen:     349526,
		Digests:       digests,
		MAC:           make([]byte, MACLen),
	}
}

func shaped(k, n int) *Manifest {
	m := &Manifest{
		Version: Version,
		K:       k,
		N:       n,
		Digests: make([][]byte, n),
		MAC:     make([]byte, MACLen),
	}
	for i := range m.Digests {
		m.Digests[i] = make([]byte, DigestLen)
	}
	return m
}

func TestSealOpenRoundTrip(t *testing.T) {
	macKey, id, r := testKey(t)
	want := golden35()
	blob, err := Seal(want, macKey, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) == 0 {
		t.Fatal("Seal returned empty blob")
	}
	got, err := Open(blob, macKey, id)
	if err != nil {
		t.Fatal(err)
	}
	assertManifestEqual(t, got, want)
}

func TestOpenRejectsReorderedDigests(t *testing.T) {
	fx := sealedGolden(t)
	blob := resealJSON(t, fx, func(m *Manifest) {
		m.Digests[0], m.Digests[1] = m.Digests[1], m.Digests[0]
	})
	got, err := Open(blob, fx.macKey, fx.id)
	assertOpenErr(t, got, err, ErrMACMismatch)
}

func TestOpenRejectsAlteredDigestByte(t *testing.T) {
	fx := sealedGolden(t)
	blob := resealJSON(t, fx, func(m *Manifest) {
		d := append([]byte{}, m.Digests[0]...)
		d[0] ^= 0xff
		m.Digests[0] = d
	})
	got, err := Open(blob, fx.macKey, fx.id)
	assertOpenErr(t, got, err, ErrMACMismatch)
}

func TestOpenRejectsForeignMACKey(t *testing.T) {
	fx := sealedGolden(t)
	foreign, _, _ := testKey(t)
	if hmac.Equal(foreign, fx.macKey) {
		t.Fatal("foreign MAC key collided with sealed key")
	}
	got, err := Open(fx.blob, foreign, fx.id)
	assertOpenErr(t, got, err, ErrMACMismatch)
}

func TestOpenRejectsDroppedDigestBeforeMAC(t *testing.T) {
	t.Run("drop digest", func(t *testing.T) {
		fx := sealedGolden(t)
		blob := resealJSON(t, fx, func(m *Manifest) {
			m.Digests = m.Digests[:len(m.Digests)-1]
		})
		got, err := Open(blob, fx.macKey, fx.id)
		assertOpenErr(t, got, err, ErrMalformed)
	})
	t.Run("drop digest and lower n", func(t *testing.T) {
		fx := sealedGolden(t)
		blob := resealJSON(t, fx, func(m *Manifest) {
			m.Digests = m.Digests[:len(m.Digests)-1]
			m.N = len(m.Digests)
		})
		got, err := Open(blob, fx.macKey, fx.id)
		assertOpenErr(t, got, err, ErrMACMismatch)
	})
}

func TestOpenInconsistentIsNotMACMismatch(t *testing.T) {
	macKey, id, r := testKey(t)
	m := golden35()
	m.StripeLen++
	blob, err := Seal(m, macKey, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(blob, macKey, id)
	assertOpenErr(t, got, err, ErrInconsistent)
}

func TestOpenRejectsVersionBump(t *testing.T) {
	fx := sealedGolden(t)
	blob := resealJSON(t, fx, func(m *Manifest) {
		m.Version = 2
	})
	got, err := Open(blob, fx.macKey, fx.id)
	assertOpenErr(t, got, err, ErrUnsupportedVersion)
}

func TestOpenWrongIdentity(t *testing.T) {
	fx := sealedGolden(t)
	_, other, _ := testKey(t)
	got, err := Open(fx.blob, fx.macKey, other)
	assertOpenErr(t, got, err, crypt.ErrWrongIdentity)
}

func TestOpenTruncatedBlob(t *testing.T) {
	fx := sealedGolden(t)
	if len(fx.blob) < 2 {
		t.Fatalf("sealed blob length %d, want > 1", len(fx.blob))
	}
	truncated := fx.blob[:len(fx.blob)-1]
	if _, err := crypt.DecryptBytes(truncated, fx.id); err == nil {
		t.Fatal("DecryptBytes(truncated): err = nil, want step-1 failure")
	}
	got, err := Open(truncated, fx.macKey, fx.id)
	if got != nil {
		t.Fatal("Open returned a Manifest")
	}
	if err == nil {
		t.Fatal("Open truncated blob: err = nil, want error")
	}
	for _, other := range []error{ErrUnsupportedVersion, ErrMalformed, ErrMACMismatch, ErrInconsistent} {
		if errors.Is(err, other) {
			t.Fatalf("Open truncated blob matched %v", other)
		}
	}
}

type sealFix struct {
	blob   []byte
	macKey []byte
	id     age.Identity
	r      age.Recipient
}

func testKey(t *testing.T) (macKey []byte, id age.Identity, r age.Recipient) {
	t.Helper()
	kid, err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}
	macKey, err = kid.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(macKey) != key.MACKeyLen {
		t.Fatalf("mac key len = %d, want %d", len(macKey), key.MACKeyLen)
	}
	return macKey, kid.AgeIdentity(), kid.Recipient()
}

func sealedGolden(t *testing.T) sealFix {
	t.Helper()
	macKey, id, r := testKey(t)
	blob, err := Seal(golden35(), macKey, r)
	if err != nil {
		t.Fatal(err)
	}
	return sealFix{blob: blob, macKey: macKey, id: id, r: r}
}

func resealJSON(t *testing.T, fx sealFix, mut func(*Manifest)) []byte {
	t.Helper()
	body, err := crypt.DecryptBytes(fx.blob, fx.id)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	mut(&m)
	raw, err := json.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	out, err := crypt.EncryptBytes(raw, fx.r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertOpenErr(t *testing.T, got *Manifest, err, want error) {
	t.Helper()
	if got != nil {
		t.Fatal("Open returned a Manifest")
	}
	if !errors.Is(err, want) {
		t.Fatalf("Open: errors.Is(., %v) = false", want)
	}
	for _, other := range []error{ErrUnsupportedVersion, ErrMalformed, ErrMACMismatch, ErrInconsistent, crypt.ErrWrongIdentity} {
		if other != want && errors.Is(err, other) {
			t.Fatalf("Open: error also matched %v", other)
		}
	}
}

func assertManifestEqual(t *testing.T, got, want *Manifest) {
	t.Helper()
	if got == nil {
		t.Fatal("Open returned nil Manifest")
	}
	if got.Version != want.Version || got.K != want.K || got.N != want.N ||
		got.CiphertextLen != want.CiphertextLen || got.StripeLen != want.StripeLen {
		t.Errorf("manifest scalars: version=%d k=%d n=%d ciphertext_len=%d stripe_len=%d, want version=%d k=%d n=%d ciphertext_len=%d stripe_len=%d",
			got.Version, got.K, got.N, got.CiphertextLen, got.StripeLen,
			want.Version, want.K, want.N, want.CiphertextLen, want.StripeLen)
	}
	if len(got.Digests) != len(want.Digests) {
		t.Fatalf("digest count = %d, want %d", len(got.Digests), len(want.Digests))
	}
	for i := range want.Digests {
		if !hmac.Equal(got.Digests[i], want.Digests[i]) {
			t.Errorf("digests[%d] mismatch: len got=%d want=%d, sha256 got=%x want=%x",
				i, len(got.Digests[i]), len(want.Digests[i]), sha256.Sum256(got.Digests[i]), sha256.Sum256(want.Digests[i]))
		}
	}
	if !hmac.Equal(got.MAC, want.MAC) {
		t.Errorf("MAC mismatch: len got=%d want=%d, sha256 got=%x want=%x",
			len(got.MAC), len(want.MAC), sha256.Sum256(got.MAC), sha256.Sum256(want.MAC))
	}
}
