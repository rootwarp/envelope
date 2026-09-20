package manifest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
)

func TestV2MACInputGoldenVector(t *testing.T) {
	want, err := hex.DecodeString("0000000200000001a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000030000000500000000001000000000000000055556000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 208 {
		t.Fatalf("golden v2 macInput len = %d, want 208", len(want))
	}
	macKey, err := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	if err != nil {
		t.Fatal(err)
	}
	if len(macKey) != MACLen {
		t.Fatalf("mac key len = %d, want %d", len(macKey), MACLen)
	}
	wantMAC, err := hex.DecodeString("03e77824f1552e14c793750dab3d3694d49e572e023fca81375e5ad4c4040c48")
	if err != nil {
		t.Fatal(err)
	}
	if len(wantMAC) != MACLen {
		t.Fatalf("golden MAC len = %d, want %d", len(wantMAC), MACLen)
	}

	got, err := goldenV2(goldenV2KeyID()).macInput()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 208 {
		t.Fatalf("macInput len = %d, want 208", len(got))
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

func TestV2MACInputFieldOffsets(t *testing.T) {
	keyID := make([]byte, MACKeyIDLen)
	for i := range keyID {
		keyID[i] = byte(0xb0 + i)
	}
	m := Manifest{
		Version:       VersionPin,
		MACSource:     MACSourcePin,
		MACKeyID:      keyID,
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
	if len(in) != 48+32*m.N {
		t.Fatalf("macInput len = %d, want %d", len(in), 48+32*m.N)
	}
	if v := binary.BigEndian.Uint32(in[0:4]); v != m.Version {
		t.Errorf("version@0 = %d, want %d", v, m.Version)
	}
	if v := binary.BigEndian.Uint32(in[4:8]); v != m.MACSource {
		t.Errorf("mac_source@4 = %d, want %d", v, m.MACSource)
	}
	if !hmac.Equal(in[8:8+MACKeyIDLen], keyID) {
		t.Errorf("mac_key_id@8 mismatch: sha256 got=%x want=%x",
			sha256.Sum256(in[8:8+MACKeyIDLen]), sha256.Sum256(keyID))
	}
	if v := binary.BigEndian.Uint32(in[24:28]); v != uint32(m.K) {
		t.Errorf("k@24 = %d, want %d", v, m.K)
	}
	if v := binary.BigEndian.Uint32(in[28:32]); v != uint32(m.N) {
		t.Errorf("n@28 = %d, want %d", v, m.N)
	}
	if v := binary.BigEndian.Uint64(in[32:40]); v != uint64(m.CiphertextLen) {
		t.Errorf("ciphertext_len@32 = %d, want %d", v, m.CiphertextLen)
	}
	if v := binary.BigEndian.Uint64(in[40:48]); v != uint64(m.StripeLen) {
		t.Errorf("stripe_len@40 = %d, want %d", v, m.StripeLen)
	}
	for i, d := range m.Digests {
		off := 48 + 32*i
		got := in[off : off+DigestLen]
		if !hmac.Equal(got, d) {
			t.Errorf("digests[%d]@%d mismatch: len got=%d want=%d, sha256 got=%x want=%x",
				i, off, len(got), len(d), sha256.Sum256(got), sha256.Sum256(d))
		}
	}
}

func TestV1MACDoesNotValidateV2Body(t *testing.T) {
	macKey := bytes.Repeat([]byte{0x5a}, MACLen)
	v1 := golden35()
	v2 := goldenV2(goldenV2KeyID())
	in1, err := v1.macInput()
	if err != nil {
		t.Fatal(err)
	}
	in2, err := v2.macInput()
	if err != nil {
		t.Fatal(err)
	}
	mac1 := hmacSHA256(macKey, in1)
	mac2 := hmacSHA256(macKey, in2)
	if hmac.Equal(hmacSHA256(macKey, in2), mac1) {
		t.Fatal("v1 MAC validates v2 macInput")
	}
	if hmac.Equal(hmacSHA256(macKey, in1), mac2) {
		t.Fatal("v2 MAC validates v1 macInput")
	}

	_, id := testKey(t)
	src := &recSource{keyID: bytes.Clone(v2.MACKeyID), key: macKey}
	v2.MAC = mac1
	body, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := id.EncryptBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(blob, src, id)
	assertOpenErr(t, got, err, ErrMACMismatch)

	src1 := &recSource{key: macKey}
	v1.MAC = mac2
	body, err = json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	blob, err = id.EncryptBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	got, err = Open(blob, src1, id)
	assertOpenErr(t, got, err, ErrMACMismatch)
}

func TestSealOpenV2RoundTrip(t *testing.T) {
	fx := sealedV2(t)
	got, err := Open(fx.blob, fx.newSource(), fx.id)
	if err != nil {
		t.Fatal(err)
	}
	assertManifestEqual(t, got, fx.m)
	if got.MACSource != MACSourcePin {
		t.Fatalf("MACSource = %d, want %d", got.MACSource, MACSourcePin)
	}
	if !hmac.Equal(got.MACKeyID, fx.keyID) {
		t.Fatal("MACKeyID round-trip mismatch")
	}
}

func TestSealRefusesVersionPinWithMACSourceScalar(t *testing.T) {
	_, id := testKey(t)
	m := goldenV2(bytes.Repeat([]byte{0x22}, MACKeyIDLen))
	m.MACSource = MACSourceScalar
	blob, err := Seal(m, bytes.Repeat([]byte{0x11}, MACLen), id)
	if blob != nil {
		t.Fatal("Seal returned a blob")
	}
	if !errors.Is(err, ErrUnknownMACSource) {
		t.Fatalf("Seal: errors.Is(., ErrUnknownMACSource) = false")
	}
}

func TestOpenV2StepOrder(t *testing.T) {
	fx := sealedV2(t)
	dir := t.TempDir()
	shard := filepath.Join(dir, "shard-00")
	if err := os.WriteFile(shard, []byte("unused"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("success KeyIDFor before KeyFor", func(t *testing.T) {
		src := fx.newSource()
		op := &recOpener{inner: fx.id}
		h := &shardHook{}
		got, err := openThenShards(fx.blob, src, op, h, shard)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("Open returned nil Manifest")
		}
		if op.n != 1 {
			t.Fatalf("DecryptBytes calls = %d, want 1", op.n)
		}
		if want := []string{"KeyIDFor", "KeyFor"}; !equalStrings(src.calls, want) {
			t.Fatalf("resolver calls %v, want %v", src.calls, want)
		}
		if src.n != 1 {
			t.Fatalf("interactions = %d, want 1", src.n)
		}
		if len(h.opened) != 1 {
			t.Fatalf("shard opens = %d, want 1 after success", len(h.opened))
		}
	})

	t.Run("version 3", func(t *testing.T) {
		src := fx.newSource()
		op := &recOpener{inner: fx.id}
		h := &shardHook{}
		blob := resealJSON(t, fx.sealFix(), func(m *Manifest) { m.Version = 3 })
		got, err := openThenShards(blob, src, op, h, shard)
		assertOpenErr(t, got, err, ErrUnsupportedVersion)
		if op.n != 1 {
			t.Fatalf("DecryptBytes calls = %d, want 1", op.n)
		}
		if len(src.calls) != 0 {
			t.Fatalf("resolver calls %v, want none", src.calls)
		}
		if src.n != 0 {
			t.Fatalf("interactions = %d, want 0", src.n)
		}
		assertNoShardRead(t, h)
	})

	t.Run("malformed 15-byte id", func(t *testing.T) {
		src := fx.newSource()
		op := &recOpener{inner: fx.id}
		h := &shardHook{}
		blob := resealJSON(t, fx.sealFix(), func(m *Manifest) {
			m.MACKeyID = m.MACKeyID[:15]
		})
		got, err := openThenShards(blob, src, op, h, shard)
		assertOpenErr(t, got, err, ErrMalformed)
		if len(src.calls) != 0 {
			t.Fatalf("resolver calls %v, want none", src.calls)
		}
		assertNoShardRead(t, h)
	})

	t.Run("unknown mac_source", func(t *testing.T) {
		src := fx.newSource()
		op := &recOpener{inner: fx.id}
		h := &shardHook{}
		blob := resealJSON(t, fx.sealFix(), func(m *Manifest) { m.MACSource = 99 })
		got, err := openThenShards(blob, src, op, h, shard)
		assertOpenErr(t, got, err, ErrUnknownMACSource)
		if len(src.calls) != 0 {
			t.Fatalf("resolver calls %v, want none", src.calls)
		}
		assertNoShardRead(t, h)
	})

	t.Run("key-id mismatch", func(t *testing.T) {
		src := fx.newSource()
		src.keyID = bytes.Repeat([]byte{0x99}, MACKeyIDLen)
		op := &recOpener{inner: fx.id}
		h := &shardHook{}
		got, err := openThenShards(fx.blob, src, op, h, shard)
		assertOpenErr(t, got, err, ErrMACKeyIDMismatch)
		if want := []string{"KeyIDFor"}; !equalStrings(src.calls, want) {
			t.Fatalf("resolver calls %v, want %v", src.calls, want)
		}
		if src.n != 0 {
			t.Fatalf("interactions = %d, want 0", src.n)
		}
		assertNoShardRead(t, h)
	})

	t.Run("MAC mismatch after KeyFor", func(t *testing.T) {
		src := fx.newSource()
		src.key = bytes.Repeat([]byte{0x33}, MACLen)
		op := &recOpener{inner: fx.id}
		h := &shardHook{}
		got, err := openThenShards(fx.blob, src, op, h, shard)
		assertOpenErr(t, got, err, ErrMACMismatch)
		if want := []string{"KeyIDFor", "KeyFor"}; !equalStrings(src.calls, want) {
			t.Fatalf("resolver calls %v, want %v", src.calls, want)
		}
		assertNoShardRead(t, h)
	})

	t.Run("inconsistent StripeLen last", func(t *testing.T) {
		m := goldenV2(bytes.Clone(fx.keyID))
		m.StripeLen++
		blob, err := Seal(m, fx.macKey, fx.id)
		if err != nil {
			t.Fatal(err)
		}
		src := fx.newSource()
		op := &recOpener{inner: fx.id}
		h := &shardHook{}
		got, err := openThenShards(blob, src, op, h, shard)
		assertOpenErr(t, got, err, ErrInconsistent)
		if want := []string{"KeyIDFor", "KeyFor"}; !equalStrings(src.calls, want) {
			t.Fatalf("resolver calls %v, want %v", src.calls, want)
		}
		assertNoShardRead(t, h)
	})
}

func TestOpenVersion3NoShardNoResolver(t *testing.T) {
	fx := sealedV2(t)
	src := fx.newSource()
	op := &recOpener{inner: fx.id}
	h := &shardHook{}
	shard := filepath.Join(t.TempDir(), "shard-00")
	if err := os.WriteFile(shard, []byte("unused"), 0o644); err != nil {
		t.Fatal(err)
	}
	blob := resealJSON(t, fx.sealFix(), func(m *Manifest) { m.Version = 3 })
	got, err := openThenShards(blob, src, op, h, shard)
	assertOpenErr(t, got, err, ErrUnsupportedVersion)
	if len(src.calls) != 0 {
		t.Fatalf("resolver calls %v, want none", src.calls)
	}
	assertNoShardRead(t, h)
}

func TestOpenMutatedMACSourceFailsMAC(t *testing.T) {
	fx := sealedV2(t)
	h := &shardHook{}
	shard := filepath.Join(t.TempDir(), "shard-00")
	if err := os.WriteFile(shard, []byte("unused"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := fx.newSource()
	blob := resealJSON(t, fx.sealFix(), func(m *Manifest) {
		m.MACSource = MACSourceScalar
	})
	got, err := openThenShards(blob, src, fx.id, h, shard)
	assertOpenErr(t, got, err, ErrMACMismatch)
	assertNoShardRead(t, h)
}

func TestOpenMutatedMACKeyIDFailsMAC(t *testing.T) {
	fx := sealedV2(t)
	h := &shardHook{}
	shard := filepath.Join(t.TempDir(), "shard-00")
	if err := os.WriteFile(shard, []byte("unused"), 0o644); err != nil {
		t.Fatal(err)
	}
	mut := bytes.Clone(fx.keyID)
	mut[0] ^= 0xff
	blob := resealJSON(t, fx.sealFix(), func(m *Manifest) {
		m.MACKeyID = mut
	})
	// Key-id check is a usability aid: matching the mutated field still
	// fails the MAC, which is the verdict.
	src := &recSource{keyID: mut, key: fx.macKey}
	got, err := openThenShards(blob, src, fx.id, h, shard)
	assertOpenErr(t, got, err, ErrMACMismatch)
	assertNoShardRead(t, h)
}

func TestOpenMACKeyIDWrongLengthMalformed(t *testing.T) {
	fx := sealedV2(t)
	for _, n := range []int{15, 17} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			id := make([]byte, n)
			copy(id, fx.keyID)
			if n == 17 {
				id[16] = 0xff
			}
			src := fx.newSource()
			blob := resealJSON(t, fx.sealFix(), func(m *Manifest) {
				m.MACKeyID = id
			})
			h := &shardHook{}
			got, err := openThenShards(blob, src, fx.id, h)
			assertOpenErr(t, got, err, ErrMalformed)
			if len(src.calls) != 0 {
				t.Fatalf("resolver calls %v, want none", src.calls)
			}
			assertNoShardRead(t, h)
		})
	}
}

func TestOpenV1BodyWithMACSourceFieldsMalformed(t *testing.T) {
	fx := sealedGolden(t)
	t.Run("mac_source", func(t *testing.T) {
		blob := resealJSON(t, fx, func(m *Manifest) { m.MACSource = MACSourcePin })
		got, err := Open(blob, fx.id, fx.id)
		assertOpenErr(t, got, err, ErrMalformed)
	})
	t.Run("mac_key_id", func(t *testing.T) {
		blob := resealJSON(t, fx, func(m *Manifest) {
			m.MACKeyID = bytes.Repeat([]byte{0x01}, MACKeyIDLen)
		})
		got, err := Open(blob, fx.id, fx.id)
		assertOpenErr(t, got, err, ErrMalformed)
	})
}

func TestOpenRejectsRecipientOnlyForgeryBeforeShardRead(t *testing.T) {
	owner, err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Zero)
	rec, err := owner.RecipientString()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := key.ParseNativeRecipients([]string{rec})
	if err != nil {
		t.Fatal(err)
	}

	k, n := 2, 3
	stripe := bytes.Repeat([]byte{0xab}, 32)
	shards := make([][]byte, n)
	digests := make([][]byte, n)
	for i := range shards {
		shards[i] = bytes.Clone(stripe)
		sum := sha256.Sum256(shards[i])
		digests[i] = sum[:]
	}

	keyID := bytes.Repeat([]byte{0xcd}, MACKeyIDLen)
	pinKey := bytes.Repeat([]byte{0x11}, MACLen)
	forgerKey := bytes.Repeat([]byte{0x22}, MACLen)
	if hmac.Equal(pinKey, forgerKey) {
		t.Fatal("forger key collided with pin")
	}

	m := &Manifest{
		Version:       VersionPin,
		MACSource:     MACSourcePin,
		MACKeyID:      bytes.Clone(keyID),
		K:             k,
		N:             n,
		CiphertextLen: int64(k) * int64(len(stripe)),
		StripeLen:     int64(len(stripe)),
		Digests:       digests,
		MAC:           make([]byte, MACLen),
	}
	blob, err := Seal(m, forgerKey, rs)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	paths := make([]string, n)
	for i := range shards {
		paths[i] = filepath.Join(dir, shardName(i))
		if err := os.WriteFile(paths[i], shards[i], 0o644); err != nil {
			t.Fatal(err)
		}
	}

	src := &recSource{keyID: keyID, key: pinKey}
	op := &recOpener{inner: owner}
	h := &shardHook{}
	got, err := openThenShards(blob, src, op, h, paths...)
	assertOpenErr(t, got, err, ErrMACMismatch)
	if want := []string{"KeyIDFor", "KeyFor"}; !equalStrings(src.calls, want) {
		t.Fatalf("resolver calls %v, want %v", src.calls, want)
	}
	assertNoShardRead(t, h)
}

func TestOpenKeyIDMismatchZeroInteractions(t *testing.T) {
	fx := sealedV2(t)
	src := fx.newSource()
	src.keyID = bytes.Repeat([]byte{0xee}, MACKeyIDLen)
	h := &shardHook{}
	shard := filepath.Join(t.TempDir(), "shard-00")
	if err := os.WriteFile(shard, []byte("unused"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := openThenShards(fx.blob, src, fx.id, h, shard)
	assertOpenErr(t, got, err, ErrMACKeyIDMismatch)
	if errors.Is(err, ErrMACMismatch) {
		t.Fatal("key-id mismatch also matched ErrMACMismatch")
	}
	if src.n != 0 {
		t.Fatalf("interactions = %d, want 0", src.n)
	}
	if want := []string{"KeyIDFor"}; !equalStrings(src.calls, want) {
		t.Fatalf("resolver calls %v, want %v", src.calls, want)
	}
	assertNoShardRead(t, h)
}

func TestOpenV1WithHardwareBundleStubZeroInteractions(t *testing.T) {
	macKey, id := testKey(t)
	blob, err := Seal(golden35(), macKey, id)
	if err != nil {
		t.Fatal(err)
	}
	src := &recSource{key: macKey}
	h := &shardHook{}
	shard := filepath.Join(t.TempDir(), "shard-00")
	if err := os.WriteFile(shard, []byte("unused"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := openThenShards(blob, src, id, h, shard)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != Version {
		t.Fatalf("Version = %d, want %d", got.Version, Version)
	}
	if src.n != 0 {
		t.Fatalf("interactions = %d, want 0", src.n)
	}
	if want := []string{"KeyIDFor", "KeyFor"}; !equalStrings(src.calls, want) {
		t.Fatalf("resolver calls %v, want %v", src.calls, want)
	}
}

func TestValidateShapeV2MACKeyIDLength(t *testing.T) {
	for _, n := range []int{15, 17} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			m := goldenV2(make([]byte, n))
			if n == 17 {
				m.MACKeyID[16] = 0x01
			}
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

func goldenV2KeyID() []byte {
	id := make([]byte, MACKeyIDLen)
	for i := range id {
		id[i] = byte(0xa0 + i)
	}
	return id
}

func goldenV2(keyID []byte) *Manifest {
	m := golden35()
	m.Version = VersionPin
	m.MACSource = MACSourcePin
	m.MACKeyID = bytes.Clone(keyID)
	return m
}

type v2fix struct {
	blob   []byte
	macKey []byte
	keyID  []byte
	id     *key.Identity
	m      *Manifest
}

func sealedV2(t *testing.T) v2fix {
	t.Helper()
	_, id := testKey(t)
	macKey := bytes.Repeat([]byte{0x11}, MACLen)
	keyID := bytes.Repeat([]byte{0x22}, MACKeyIDLen)
	m := goldenV2(keyID)
	blob, err := Seal(m, macKey, id)
	if err != nil {
		t.Fatal(err)
	}
	return v2fix{blob: blob, macKey: macKey, keyID: keyID, id: id, m: m}
}

func (fx v2fix) newSource() *recSource {
	return &recSource{keyID: bytes.Clone(fx.keyID), key: bytes.Clone(fx.macKey)}
}

func (fx v2fix) sealFix() sealFix {
	return sealFix{blob: fx.blob, macKey: fx.macKey, id: fx.id}
}

// recSource is a YK-13 stub resolver. Tests must not use *key.Set.
type recSource struct {
	keyID []byte
	key   []byte
	calls []string
	n     int
}

func (s *recSource) KeyIDFor(version, macSource uint32) ([]byte, error) {
	s.calls = append(s.calls, "KeyIDFor")
	if len(s.keyID) == 0 {
		return nil, nil
	}
	return bytes.Clone(s.keyID), nil
}

func (s *recSource) KeyFor(version, macSource uint32) ([]byte, error) {
	s.calls = append(s.calls, "KeyFor")
	if version == VersionPin {
		s.n++
	}
	return bytes.Clone(s.key), nil
}

type recOpener struct {
	inner Opener
	n     int
}

func (o *recOpener) DecryptBytes(blob []byte) ([]byte, error) {
	o.n++
	return o.inner.DecryptBytes(blob)
}

type shardHook struct {
	opened []string
}

func (h *shardHook) read(path string) error {
	h.opened = append(h.opened, path)
	_, err := os.ReadFile(path)
	return err
}

func openThenShards(blob []byte, src MACKeySource, op Opener, h *shardHook, shardPaths ...string) (*Manifest, error) {
	m, err := Open(blob, src, op)
	if err != nil {
		return nil, err
	}
	for _, p := range shardPaths {
		if err := h.read(p); err != nil {
			return m, err
		}
	}
	return m, nil
}

func assertNoShardRead(t *testing.T, h *shardHook) {
	t.Helper()
	if len(h.opened) != 0 {
		t.Fatalf("shard path opened on failure: %v", h.opened)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func shardName(i int) string {
	return "shard-0" + string(rune('0'+i))
}
