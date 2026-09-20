package key

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

func TestLoadSetRecordsBundlePin(t *testing.T) {
	b, _ := mustNativeBundle(t)
	path := writeBundleFile(t, b)
	wantID := append([]byte(nil), b.MACKeyID...)
	wantPin := append([]byte(nil), b.Pin...)
	wantRec := append([]string(nil), b.Recipients...)
	b.MACKeyID[0] ^= 0xff
	b.Pin[0] ^= 0xff

	set, err := LoadSet([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	if !set.HasPin() {
		t.Fatal("HasPin = false after loading a bundle")
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0 (no unwrap at load)", set.Interactions())
	}
	if !hmac.Equal(set.pin.macKeyID, wantID) {
		t.Fatal("recorded mac_key_id does not match the bundle")
	}
	if !bytes.Equal(set.pin.pin, wantPin) {
		t.Fatal("recorded pin ciphertext does not match the bundle")
	}
	if len(set.pin.recipients) != len(wantRec) {
		t.Fatalf("recipients = %d, want %d", len(set.pin.recipients), len(wantRec))
	}
	for i := range wantRec {
		if set.pin.recipients[i] != wantRec[i] {
			t.Fatal("recorded recipients do not match the bundle")
		}
	}
	if set.BareFileIdentity() {
		t.Fatal("bundle path: BareFileIdentity = true")
	}
	gotID, err := set.KeyIDFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(gotID, wantID) {
		t.Fatal("KeyIDFor did not return the recorded id")
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions after KeyIDFor = %d, want 0", set.Interactions())
	}
}

func TestKeyIDForStartsNoPlugin(t *testing.T) {
	skipWindows(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")

	native, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Zero)
	rs, err := NewRecipientSet(native)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle([]string{fakeplugin.Identity("envtest", fakeplugin.ModeFatal)}, rs)
	if err != nil {
		t.Fatal(err)
	}
	set := mustLoadSet(t, nil, writeBundleFile(t, b))
	if set.Interactions() != 0 {
		t.Fatalf("Interactions after load = %d, want 0", set.Interactions())
	}

	got, err := set.KeyIDFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(got, b.MACKeyID) {
		t.Fatal("KeyIDFor did not return the recorded id")
	}
	if _, err := set.KeyIDFor(versionScalar, macSourceScalar); err != nil {
		t.Fatal(err)
	}
	if _, err := set.KeyIDFor(versionPin, macSourcePin); err != nil {
		t.Fatal(err)
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions after KeyIDFor = %d, want 0", set.Interactions())
	}
	if n := fakeplugin.Invocations(t); len(n) != 0 {
		t.Fatalf("plugin started: %d invocations", len(n))
	}
	assertNoSecrets(t, nil, nil, []byte(fakeplugin.PIN))
}

func TestKeyForV1ZeroInteractionsWithBundle(t *testing.T) {
	skipWindows(t)
	native, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(native.Zero)
	nativePath := writeIdentityFile(t, native.age.String()+"\n")

	b, setPlugin, rec := mustWrittenPluginBundle(t, fakeplugin.ModeOK)
	_ = setPlugin
	set := mustLoadSet(t, rec.source(), nativePath, writeBundleFile(t, b))
	if !set.HasPin() {
		t.Fatal("HasPin = false with a hardware bundle loaded")
	}

	got, err := set.KeyFor(versionScalar, macSourceScalar)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	want, err := native.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !hmac.Equal(got, want) {
		t.Fatal("KeyFor(1, 0) disagrees with ManifestMACKey")
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0", set.Interactions())
	}
	assertNoSecrets(t, nil, rec, append(secretsFromNative(t, native), []byte(fakeplugin.PIN))...)
}

func TestKeyForPinP1Memoized(t *testing.T) {
	skipWindows(t)
	b, set, rec := mustWrittenPluginBundle(t, fakeplugin.ModeOK)
	got, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if set.Interactions() != 1 {
		t.Fatalf("Interactions first = %d, want 1", set.Interactions())
	}
	again, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(again)
	if set.Interactions() != 1 {
		t.Fatalf("Interactions repeat = %d, want 1", set.Interactions())
	}
	if !hmac.Equal(got, again) {
		t.Fatal("memoized KeyFor returned a different key")
	}
	seed, err := set.DecryptBytes(b.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	want, err := derivePinMACKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !hmac.Equal(got, want) {
		t.Fatal("KeyFor pin key disagrees with HKDF")
	}
	assertNoSecrets(t, nil, rec, []byte(fakeplugin.PIN), seed, want, []byte(hex.EncodeToString(seed)), []byte(hex.EncodeToString(want)))
}

func TestKeyForPinP2FirstRejectedMemoized(t *testing.T) {
	skipWindows(t)
	_, set, rec := mustWrittenPluginBundle(t, fakeplugin.ModeIncorrectIdentity, fakeplugin.ModeOK)
	if len(set.Identities()) != 2 {
		t.Fatalf("identities = %d, want 2", len(set.Identities()))
	}
	got, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if set.Interactions() != 2 {
		t.Fatalf("Interactions first = %d, want 2", set.Interactions())
	}
	again, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(again)
	if set.Interactions() != 2 {
		t.Fatalf("Interactions repeat = %d, want 2", set.Interactions())
	}
	if !hmac.Equal(got, again) {
		t.Fatal("memoized KeyFor returned a different key")
	}
	assertNoSecrets(t, nil, rec, []byte(fakeplugin.PIN), got, []byte(hex.EncodeToString(got)))
}

func TestSameIDBundlesFirstWins(t *testing.T) {
	skipWindows(t)
	b, set0, rec := mustWrittenPluginBundle(t, fakeplugin.ModeOK)
	_ = set0
	path1 := writeBundleFile(t, b)
	path2 := writeBundleFile(t, b)
	set := mustLoadSet(t, rec.source(), path1, path2)
	got, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if set.Interactions() != 1 {
		t.Fatalf("Interactions = %d, want 1", set.Interactions())
	}
	id, err := set.KeyIDFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(id, b.MACKeyID) {
		t.Fatal("KeyIDFor did not return the first recorded id")
	}
	assertNoSecrets(t, nil, rec, []byte(fakeplugin.PIN), got)
}

func TestSameIDBundlesFirstPinUsed(t *testing.T) {
	b, id := mustNativeBundle(t)
	good := writeBundleFile(t, b)

	rs, err := NewRecipientSet(id)
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{0x11}, seedLen)
	badPin, err := rs.EncryptBytes(wrong)
	if err != nil {
		t.Fatal(err)
	}
	clear(wrong)
	bad := *b
	bad.Pin = badPin
	badPath := writeBundleFile(t, &bad)

	okSet := mustLoadSet(t, nil, good, badPath)
	got, err := okSet.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	clear(got)

	badSet := mustLoadSet(t, nil, badPath, good)
	k, err := badSet.KeyFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrPinCorrupt) {
		t.Fatalf("errors.Is(., ErrPinCorrupt) = false: %v", err)
	}
	if k != nil {
		clear(k)
		t.Fatal("KeyFor returned a key for a corrupt first pin")
	}
	assertNoSecrets(t, err, nil, secretsFromNative(t, id)...)
}

func TestDifferentIDBundlesErrAmbiguousPin(t *testing.T) {
	b1, id1 := mustNativeBundle(t)
	b2, _ := mustNativeBundle(t)
	set := mustLoadSet(t, nil, writeBundleFile(t, b1), writeBundleFile(t, b2))

	_, err := set.KeyIDFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrAmbiguousPin) {
		t.Fatalf("KeyIDFor: errors.Is(., ErrAmbiguousPin) = false: %v", err)
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions after KeyIDFor = %d, want 0", set.Interactions())
	}
	k, err := set.KeyFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrAmbiguousPin) {
		t.Fatalf("KeyFor pin: errors.Is(., ErrAmbiguousPin) = false: %v", err)
	}
	if k != nil {
		clear(k)
		t.Fatal("KeyFor returned a key on ErrAmbiguousPin")
	}
	pinErr := err
	if set.Interactions() != 0 {
		t.Fatalf("Interactions after KeyFor pin = %d, want 0", set.Interactions())
	}

	got, err := set.KeyFor(versionScalar, macSourceScalar)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	want, err := id1.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !hmac.Equal(got, want) {
		t.Fatal("KeyFor(1, 0) failed with two different-id bundles loaded")
	}
	assertNoSecrets(t, pinErr, nil, secretsFromNative(t, id1)...)
}

func TestNoPinErrNoPin(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	set := mustLoadSet(t, nil, writeIdentityFile(t, id.age.String()+"\n"))
	if set.HasPin() {
		t.Fatal("HasPin = true with no bundle")
	}
	kid, err := set.KeyIDFor(versionScalar, macSourceScalar)
	if err != nil {
		t.Fatal(err)
	}
	if kid != nil {
		t.Fatal("KeyIDFor(1, 0) returned a key id")
	}

	_, err = set.KeyIDFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrNoPin) {
		t.Fatalf("KeyIDFor: errors.Is(., ErrNoPin) = false: %v", err)
	}
	if !strings.Contains(err.Error(), "envelope bind") {
		t.Fatalf("ErrNoPin does not name envelope bind: %q", err.Error())
	}
	k, err := set.KeyFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrNoPin) {
		t.Fatalf("KeyFor pin: errors.Is(., ErrNoPin) = false: %v", err)
	}
	if k != nil {
		clear(k)
		t.Fatal("KeyFor returned a key on ErrNoPin")
	}
	pinErr := err
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0", set.Interactions())
	}

	got, err := set.KeyFor(versionScalar, macSourceScalar)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	want, err := id.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if !hmac.Equal(got, want) {
		t.Fatal("KeyFor(1, 0) failed with no pin")
	}
	assertNoSecrets(t, pinErr, nil, secretsFromNative(t, id)...)
}

func TestTamperedSeedErrPinCorrupt(t *testing.T) {
	b, id := mustNativeBundle(t)
	rs, err := NewRecipientSet(id)
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{0xab}, seedLen)
	pin, err := rs.EncryptBytes(wrong)
	if err != nil {
		t.Fatal(err)
	}
	b.Pin = pin
	set := mustLoadSet(t, nil, writeBundleFile(t, b))

	k, err := set.KeyFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrPinCorrupt) {
		t.Fatalf("errors.Is(., ErrPinCorrupt) = false: %v", err)
	}
	if k != nil {
		clear(k)
		t.Fatal("KeyFor returned a key for a tampered seed")
	}
	if set.macKey != nil {
		t.Fatal("memoized a key after ErrPinCorrupt")
	}
	again, err := set.KeyFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrPinCorrupt) {
		t.Fatalf("repeat: errors.Is(., ErrPinCorrupt) = false: %v", err)
	}
	if again != nil {
		clear(again)
	}
	assertNoSecrets(t, err, nil, append(secretsFromNative(t, id), wrong, []byte(hex.EncodeToString(wrong)))...)
	clear(wrong)
}

func TestUnknownMACSourceNoPlugin(t *testing.T) {
	skipWindows(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("AGEDEBUG", "")
	b, _ := mustNativeBundle(t)
	set := mustLoadSet(t, nil, writeBundleFile(t, b))

	pairs := [][2]uint32{{2, 0}, {1, 1}, {3, 0}, {2, 2}}
	for _, pair := range pairs {
		_, err := set.KeyIDFor(pair[0], pair[1])
		if !errors.Is(err, errMACSourceUnsupported) {
			t.Fatalf("KeyIDFor(%d, %d): errors.Is(., errMACSourceUnsupported) = false: %v", pair[0], pair[1], err)
		}
		if errors.Is(err, ErrNoPin) || errors.Is(err, ErrAmbiguousPin) {
			t.Fatalf("KeyIDFor(%d, %d) used a pin sentinel", pair[0], pair[1])
		}
		k, err := set.KeyFor(pair[0], pair[1])
		if !errors.Is(err, errMACSourceUnsupported) {
			t.Fatalf("KeyFor(%d, %d): errors.Is(., errMACSourceUnsupported) = false: %v", pair[0], pair[1], err)
		}
		if k != nil {
			clear(k)
			t.Fatalf("KeyFor(%d, %d) returned a key", pair[0], pair[1])
		}
		assertNoSecrets(t, err, nil)
	}
	if set.Interactions() != 0 {
		t.Fatalf("Interactions = %d, want 0", set.Interactions())
	}
}

func TestKeyForClearsSeed(t *testing.T) {
	b, _ := mustNativeBundle(t)
	set := mustLoadSet(t, nil, writeBundleFile(t, b))

	var alias []byte
	testObserveSeed = func(seed []byte) { alias = seed }
	t.Cleanup(func() { testObserveSeed = nil })

	got, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if alias == nil {
		t.Fatal("seed hook was not called")
	}
	if len(alias) != seedLen {
		t.Fatalf("seed len = %d, want %d", len(alias), seedLen)
	}
	for _, c := range alias {
		if c != 0 {
			t.Fatal("seed buffer still live after KeyFor")
		}
	}
}

func TestKeyForClearsSeedOnCorrupt(t *testing.T) {
	b, id := mustNativeBundle(t)
	rs, err := NewRecipientSet(id)
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{0xcd}, seedLen)
	pin, err := rs.EncryptBytes(wrong)
	if err != nil {
		t.Fatal(err)
	}
	clear(wrong)
	b.Pin = pin
	set := mustLoadSet(t, nil, writeBundleFile(t, b))

	var alias []byte
	testObserveSeed = func(seed []byte) { alias = seed }
	t.Cleanup(func() { testObserveSeed = nil })

	k, err := set.KeyFor(versionPin, macSourcePin)
	if !errors.Is(err, ErrPinCorrupt) {
		t.Fatalf("errors.Is(., ErrPinCorrupt) = false: %v", err)
	}
	if k != nil {
		clear(k)
	}
	if alias == nil {
		t.Fatal("seed hook was not called")
	}
	for _, c := range alias {
		if c != 0 {
			t.Fatal("seed buffer still live after ErrPinCorrupt")
		}
	}
}

func TestZeroDropsMemoizedKey(t *testing.T) {
	skipWindows(t)
	_, set, rec := mustWrittenPluginBundle(t, fakeplugin.ModeOK)
	got, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	clear(got)
	if set.Interactions() != 1 {
		t.Fatalf("Interactions first = %d, want 1", set.Interactions())
	}
	set.Zero()
	again, err := set.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	clear(again)
	if set.Interactions() != 2 {
		t.Fatalf("Interactions after Zero = %d, want 2 (memo must not survive Zero)", set.Interactions())
	}
	assertNoSecrets(t, nil, rec, []byte(fakeplugin.PIN))
}

func TestMemoizationIsPerSet(t *testing.T) {
	skipWindows(t)
	b, _, rec := mustWrittenPluginBundle(t, fakeplugin.ModeOK)
	path := writeBundleFile(t, b)
	a := mustLoadSet(t, rec.source(), path)
	c := mustLoadSet(t, rec.source(), path)
	got, err := a.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	clear(got)
	if a.Interactions() != 1 {
		t.Fatalf("set A Interactions = %d, want 1", a.Interactions())
	}
	if c.Interactions() != 0 {
		t.Fatalf("set C Interactions = %d, want 0 (per-Set memo, not process)", c.Interactions())
	}
	got, err = c.KeyFor(versionPin, macSourcePin)
	if err != nil {
		t.Fatal(err)
	}
	clear(got)
	if c.Interactions() != 1 {
		t.Fatalf("set C Interactions = %d, want 1", c.Interactions())
	}
}

func writeBundleFile(t *testing.T, b *Bundle) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.txt")
	if err := WriteNew(path, b); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustLoadSet(t *testing.T, term TerminalSource, paths ...string) *Set {
	t.Helper()
	set, err := LoadSet(paths, term)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.Zero)
	return set
}

func mustWrittenPluginBundle(t *testing.T, modes ...fakeplugin.Mode) (*Bundle, *Set, *uiTerm) {
	t.Helper()
	name := "envtest"
	fakeplugin.Install(t, name)
	rec := &uiTerm{}
	ui := NewClientUI(rec.source())
	recips := make([]string, len(modes))
	lines := make([]string, len(modes))
	for i, m := range modes {
		recips[i] = fakeplugin.Recipient(name, m)
		lines[i] = fakeplugin.Identity(name, m)
	}
	rs := mustParseRecipients(t, ui, recips...)
	b, err := NewBundle(lines, rs)
	if err != nil {
		t.Fatal(err)
	}
	set := mustLoadSet(t, rec.source(), writeBundleFile(t, b))
	return b, set, rec
}

func secretsFromNative(t *testing.T, id *Identity) [][]byte {
	t.Helper()
	out := make([][]byte, 0, 2)
	if id.hasScalar {
		out = append(out, append([]byte(nil), id.scalar[:]...))
	}
	return out
}

func assertNoSecrets(t *testing.T, err error, rec *uiTerm, secrets ...[]byte) {
	t.Helper()
	var blobs [][]byte
	if err != nil {
		blobs = append(blobs, []byte(err.Error()))
	}
	if rec != nil {
		blobs = append(blobs, []byte(rec.captured()))
		for _, line := range rec.lines() {
			blobs = append(blobs, []byte(line))
		}
	}
	for _, sec := range secrets {
		if len(sec) < 4 {
			continue
		}
		for _, blob := range blobs {
			if bytes.Contains(blob, sec) {
				t.Fatal("PIN, seed, scalar or derived key appeared in an error or captured stream")
			}
		}
	}
}

func TestUsageDocumentsPinErrors(t *testing.T) {
	root := moduleRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "usage.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, needle := range []string{ErrNoPin.Error(), ErrAmbiguousPin.Error()} {
		if !strings.Contains(body, needle) {
			t.Fatalf("docs/usage.md missing %q", needle)
		}
	}
}
