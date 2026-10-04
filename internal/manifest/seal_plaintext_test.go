package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Captured from Seal before it took Fields, with the committed macInput key
// on golden35 and goldenV2. No existing test pinned this JSON: age randomizes
// the ciphertext, and the golden MAC tests never call Seal.
func TestSealPlaintextFrozen(t *testing.T) {
	macKey, err := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	if err != nil {
		t.Fatal(err)
	}
	if len(macKey) != MACLen {
		t.Fatalf("mac key len = %d, want %d", len(macKey), MACLen)
	}
	dir := filepath.Join("..", "..", "test", "golden", "seal-plaintext")
	for _, tc := range []struct {
		name   string
		fields Fields
		file   string
	}{
		{"v1", golden35().Fields(), "v1.json"},
		{"v2", goldenV2(goldenV2KeyID()).Fields(), "v2.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sealPlaintext(t, tc.fields, macKey)
			want, err := os.ReadFile(filepath.Join(dir, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s differs at byte %d (len got=%d want=%d)", tc.file, firstDiff(got, want), len(got), len(want))
			}
			var decoded Manifest
			if err := json.Unmarshal(got, &decoded); err != nil {
				t.Fatal(err)
			}
			again, err := json.Marshal(&decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, got) {
				t.Fatal("JSON is not byte-identical to marshalling the decoded Manifest")
			}
		})
	}
}

type recordingSealer struct {
	body []byte
}

func (r *recordingSealer) EncryptBytes(body []byte) ([]byte, error) {
	r.body = bytes.Clone(body)
	return []byte{0x01}, nil
}

func sealPlaintext(t *testing.T, f Fields, macKey []byte) []byte {
	t.Helper()
	rec := &recordingSealer{}
	if _, err := Seal(f, macKey, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.body) == 0 {
		t.Fatal("Seal presented an empty body")
	}
	return rec.body
}

func firstDiff(got, want []byte) int {
	n := min(len(got), len(want))
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			return i
		}
	}
	return n
}
