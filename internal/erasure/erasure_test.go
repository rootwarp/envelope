package erasure

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/reedsolomon"
)

func TestShardSizeMultipleIsOne(t *testing.T) {
	assertShardSizeMultipleOne(t, 3, 5) // shipped default

	for _, tt := range []struct{ k, n int }{
		{1, 2},
		{3, 4},
		{3, 5},
		{128, 256},
	} {
		t.Run(fmt.Sprintf("(%d,%d)", tt.k, tt.n), func(t *testing.T) {
			assertShardSizeMultipleOne(t, tt.k, tt.n)
		})
	}
}

func assertShardSizeMultipleOne(t *testing.T, k, n int) {
	t.Helper()
	e, err := New(k, n)
	if err != nil {
		t.Fatal(err)
	}
	if e.K() != k {
		t.Fatalf("K() = %d, want %d", e.K(), k)
	}
	if e.N() != n {
		t.Fatalf("N() = %d, want %d", e.N(), n)
	}
	ext, ok := e.enc.(reedsolomon.Extensions)
	if !ok {
		t.Fatal("encoder does not implement reedsolomon.Extensions")
	}
	if got := ext.ShardSizeMultiple(); got != 1 {
		t.Fatalf("ShardSizeMultiple() = %d, want 1", got)
	}
}

func TestNewReportsConstructionError(t *testing.T) {
	// reedsolomon.New(257, 0) is the Leopard path: err is set, but the Encoder
	// interface is a typed nil, so a method call panics.
	rs, rsErr := reedsolomon.New(257, 0)
	if rsErr == nil {
		t.Fatal("reedsolomon.New(257, 0): err = nil")
	}
	if rs == nil {
		t.Fatal("reedsolomon.New(257, 0) returned a nil interface; typed-nil trap gone")
	}
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		_ = rs.(reedsolomon.Extensions).DataShards()
	}()
	if !panicked {
		t.Fatal("method on construction-error encoder did not panic; typed-nil trap gone")
	}

	// Envelope must surface the library error rather than method-call panicking.
	for _, tt := range []struct {
		name string
		k, n int
		want error
	}{
		{"ErrInvShardNum", 257, 257, reedsolomon.ErrInvShardNum},
		{"ErrMaxShardNum", 1, 65537, reedsolomon.ErrMaxShardNum},
		{"ErrInvShardCombo", 60000, 65536, reedsolomon.ErrInvShardCombo},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, err := newEncoder(tt.k, tt.n)
			if err == nil {
				t.Fatal("err = nil, want wrapped library error")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("errors.Is(., %v) = false", tt.want)
			}
			for _, env := range []error{ErrInvalidK, ErrInvalidN, ErrTooManyShards, ErrShardSizeMultiple} {
				if errors.Is(err, env) {
					t.Fatalf("library error was flattened into %v", env)
				}
			}
			if e != nil {
				t.Fatal("newEncoder returned an Encoder with an error")
			}
		})
	}

	t.Run("ErrShardSizeMultiple", func(t *testing.T) {
		// (200, 257) is reedsolomon.New(200, 57): total 257 selects Leopard
		// (multiple 64). Validate rejects this pair; newEncoder is the backstop.
		e, err := newEncoder(200, 257)
		if !errors.Is(err, ErrShardSizeMultiple) {
			t.Fatalf("newEncoder(200, 257): errors.Is(., ErrShardSizeMultiple) = false")
		}
		if e != nil {
			t.Fatal("newEncoder returned an Encoder with an error")
		}
	})

	if _, err := New(1, 257); !errors.Is(err, ErrTooManyShards) {
		t.Fatalf("New(1, 257): errors.Is(., ErrTooManyShards) = false")
	}

	needle := "enc ==" + " nil"
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no Go files in package directory")
	}
	for _, name := range matches {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(src, []byte(needle)) {
			t.Errorf("%s compares the encoder to nil", name)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		k, n  int
		want  error
		param string
	}{
		{name: "k=0", k: 0, n: 5, want: ErrInvalidK, param: "k"},
		{name: "k=-1", k: -1, n: 5, want: ErrInvalidK, param: "k"},
		{name: "(k=3,n=2)", k: 3, n: 2, want: ErrInvalidN, param: "n"},
		{name: "(k=3,n=3)", k: 3, n: 3, want: ErrInvalidN, param: "n"},
		{name: "n=257", k: 3, n: 257, want: ErrTooManyShards, param: "n"},
		{name: "(k=3,n=4)", k: 3, n: 4, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.k, tt.n)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Validate(%d, %d) = %v, want nil", tt.k, tt.n, err)
				}
			} else {
				if !errors.Is(err, tt.want) {
					t.Fatalf("Validate(%d, %d): errors.Is(., %v) = false", tt.k, tt.n, tt.want)
				}
				msg := err.Error()
				if !strings.Contains(msg, tt.param) {
					t.Fatalf("error %q does not name %q", msg, tt.param)
				}
			}

			_, nerr := New(tt.k, tt.n)
			if tt.want == nil {
				if nerr != nil {
					t.Fatalf("New(%d, %d) = %v, want nil", tt.k, tt.n, nerr)
				}
				return
			}
			if !errors.Is(nerr, tt.want) {
				t.Fatalf("New(%d, %d): errors.Is(., %v) = false", tt.k, tt.n, tt.want)
			}
		})
	}

	allocs := testing.AllocsPerRun(1000, func() {
		for _, tt := range tests {
			_ = Validate(tt.k, tt.n)
		}
	})
	if allocs != 0 {
		t.Fatalf("Validate allocated %.2f times per run, want 0", allocs)
	}
}

var splitCases = []struct {
	k, n, ctLen int
}{
	{1, 2, 1},
	{1, 2, 7},
	{3, 4, 3},
	{3, 5, 3},
	{3, 5, 4},  // does not divide
	{3, 5, 10}, // does not divide
	{3, 5, 184},
	{5, 8, 17}, // does not divide
	{7, 10, 100},
	{128, 256, 200}, // does not divide; FR-7 boundary
}

func TestSplitStripeLen(t *testing.T) {
	for _, tt := range splitCases {
		t.Run(fmt.Sprintf("(%d,%d)/len=%d", tt.k, tt.n, tt.ctLen), func(t *testing.T) {
			shards, stripeLen := mustSplit(t, tt.k, tt.n, tt.ctLen)
			want := (int64(tt.ctLen) + int64(tt.k) - 1) / int64(tt.k)
			if stripeLen != want {
				t.Fatalf("stripeLen = %d, want ceil(%d/%d) = %d", stripeLen, tt.ctLen, tt.k, want)
			}
			for i, shard := range shards {
				if int64(len(shard)) != stripeLen {
					t.Fatalf("len(shards[%d]) = %d, want stripeLen %d", i, len(shard), stripeLen)
				}
			}
		})
	}
}

func TestSplitLenShards(t *testing.T) {
	for _, tt := range splitCases {
		t.Run(fmt.Sprintf("(%d,%d)/len=%d", tt.k, tt.n, tt.ctLen), func(t *testing.T) {
			shards, _ := mustSplit(t, tt.k, tt.n, tt.ctLen)
			if len(shards) != tt.n {
				t.Fatalf("len(shards) = %d, want n=%d", len(shards), tt.n)
			}
		})
	}
}

func TestSplitEncodesParity(t *testing.T) {
	for _, tt := range splitCases {
		t.Run(fmt.Sprintf("(%d,%d)/len=%d", tt.k, tt.n, tt.ctLen), func(t *testing.T) {
			e, err := New(tt.k, tt.n)
			if err != nil {
				t.Fatal(err)
			}
			ct := make([]byte, tt.ctLen)
			if _, err := rand.Read(ct); err != nil {
				t.Fatal(err)
			}
			ct[0] |= 1 // all-zero input encodes to all-zero parity, matching the unencoded zeros
			raw, err := e.enc.Split(bytes.Clone(ct))
			if err != nil {
				t.Fatal(err)
			}
			shards, _, err := e.Split(ct)
			if err != nil {
				t.Fatal(err)
			}
			for i := e.K(); i < e.N(); i++ {
				if bytes.Equal(shards[i], raw[i]) {
					t.Fatalf("parity shard %d matches library Split without Encode", i)
				}
			}
		})
	}
}

func TestSplitCiphertextTooShort(t *testing.T) {
	tests := []struct {
		k, n, ctLen int
	}{
		{3, 5, 0},
		{3, 5, 1},
		{3, 5, 2},
		{5, 8, 4},
		{1, 2, 0},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("(%d,%d)/len=%d", tt.k, tt.n, tt.ctLen), func(t *testing.T) {
			e, err := New(tt.k, tt.n)
			if err != nil {
				t.Fatal(err)
			}
			ct := make([]byte, tt.ctLen)
			shards, stripeLen, err := e.Split(ct)
			if shards != nil || stripeLen != 0 {
				t.Fatalf("Split returned %d shards, stripeLen=%d; want nil, 0", len(shards), stripeLen)
			}
			if !errors.Is(err, ErrCiphertextTooShort) {
				t.Fatalf("errors.Is(., ErrCiphertextTooShort) = false")
			}
			if errors.Is(err, reedsolomon.ErrShortData) {
				t.Fatal("reedsolomon.ErrShortData escaped")
			}
		})
	}
}

func TestDigestMatchesSHA256(t *testing.T) {
	for _, n := range []int{0, 1, 31, 32, 33, 64, 1024} {
		t.Run(fmt.Sprintf("len=%d", n), func(t *testing.T) {
			shard := make([]byte, n)
			if _, err := rand.Read(shard); err != nil {
				t.Fatal(err)
			}
			got := Digest(shard)
			if len(got) != DigestLen {
				t.Fatalf("Digest len = %d, want %d", len(got), DigestLen)
			}
			want := sha256.Sum256(shard)
			assertSameBytes(t, got, want[:])
		})
	}
}

func TestNewDigestComposesWithMultiWriter(t *testing.T) {
	for _, n := range []int{0, 1, 1024} {
		t.Run(fmt.Sprintf("len=%d", n), func(t *testing.T) {
			shard := make([]byte, n)
			if _, err := rand.Read(shard); err != nil {
				t.Fatal(err)
			}
			h := NewDigest()
			if _, err := io.MultiWriter(io.Discard, h).Write(shard); err != nil {
				t.Fatal(err)
			}
			assertSameBytes(t, h.Sum(nil), Digest(shard))
		})
	}
}

func TestReconstructWrongSliceLength(t *testing.T) {
	e, err := New(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{4, 6} { // short and over-long
		t.Run(fmt.Sprintf("len=%d", n), func(t *testing.T) {
			err := e.Reconstruct(make([][]byte, n))
			if !errors.Is(err, ErrWrongSliceLength) {
				t.Fatalf("errors.Is(., ErrWrongSliceLength) = false")
			}
			if errors.Is(err, reedsolomon.ErrTooFewShards) {
				t.Fatal("reedsolomon.ErrTooFewShards escaped")
			}
		})
	}
}

func TestTooFewShardsMessage(t *testing.T) {
	e, _, shards := splitRandom(t, 3, 5, 64)
	got := append([][]byte(nil), shards...)
	got[0], got[1], got[2] = nil, nil, nil // 2 usable at original indices
	err := e.Reconstruct(got)
	var tf *TooFewShardsError
	if !errors.As(err, &tf) {
		t.Fatalf("errors.As(., *TooFewShardsError) = false")
	}
	if tf.Need != 3 || tf.Have != 2 {
		t.Fatalf("Need=%d Have=%d, want 3, 2", tf.Need, tf.Have)
	}
	const want = "need at least 3 usable shards, have 2"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	if errors.Is(err, reedsolomon.ErrTooFewShards) {
		t.Fatal("reedsolomon.ErrTooFewShards in chain")
	}
}

func TestReconstructFromSurvivorsAtOriginalIndices(t *testing.T) {
	e, ct, shards := splitRandom(t, 3, 5, 64)
	got := append([][]byte(nil), shards...)
	got[1], got[3] = nil, nil // 0, 2, 4 present; do not compact
	if len(got) != 5 {
		t.Fatalf("len(shards) = %d, want n=5", len(got))
	}
	if err := e.Reconstruct(got); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := e.Join(&buf, got, int64(len(ct))); err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, buf.Bytes(), ct)
}

func TestEraseCorruptDonatesBuffer(t *testing.T) {
	e, ct, shards := splitRandom(t, 3, 5, 64)
	Erase(shards, 0)
	if shards[0] == nil {
		t.Fatal("present shard became nil")
	}
	if len(shards[0]) != 0 {
		t.Fatalf("len(present after Erase) = %d, want 0", len(shards[0]))
	}
	if cap(shards[0]) == 0 {
		t.Fatal("cap(present after Erase) = 0, want > 0")
	}

	shards[1] = nil
	Erase(shards, 1)
	if shards[1] != nil {
		t.Fatal("absent shard is not nil")
	}
	if len(shards[1]) != 0 {
		t.Fatalf("len(nil after Erase) = %d, want 0", len(shards[1]))
	}

	if err := e.Reconstruct(shards); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := e.Join(&buf, shards, int64(len(ct))); err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, buf.Bytes(), ct)
}

func TestEraseSetsNotAccumulates(t *testing.T) {
	e, ct, shards := splitRandom(t, 3, 5, 64)
	orig := bytes.Clone(shards[0])
	for i := range shards[0] {
		shards[0][i] = 0xaa
	}
	Erase(shards, 0)
	if err := e.Reconstruct(shards); err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, shards[0], orig)

	var buf bytes.Buffer
	if err := e.Join(&buf, shards, int64(len(ct))); err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, buf.Bytes(), ct)
}

func TestUsableCountsNonEmpty(t *testing.T) {
	empty := make([]byte, 0, 16)
	shards := [][]byte{
		nil,
		empty,
		{1},
		{1, 2},
		{},
	}
	if got := Usable(shards); got != 2 {
		t.Fatalf("Usable = %d, want 2", got)
	}
	if got := Usable(nil); got != 0 {
		t.Fatalf("Usable(nil) = %d, want 0", got)
	}
}

func TestJoinRangeCheck(t *testing.T) {
	e, err := New(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	shards := make([][]byte, 5)
	for i := range shards {
		shards[i] = []byte{1}
	}
	var buf bytes.Buffer
	err = e.Join(&buf, shards, -1)
	if err == nil {
		t.Fatal("negative outSize: err = nil")
	}
	if !errors.Is(err, ErrOutSizeRange) {
		t.Fatalf("negative: errors.Is(., ErrOutSizeRange) = false")
	}

	// int64 cannot hold MaxInt+1 on 64-bit; the overflow case is 32-bit only.
	maxInt := math.MaxInt
	if int64(maxInt) < math.MaxInt64 {
		err = e.Join(&buf, shards, int64(maxInt)+1)
		if err == nil {
			t.Fatal("outSize > MaxInt: err = nil")
		}
		if !errors.Is(err, ErrOutSizeRange) {
			t.Fatalf(">MaxInt: errors.Is(., ErrOutSizeRange) = false")
		}
	}
}

func TestJoinRejectsErasedDataShard(t *testing.T) {
	for _, tt := range []struct{ k, n, ctLen int }{
		{3, 5, 4},
		{32, 33, 184},
	} {
		t.Run(fmt.Sprintf("(%d,%d)/len=%d", tt.k, tt.n, tt.ctLen), func(t *testing.T) {
			e, ct, shards := splitRandom(t, tt.k, tt.n, tt.ctLen)
			Erase(shards, 0) // data index; [:0] is not nil
			var buf bytes.Buffer
			err := e.Join(&buf, shards, int64(len(ct)))
			if err == nil {
				t.Fatal("Join after Erase without Reconstruct: err = nil")
			}
			if buf.Len() != 0 {
				t.Fatalf("Join wrote %d bytes after error, want 0", buf.Len())
			}
		})
	}
}

func TestJoinExactLength(t *testing.T) {
	e, ct, shards := splitRandom(t, 3, 5, 10) // does not divide by k
	for lost := 0; lost <= 3; lost++ {
		t.Run(fmt.Sprintf("lost=%d", lost), func(t *testing.T) {
			got := append([][]byte(nil), shards...)
			for i := 0; i < lost; i++ {
				got[i] = nil
			}
			err := e.Reconstruct(got)
			if lost == 3 {
				var tf *TooFewShardsError
				if !errors.As(err, &tf) {
					t.Fatalf("errors.As(., *TooFewShardsError) = false")
				}
				if tf.Need != 3 || tf.Have != 2 {
					t.Fatalf("Need=%d Have=%d, want 3, 2", tf.Need, tf.Have)
				}
				if errors.Is(err, reedsolomon.ErrTooFewShards) {
					t.Fatal("reedsolomon.ErrTooFewShards in chain")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := e.Join(&buf, got, int64(len(ct))); err != nil {
				t.Fatal(err)
			}
			assertSameBytes(t, buf.Bytes(), ct)
		})
	}
}

func TestReconstructUsesReconstructData(t *testing.T) {
	src, err := os.ReadFile("erasure.go")
	if err != nil {
		t.Fatal(err)
	}
	if c := bytes.Count(src, []byte("ReconstructData")); c < 1 {
		t.Fatalf("ReconstructData count = %d, want >= 1", c)
	}
	if bytes.Contains(src, []byte(".Reconstruct(")) {
		t.Fatal("library Reconstruct( appears in erasure.go")
	}
}

func splitRandom(t *testing.T, k, n, ctLen int) (*Encoder, []byte, [][]byte) {
	t.Helper()
	e, err := New(k, n)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, ctLen)
	if _, err := rand.Read(ct); err != nil {
		t.Fatal(err)
	}
	shards, _, err := e.Split(bytes.Clone(ct))
	if err != nil {
		t.Fatal(err)
	}
	return e, ct, shards
}

func mustSplit(t *testing.T, k, n, ctLen int) ([][]byte, int64) {
	t.Helper()
	e, err := New(k, n)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, ctLen)
	if _, err := rand.Read(ct); err != nil {
		t.Fatal(err)
	}
	shards, stripeLen, err := e.Split(ct)
	if err != nil {
		t.Fatal(err)
	}
	return shards, stripeLen
}

// assertSameBytes compares payloads without ever putting them in the log.
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
