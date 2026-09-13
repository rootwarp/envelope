package erasure

import (
	"bytes"
	"errors"
	"fmt"
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
