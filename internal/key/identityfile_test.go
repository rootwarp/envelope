package key

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestNoOSReadFileInKeyOrPipeline(t *testing.T) {
	root := moduleRoot(t)
	for _, dir := range []string{
		filepath.Join(root, "internal", "key"),
		filepath.Join(root, "internal", "pipeline"),
	} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "ReadFile" {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if ok && id.Name == "os" {
					t.Errorf("%s: os.ReadFile", path)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadIdentityFileRefusesSparseBeforeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 30); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := ReadIdentityFile(path)
	defer got.Zero()
	if !errors.Is(err, ErrIdentityTooLarge) {
		t.Fatalf("errors.Is(., ErrIdentityTooLarge) = false: %v", err)
	}
	if got == nil {
		t.Fatal("nil IdentityFile")
	}
	// Nil data is only the fstat refusal. Growth returns a non-nil empty
	// slice, so deleting the pre-read check fails here: the sparse file is
	// then read, or refused with that empty slice.
	if got.data != nil {
		t.Fatal("fstat refusal allocated a buffer")
	}

	_, err = Load(path)
	if !errors.Is(err, ErrIdentityTooLarge) {
		t.Fatalf("Load: errors.Is(., ErrIdentityTooLarge) = false: %v", err)
	}
	_, err = LoadSet([]string{path}, nil)
	if !errors.Is(err, ErrIdentityTooLarge) {
		t.Fatalf("LoadSet: errors.Is(., ErrIdentityTooLarge) = false: %v", err)
	}
}

func TestReadIdentityFileOverReadReturnsEmptySlice(t *testing.T) {
	// Size 0 and a following byte is growth past the fstat size. /dev/zero
	// is that shape without a racing writer.
	fi, err := os.Stat("/dev/zero")
	if err != nil || fi.Size() != 0 {
		t.Skip("/dev/zero is not an empty stat")
	}
	got, err := ReadIdentityFile("/dev/zero")
	defer got.Zero()
	if !errors.Is(err, ErrIdentityTooLarge) {
		t.Fatalf("errors.Is(., ErrIdentityTooLarge) = false: %v", err)
	}
	if got == nil || got.data == nil || len(got.data) != 0 {
		t.Fatal("over-read must return a non-nil empty buffer")
	}
}

func TestIdentityFileZeroClearsBytes(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	line := id.age.String()
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := ReadIdentityFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(f.data, []byte(line)) {
		t.Fatal("file does not hold the identity line")
	}
	held := f.data
	scalar := id.scalar

	parsed, err := f.Single()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parsed.Zero)

	f.Zero()
	if f.data != nil {
		t.Fatal("IdentityFile still holds the buffer")
	}
	if bytes.Contains(held, []byte(line)) || bytes.Contains(held, scalar[:]) {
		t.Fatal("identity bytes survived Zero")
	}
	for i, b := range held {
		if b != 0 {
			t.Fatalf("byte %d survived Zero", i)
		}
	}
	if _, err := f.Single(); !errors.Is(err, ErrNotSingleIdentity) {
		t.Fatalf("bytes still parse after Zero: %v", err)
	}
}

func TestIdentityFileZeroDropsLargeChunk(t *testing.T) {
	// io.ReadAll's first chunk is 512 bytes and is abandoned once fewer
	// than cap/16 bytes remain, which is 481 bytes read. A normal bundle
	// is past that, so Zero of the returned slice would leave the secret
	// in the abandoned chunk.
	path := writeBundleForZero(t)
	runtime.GC()
	runtime.GC()

	prev := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prev)

	func() {
		f, err := ReadIdentityFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Zero()
		if len(f.data) < 481 {
			t.Fatalf("read %d bytes, want at least 481", len(f.data))
		}
	}()

	dump := heapDump(t)
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := lastNonCommentLine(disk)
	// The full line is not a reliable needle: a growing reader can split it
	// across abandoned chunks. Any 16-byte window still fits in one chunk.
	if len(line) < 16 {
		t.Fatal("bundle identity line is shorter than the search window")
	}
	if containsWindow(dump, line, 16) {
		t.Fatal("identity line survived in an abandoned heap chunk")
	}
}

func writeBundleForZero(t *testing.T) string {
	t.Helper()
	b, _ := mustNativeBundle(t)
	data := b.Marshal()
	if len(data) < 481 {
		t.Fatalf("bundle is %d bytes, want at least 481", len(data))
	}
	path := filepath.Join(t.TempDir(), "bundle.txt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func containsWindow(haystack, needle []byte, window int) bool {
	if window <= 0 || len(needle) < window {
		return false
	}
	for i := 0; i+window <= len(needle); i++ {
		if bytes.Contains(haystack, needle[i:i+window]) {
			return true
		}
	}
	return false
}

func lastNonCommentLine(data []byte) []byte {
	var line []byte
	for _, ln := range bytes.Split(data, []byte("\n")) {
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		line = ln
	}
	return line
}

func heapDump(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "heap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	debug.WriteHeapDump(f.Fd())
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dump, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return dump
}

func TestLoadSetParseErrorPrecedesLaterOpen(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("not-an-identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.txt")
	_, openErr := os.Open(missing)

	_, err := LoadSet([]string{bad, missing}, nil)
	if !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("errors.Is(., ErrInvalidIdentity) = false: %v", err)
	}
	if openErr == nil || err.Error() == openErr.Error() {
		t.Fatal("later open error replaced the parse error")
	}

	_, err = LoadSet([]string{missing, bad}, nil)
	assertSameErrorText(t, "LoadSet missing first", openErr, err)
}

func TestIdentityFileErrorText(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	_, openErr := os.Open(missing)
	_, statErr := os.Stat(missing)

	assertSameErrorText(t, "ReadIdentityFile", openErr, readIdentityErr(missing))
	_, err := Load(missing)
	assertSameErrorText(t, "Load", openErr, err)
	_, err = LoadSet([]string{missing}, nil)
	assertSameErrorText(t, "LoadSet", openErr, err)
	_, err = ReadBundle(missing)
	assertSameErrorText(t, "ReadBundle", statErr, err)
	_, err = ReadBundleFile(missing)
	assertSameErrorText(t, "ReadBundleFile", statErr, err)

	dir := t.TempDir()
	_, readErr := os.ReadFile(dir)
	assertSameErrorText(t, "ReadIdentityFile dir", readErr, readIdentityErr(dir))
	_, err = Load(dir)
	assertSameErrorText(t, "Load dir", readErr, err)
	_, err = LoadSet([]string{dir}, nil)
	assertSameErrorText(t, "LoadSet dir", readErr, err)
	_, err = ReadBundle(dir)
	assertSameErrorText(t, "ReadBundle dir", readErr, err)
}

func readIdentityErr(path string) error {
	f, err := ReadIdentityFile(path)
	f.Zero()
	return err
}

func assertSameErrorText(t *testing.T, name string, want, got error) {
	t.Helper()
	if want == nil || got == nil || got.Error() != want.Error() {
		t.Fatalf("%s error %v, want %v", name, got, want)
	}
}
