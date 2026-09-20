package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

func TestRunIsCallableWithBuffers(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "identity.txt")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "-out", tmp}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatal("identity file was not created")
	}
}

func TestHelpMatchesContract(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contract string
		flags    []string
	}{
		{
			name:     "keygen -h",
			args:     []string{"keygen", "-h"},
			contract: usageKeygen,
			flags:    []string{"-out"},
		},
		{
			name:     "split -h",
			args:     []string{"split", "-h"},
			contract: usageSplit,
			flags:    []string{"-identity", "-recipient", "-in", "-out", "-k", "-n"},
		},
		{
			name:     "restore -h",
			args:     []string{"restore", "-h"},
			contract: usageRestore,
			flags:    []string{"-identity", "-in", "-out"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != exitOK {
				t.Fatalf("exit = %d, want %d", code, exitOK)
			}
			help := stdout.String() + stderr.String()
			found := false
			for _, line := range strings.Split(help, "\n") {
				if strings.TrimSpace(line) == tt.contract {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("help missing contract line %q", tt.contract)
			}
			for _, f := range tt.flags {
				if !strings.Contains(help, f) {
					t.Fatalf("help missing flag %s", f)
				}
			}
		})
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args func(*testing.T) []string
		want int
	}{
		{
			name: "unknown subcommand",
			args: func(*testing.T) []string { return []string{"nope"} },
			want: exitUsage,
		},
		{
			name: "unknown flag",
			args: func(*testing.T) []string { return []string{"keygen", "-bogus"} },
			want: exitUsage,
		},
		{
			name: "missing required flag",
			args: func(*testing.T) []string { return []string{"keygen"} },
			want: exitUsage,
		},
		{
			name: "explicit help",
			args: func(*testing.T) []string { return []string{"keygen", "-h"} },
			want: exitOK,
		},
		{
			name: "-k 0",
			args: func(*testing.T) []string {
				return []string{"split", "-identity", "id", "-in", "in", "-out", "out", "-k", "0"}
			},
			want: exitUsage,
		},
		{
			name: "-n 3 -k 3",
			args: func(*testing.T) []string {
				return []string{"split", "-identity", "id", "-in", "in", "-out", "out", "-n", "3", "-k", "3"}
			},
			want: exitUsage,
		},
		{
			name: "-n 257",
			args: func(*testing.T) []string {
				return []string{"split", "-identity", "id", "-in", "in", "-out", "out", "-n", "257"}
			},
			want: exitUsage,
		},
		{
			name: "wrong identity restore",
			args: func(t *testing.T) []string {
				dir := t.TempDir()
				id := filepath.Join(dir, "identity.txt")
				other := filepath.Join(dir, "other.txt")
				in := filepath.Join(dir, "in.bin")
				shards := filepath.Join(dir, "shards")
				out := filepath.Join(dir, "out.bin")
				mustRun(t, "keygen", "-out", id)
				mustRun(t, "keygen", "-out", other)
				writeOpaque(t, in, 32)
				mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
				return []string{"restore", "-identity", other, "-in", shards, "-out", out}
			},
			want: exitFailure,
		},
		{
			name: "non-empty -out split",
			args: func(t *testing.T) []string {
				dir := t.TempDir()
				id := filepath.Join(dir, "identity.txt")
				in := filepath.Join(dir, "in.bin")
				shards := filepath.Join(dir, "shards")
				mustRun(t, "keygen", "-out", id)
				writeOpaque(t, in, 32)
				if err := os.MkdirAll(shards, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(shards, "occupant"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				return []string{"split", "-identity", id, "-in", in, "-out", shards}
			},
			want: exitFailure,
		},
		{
			name: "success",
			args: func(t *testing.T) []string {
				return []string{"keygen", "-out", filepath.Join(t.TempDir(), "identity.txt")}
			},
			want: exitOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args(t), &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("exit = %d, want %d", code, tt.want)
			}
		})
	}
}

func TestVersionNamesBothPins(t *testing.T) {
	// ReadBuildInfo reports resolved module versions and returns nothing useful
	// outside module mode, so this AC holds for a normal go build.
	var stdout, stderr bytes.Buffer
	code := run([]string{"-version"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	out := stdout.String()
	if !strings.Contains(out, "filippo.io/age v1.3.1") {
		t.Fatalf("stdout missing filippo.io/age v1.3.1")
	}
	if !strings.Contains(out, "github.com/klauspost/reedsolomon v1.14.2") {
		t.Fatalf("stdout missing github.com/klauspost/reedsolomon v1.14.2")
	}
}

func TestVersionPrecedesDispatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-version", "split"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "filippo.io/age v1.3.1") {
		t.Fatal("did not take the version branch")
	}
}

// FR-19: assert against the injected buffers, not by reassigning process output.
func TestMarkerNeverReachesOutput(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")

	marker := syntheticMarker(t)
	inBytes := make([]byte, 4096)
	if _, err := rand.Read(inBytes); err != nil {
		t.Fatal(err)
	}
	copy(inBytes[1024:], marker)
	if err := os.WriteFile(in, inBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(written, marker) {
		t.Fatal("marker missing from input")
	}

	var outBuf, errBuf bytes.Buffer
	for _, args := range [][]string{
		{"keygen", "-out", id},
		{"split", "-identity", id, "-in", in, "-out", shards},
		{"restore", "-identity", id, "-in", shards, "-out", out},
	} {
		if code := run(args, &outBuf, &errBuf); code != exitOK {
			t.Fatalf("run %v: exit = %d", args, code)
		}
	}

	if bytes.Contains(outBuf.Bytes(), marker) {
		t.Error("marker present in stdout")
	}
	if bytes.Contains(errBuf.Bytes(), marker) {
		t.Error("marker present in stderr")
	}

	entries, err := os.ReadDir(shards)
	if err != nil {
		t.Fatal(err)
	}
	var sawManifest, nShards int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		got, rerr := os.ReadFile(filepath.Join(shards, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		switch {
		case name == "manifest.age":
			sawManifest++
			if bytes.Contains(got, marker) {
				t.Error("marker present in manifest.age")
			}
		case strings.HasPrefix(name, "shard-"):
			nShards++
			if bytes.Contains(got, marker) {
				t.Errorf("marker present in %s", name)
			}
		}
	}
	if sawManifest == 0 {
		t.Fatal("manifest.age missing")
	}
	if nShards == 0 {
		t.Fatal("no shard files")
	}

	restored, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(restored, marker) {
		t.Fatal("marker missing from restore")
	}
}

func TestStatusLinesOnStderr(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	const size = 32
	writeOpaque(t, in, size)

	var kgOut, kgErr bytes.Buffer
	if code := run([]string{"keygen", "-out", id}, &kgOut, &kgErr); code != exitOK {
		t.Fatalf("keygen: exit = %d", code)
	}
	if kgOut.Len() != 0 {
		t.Fatalf("keygen stdout has %d bytes, want 0", kgOut.Len())
	}
	if kgErr.Len() != 0 {
		t.Fatalf("keygen stderr has %d bytes, want 0", kgErr.Len())
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"split", "-identity", id, "-in", in, "-out", shards}, &stdout, &stderr); code != exitOK {
		t.Fatalf("split: exit = %d", code)
	}
	if code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &stdout, &stderr); code != exitOK {
		t.Fatalf("restore: exit = %d", code)
	}

	wrote := fmt.Sprintf("wrote 5 shards to %s", shards)
	restored := fmt.Sprintf("restored %d bytes to %s", size, out)
	got := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
	if len(got) != 3 {
		t.Fatalf("stderr has %d lines, want 3", len(got))
	}
	nStr, ok := strings.CutPrefix(got[0], "encrypted ")
	if !ok {
		t.Fatalf("stderr line 1 = %q, want encrypted N bytes", got[0])
	}
	nStr, ok = strings.CutSuffix(nStr, " bytes")
	if !ok {
		t.Fatalf("stderr line 1 = %q, want encrypted N bytes", got[0])
	}
	if _, err := strconv.ParseUint(nStr, 10, 64); err != nil {
		t.Fatalf("stderr line 1 = %q, want encrypted N bytes", got[0])
	}
	if got[1] != wrote {
		t.Fatalf("stderr line 2 = %q, want %q", got[1], wrote)
	}
	if got[2] != restored {
		t.Fatalf("stderr line 3 = %q, want %q", got[2], restored)
	}
	outStr := stdout.String()
	for _, line := range got {
		if strings.Contains(outStr, line) {
			t.Errorf("status line present on stdout")
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
}

func TestStatusLinesPayloadFree(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")

	marker := syntheticMarker(t)
	inBytes := make([]byte, 4096)
	if _, err := rand.Read(inBytes); err != nil {
		t.Fatal(err)
	}
	copy(inBytes[1024:], marker)
	if err := os.WriteFile(in, inBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	var outBuf, errBuf bytes.Buffer
	for _, args := range [][]string{
		{"keygen", "-out", id},
		{"split", "-identity", id, "-in", in, "-out", shards},
		{"restore", "-identity", id, "-in", shards, "-out", out},
	} {
		if code := run(args, &outBuf, &errBuf); code != exitOK {
			t.Fatalf("run %v: exit = %d", args, code)
		}
	}

	if bytes.Contains(outBuf.Bytes(), marker) {
		t.Error("marker present in stdout")
	}
	if bytes.Contains(errBuf.Bytes(), marker) {
		t.Error("marker present in stderr")
	}

	stderr := errBuf.String()
	if !strings.Contains(stderr, "encrypted ") || !strings.Contains(stderr, " bytes\n") {
		t.Error("stderr missing encrypted status line")
	}
	if !strings.Contains(stderr, fmt.Sprintf("wrote 5 shards to %s", shards)) {
		t.Error("stderr missing wrote status line")
	}
	if !strings.Contains(stderr, fmt.Sprintf("restored %d bytes to %s", len(inBytes), out)) {
		t.Error("stderr missing restored status line")
	}
}

func TestCorruptShardIndexInStderr(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 4096)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	const idx = 2
	xorFileByte(t, filepath.Join(shards, fmt.Sprintf("shard-%02d", idx)), 0)

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}
	want := fmt.Sprintf("failed digest at index %d", idx)
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr %q missing %q", stderr.String(), want)
	}
}

func TestTooFewShardsCountsInStderr(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 4096)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
	for _, name := range []string{"shard-00", "shard-01", "shard-02"} {
		if err := os.Remove(filepath.Join(shards, name)); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
	}
	const want = "need at least 3 usable shards, have 2"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr %q missing %q", stderr.String(), want)
	}
}

func TestStaleManifestMessage(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	dirA := filepath.Join(dir, "a")
	dirB := filepath.Join(dir, "b")
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 4096)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", dirA)
	stale, err := os.ReadFile(filepath.Join(dirA, "manifest.age"))
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, "split", "-identity", id, "-in", in, "-out", dirB)
	if err := os.WriteFile(filepath.Join(dirB, "manifest.age"), stale, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", dirB, "-out", out}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
	}
	got := stderr.String()
	const want = "0 of 5 shards matched the manifest — the manifest may not belong to this shard set."
	if !strings.Contains(got, want) {
		t.Fatalf("stderr %q missing %q", got, want)
	}
	if !strings.Contains(got, "0 of 5") {
		t.Fatalf("stderr %q missing 0 of 5", got)
	}
	if strings.Contains(strings.ToLower(got), "all shards corrupt") {
		t.Fatalf("stderr %q is the naive all-shards-corrupt message", got)
	}
}

func TestRestorePrivateTextManifestDoesNotPrintKey(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	out := filepath.Join(dir, "out.bin")
	mustRun(t, "keygen", "-out", id)
	writeOpaque(t, in, 32)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)

	idBytes, err := os.ReadFile(id)
	if err != nil {
		t.Fatal(err)
	}
	manPath := filepath.Join(shards, "manifest.age")
	if err := os.WriteFile(manPath, idBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", shards, "-out", out}, &stdout, &stderr)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	needle := "AGE-SECRET-KEY-" + "1"
	if bytes.Contains(stderr.Bytes(), []byte(needle)) {
		t.Fatal("identity material on stderr")
	}
	if bytes.Contains(stdout.Bytes(), []byte(needle)) {
		t.Fatal("identity material on stdout")
	}
	if !strings.Contains(stderr.String(), "malformed age file") {
		t.Fatalf("stderr missing malformed-age diagnostic (len=%d)", stderr.Len())
	}
}

func TestDistinguishableFailures(t *testing.T) {
	tests := []struct {
		name   string
		prep   func(t *testing.T, dir string) (args []string, path string)
		needle string
	}{
		{
			name:   "wrong identity",
			needle: "no identity matched the file",
			prep: func(t *testing.T, dir string) ([]string, string) {
				id := filepath.Join(dir, "identity.txt")
				other := filepath.Join(dir, "other.txt")
				in := filepath.Join(dir, "in.bin")
				shards := filepath.Join(dir, "shards")
				out := filepath.Join(dir, "out.bin")
				mustRun(t, "keygen", "-out", id)
				mustRun(t, "keygen", "-out", other)
				writeOpaque(t, in, 32)
				mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
				return []string{"restore", "-identity", other, "-in", shards, "-out", out}, other
			},
		},
		{
			name:   "MAC tamper",
			needle: "manifest MAC mismatch",
			prep: func(t *testing.T, dir string) ([]string, string) {
				id := filepath.Join(dir, "identity.txt")
				in := filepath.Join(dir, "in.bin")
				shards := filepath.Join(dir, "shards")
				out := filepath.Join(dir, "out.bin")
				mustRun(t, "keygen", "-out", id)
				writeOpaque(t, in, 32)
				mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
				manPath := filepath.Join(shards, "manifest.age")
				tamperManifestMAC(t, id, manPath)
				return []string{"restore", "-identity", id, "-in", shards, "-out", out}, manPath
			},
		},
		{
			name:   "no manifest",
			needle: "no manifest.age in the shard directory",
			prep: func(t *testing.T, dir string) ([]string, string) {
				id := filepath.Join(dir, "identity.txt")
				in := filepath.Join(dir, "in.bin")
				shards := filepath.Join(dir, "shards")
				out := filepath.Join(dir, "out.bin")
				mustRun(t, "keygen", "-out", id)
				writeOpaque(t, in, 32)
				mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
				manPath := filepath.Join(shards, "manifest.age")
				if err := os.Remove(manPath); err != nil {
					t.Fatal(err)
				}
				return []string{"restore", "-identity", id, "-in", shards, "-out", out}, manPath
			},
		},
	}

	needles := make([]string, len(tests))
	for i, tt := range tests {
		needles[i] = tt.needle
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			args, path := tt.prep(t, dir)
			inBytes, err := os.ReadFile(filepath.Join(dir, "in.bin"))
			if err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != exitFailure {
				t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
			}
			got := stderr.String()
			if !strings.Contains(got, tt.needle) {
				t.Fatalf("stderr %q missing %q", got, tt.needle)
			}
			if !strings.Contains(got, path) {
				t.Fatalf("stderr %q missing path %q", got, path)
			}
			for _, other := range needles {
				if other == tt.needle {
					continue
				}
				if strings.Contains(got, other) {
					t.Fatalf("stderr %q also contains %q", got, other)
				}
			}
			if bytes.Contains(stderr.Bytes(), inBytes) {
				t.Error("payload present in stderr")
			}
		})
	}
}

func xorFileByte(t *testing.T, path string, offset int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset < 0 || offset >= len(b) {
		t.Fatalf("offset %d out of range (len %d)", offset, len(b))
	}
	b[offset] ^= 0x01
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func tamperManifestMAC(t *testing.T, identityPath, manPath string) {
	t.Helper()
	id, err := key.Load(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Zero)
	blob, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Open(blob, id, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.MAC) == 0 {
		t.Fatal("manifest MAC is empty")
	}
	m.MAC[0] ^= 0x01
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	out, err := id.EncryptBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manPath, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	code := run(args, io.Discard, io.Discard)
	if code != exitOK {
		t.Fatalf("run %v: exit = %d", args, code)
	}
}

func writeOpaque(t *testing.T, path string, n int) {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Framing is unique so a leak is obvious; the interior is random so the
// fixture is not mnemonic-shaped (FR-19, FR-24).
func syntheticMarker(t *testing.T) []byte {
	t.Helper()
	const frame = "\x00\xffENV-MARK\xff\x00"
	inner := make([]byte, 32)
	if _, err := rand.Read(inner); err != nil {
		t.Fatal(err)
	}
	m := make([]byte, 0, len(frame)+len(inner)+len(frame))
	m = append(m, frame...)
	m = append(m, inner...)
	m = append(m, frame...)
	return m
}
