package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// FR-MD-01 E-MD-2: a directory literally named a,b is one directory.
func TestCommaDirectoryIsOneDirectory(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	want, err := os.ReadFile(filepath.Join(filepath.Dir(id), "in.bin"))
	if err != nil {
		t.Fatal(err)
	}
	comma := filepath.Join(t.TempDir(), "a,b")
	copyDirFiles(t, shards, comma)

	t.Run("restore", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.bin")
		var stdout, stderr bytes.Buffer
		code := run([]string{"restore", "-identity", id, "-in", comma, "-out", out}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		assertSameBytes(t, got, want)
	})

	t.Run("verify", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", id, "-in", comma}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
		}
		if got := stdout.String(); got != wantHealthy32 {
			t.Fatalf("stdout =\n%s\nwant\n%s", got, wantHealthy32)
		}
	})
}

// FR-MD-01: every parsing form accumulates in argv order.
func TestFlagAccumulationForms(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	want, err := os.ReadFile(filepath.Join(filepath.Dir(id), "in.bin"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Chdir(root)
	copyDirFiles(t, shards, "a")
	copyDirFiles(t, shards, "b")
	xorFileByte(t, filepath.Join("a", "shard-00"), 0)

	forms := []struct {
		name string
		in   []string
		want string // first directory; a rotten copy there is reported
	}{
		{name: "-in a -in b", in: []string{"-in", "a", "-in", "b"}, want: "a"},
		{name: "-in=a -in=b", in: []string{"-in=a", "-in=b"}, want: "a"},
		{name: "--in a --in b", in: []string{"--in", "a", "--in", "b"}, want: "a"},
		{name: "--in=a --in=b", in: []string{"--in=a", "--in=b"}, want: "a"},
		{name: "-in a --in=b", in: []string{"-in", "a", "--in=b"}, want: "a"},
		{name: "--in a -in=b", in: []string{"--in", "a", "-in=b"}, want: "a"},
		{name: "-in=a --in b", in: []string{"-in=a", "--in", "b"}, want: "a"},
		{name: "-in b -in a", in: []string{"-in", "b", "-in", "a"}, want: "b"},
	}
	for _, tt := range forms {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out.bin")
			args := append([]string{"restore", "-identity", id}, tt.in...)
			args = append(args, "-out", out)
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != exitOK {
				t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			assertSameBytes(t, got, want)
			aLine := "failed digest at index 0: " + filepath.Join("a", "shard-00")
			if tt.want == "a" {
				if !strings.Contains(stderr.String(), aLine) {
					t.Fatalf("stderr %q missing %q", stderr.String(), aLine)
				}
			} else if strings.Contains(stderr.String(), aLine) {
				t.Fatalf("stderr %q names a; search order should have stopped at b", stderr.String())
			}
		})
	}
}

// FR-MD-01: SliceBase.Set does not TrimSpace string elements.
func TestTrailingSpaceDirectory(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	want, err := os.ReadFile(filepath.Join(filepath.Dir(id), "in.bin"))
	if err != nil {
		t.Fatal(err)
	}
	spaced := filepath.Join(t.TempDir(), "shards ")
	copyDirFiles(t, shards, spaced)

	out := filepath.Join(t.TempDir(), "out.bin")
	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", spaced, "-out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertSameBytes(t, got, want)

	var vout, verr bytes.Buffer
	if code := run([]string{"verify", "-identity", id, "-in", spaced}, &vout, &verr); code != exitOK {
		t.Fatalf("verify exit = %d, want %d\nstderr: %s", code, exitOK, verr.String())
	}
}

func TestEmptyInFlag(t *testing.T) {
	const emptyMsg = `invalid value "" for flag -in: -in must not be empty`
	const missingMsg = `Required flag "in" not set`
	const noValueMsg = `flag needs an argument: -in`

	rows := []struct {
		name     string
		args     []string
		reason   string
		contract string
	}{
		{
			name:     "restore -in empty",
			args:     []string{"restore", "-identity", "id", "-in", "", "-out", "out"},
			reason:   emptyMsg,
			contract: usageRestore,
		},
		{
			name:     "restore -in=",
			args:     []string{"restore", "-identity", "id", "-in=", "-out", "out"},
			reason:   emptyMsg,
			contract: usageRestore,
		},
		{
			name:     "restore missing -in",
			args:     []string{"restore", "-identity", "id", "-out", "out"},
			reason:   missingMsg,
			contract: usageRestore,
		},
		{
			name:     "restore -in no value",
			args:     []string{"restore", "-identity", "id", "-out", "out", "-in"},
			reason:   noValueMsg,
			contract: usageRestore,
		},
		{
			name:     "verify -in empty",
			args:     []string{"verify", "-identity", "id", "-in", ""},
			reason:   emptyMsg,
			contract: usageVerify,
		},
		{
			name:     "verify -in=",
			args:     []string{"verify", "-identity", "id", "-in="},
			reason:   emptyMsg,
			contract: usageVerify,
		},
		{
			name:     "verify missing -in",
			args:     []string{"verify", "-identity", "id"},
			reason:   missingMsg,
			contract: usageVerify,
		},
		{
			name:     "verify -in no value",
			args:     []string{"verify", "-identity", "id", "-in"},
			reason:   noValueMsg,
			contract: usageVerify,
		},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
			}
			if !strings.Contains(stderr.String(), tt.reason) {
				t.Fatalf("stderr %q missing %q", stderr.String(), tt.reason)
			}
			assertContractOnStderr(t, stderr.String(), tt.contract)
		})
	}
}

// FR-MD-07: existence check runs for two or more given values, before any shard read.
func TestInDirMustExist(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)

	assertFail := func(t *testing.T, args []string, out, needle string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != exitFailure {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
		}
		if !strings.Contains(stderr.String(), needle) {
			t.Fatalf("stderr %q missing %q", stderr.String(), needle)
		}
		if strings.Contains(stderr.String(), "failed digest") || strings.Contains(stderr.String(), "restored ") {
			t.Fatalf("stderr %q suggests a shard was read", stderr.String())
		}
		assertAbsent(t, out)
		assertAbsent(t, out+".partial")
	}

	t.Run("nonexistent", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.bin")
		missing := filepath.Join(t.TempDir(), "missing")
		needle := fmt.Sprintf("-in %s: stat %s: no such file or directory", missing, missing)
		assertFail(t, []string{"restore", "-identity", id, "-in", shards, "-in", missing, "-out", out}, out, needle)
	})

	t.Run("not a directory", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.bin")
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		needle := fmt.Sprintf("-in %s: not a directory", file)
		assertFail(t, []string{"restore", "-identity", id, "-in", shards, "-in", file, "-out", out}, out, needle)
	})

	t.Run("mode 0000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not deny root")
		}
		locked := t.TempDir()
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		if d, err := os.Open(locked); err == nil {
			d.Close()
			t.Skip("process can still open chmod 0000 directory")
		}
		out := filepath.Join(t.TempDir(), "out.bin")
		needle := fmt.Sprintf("-in %s: open %s: permission denied", locked, locked)
		assertFail(t, []string{"restore", "-identity", id, "-in", shards, "-in", locked, "-out", out}, out, needle)
	})

	t.Run("nope twice vs once", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.bin")
		nope := filepath.Join(t.TempDir(), "nope")
		var stdout, stderr bytes.Buffer
		code := run([]string{"restore", "-identity", id, "-in", nope, "-out", out}, &stdout, &stderr)
		if code != exitFailure {
			t.Fatalf("single: exit = %d, want %d\nstderr: %s", code, exitFailure, stderr.String())
		}
		wantSingle := fmt.Sprintf("no manifest.age in the shard directory: %s", filepath.Join(nope, "manifest.age"))
		if !strings.Contains(stderr.String(), wantSingle) {
			t.Fatalf("single stderr %q missing %q", stderr.String(), wantSingle)
		}

		var stdout2, stderr2 bytes.Buffer
		code = run([]string{"restore", "-identity", id, "-in", nope, "-in", nope + string(os.PathSeparator), "-out", out}, &stdout2, &stderr2)
		if code != exitFailure {
			t.Fatalf("double: exit = %d, want %d\nstderr: %s", code, exitFailure, stderr2.String())
		}
		wantDouble := fmt.Sprintf("-in %s: stat %s: no such file or directory", nope, nope)
		if !strings.Contains(stderr2.String(), wantDouble) {
			t.Fatalf("double stderr %q missing %q", stderr2.String(), wantDouble)
		}
		assertAbsent(t, out)
		assertAbsent(t, out+".partial")
	})
}

// FR-MD-06: duplicate -in values collapse to single-directory streams.
func TestDuplicateInDirs(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	xorFileByte(t, filepath.Join(shards, "shard-02"), 0)

	singleOut := filepath.Join(t.TempDir(), "one.bin")
	var sOut, sErr bytes.Buffer
	sCode := run([]string{"restore", "-identity", id, "-in", shards + "/", "-out", singleOut}, &sOut, &sErr)
	if sCode != exitOK {
		t.Fatalf("single restore exit = %d, want %d\nstderr: %s", sCode, exitOK, sErr.String())
	}
	var vsOut, vsErr bytes.Buffer
	vsCode := run([]string{"verify", "-identity", id, "-in", shards + "/"}, &vsOut, &vsErr)
	if vsCode != exitFailure {
		t.Fatalf("single verify exit = %d, want %d\nstderr: %s", vsCode, exitFailure, vsErr.String())
	}

	parent := filepath.Dir(shards)
	base := filepath.Base(shards)
	link := filepath.Join(parent, "link-to-shards")
	if err := os.Symlink(shards, link); err != nil {
		t.Logf("symlink skipped: %v", err)
		link = ""
	}

	rows := []struct {
		name  string
		in    []string
		chdir string
	}{
		{name: "shards/ shards/", in: []string{shards + "/", shards + "/"}},
		{name: "shards shards/", in: []string{shards, shards + "/"}},
		{name: "shards ./shards", in: []string{base, "./" + base}, chdir: parent},
	}
	if link != "" {
		rows = append(rows, struct {
			name  string
			in    []string
			chdir string
		}{name: "shards link-to-shards", in: []string{shards, link}})
	}

	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			if tt.chdir != "" {
				t.Chdir(tt.chdir)
			}
			out := filepath.Join(t.TempDir(), "out.bin")
			args := []string{"restore", "-identity", id, "-in", tt.in[0], "-in", tt.in[1], "-out", out}
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != sCode {
				t.Fatalf("restore exit = %d, want %d\nstderr: %s", code, sCode, stderr.String())
			}
			if stdout.String() != sOut.String() {
				t.Fatalf("restore stdout %q, want %q", stdout.String(), sOut.String())
			}
			got := strings.ReplaceAll(stderr.String(), out, "@OUT")
			want := strings.ReplaceAll(sErr.String(), singleOut, "@OUT")
			if got != want {
				t.Fatalf("restore stderr =\n%q\nwant\n%q", got, want)
			}

			vArgs := []string{"verify", "-identity", id, "-in", tt.in[0], "-in", tt.in[1]}
			var vOut, vErr bytes.Buffer
			vCode := run(vArgs, &vOut, &vErr)
			if vCode != vsCode {
				t.Fatalf("verify exit = %d, want %d\nstderr: %s", vCode, vsCode, vErr.String())
			}
			if vOut.String() != vsOut.String() {
				t.Fatalf("verify stdout mismatch")
			}
			if vErr.String() != vsErr.String() {
				t.Fatalf("verify stderr =\n%q\nwant\n%q", vErr.String(), vsErr.String())
			}
		})
	}
}

// FR-MD-03 I2: wrong identity across two directories prints once.
func TestWrongIdentityPrintedOnceScattered(t *testing.T) {
	id, shards, out := mustSplitFixture(t)
	other := filepath.Join(filepath.Dir(id), "other.txt")
	mustRun(t, "keygen", "-out", other)
	second := filepath.Join(t.TempDir(), "b")
	copyDirFiles(t, shards, second)

	t.Run("restore", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"restore", "-identity", other, "-in", shards, "-in", second, "-out", out}, &stdout, &stderr)
		assertErrorPrintedOnce(t, code, &stdout, &stderr)
	})
	t.Run("verify", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"verify", "-identity", other, "-in", shards, "-in", second}, &stdout, &stderr)
		assertErrorPrintedOnce(t, code, &stdout, &stderr)
	})
}

// FR-19: marker never appears on either stream over a multi-directory run.
func TestScatteredMarkerNeverReachesOutput(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "identity.txt")
	in := filepath.Join(dir, "in.bin")
	shards := filepath.Join(dir, "shards")
	marker := syntheticMarker(t)
	inBytes := make([]byte, 4096)
	if _, err := rand.Read(inBytes); err != nil {
		t.Fatal(err)
	}
	copy(inBytes[1024:], marker)
	if err := os.WriteFile(in, inBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "keygen", "-out", id)
	mustRun(t, "split", "-identity", id, "-in", in, "-out", shards)
	dirs := scatterCLI(t, shards, 2)

	check := func(t *testing.T, stdout, stderr []byte) {
		t.Helper()
		if bytes.Contains(stdout, marker) || bytes.Contains(stderr, marker) {
			t.Error("marker present in a stream")
		}
		secret := "AGE-SECRET-KEY-"
		if bytes.Contains(bytes.ToUpper(stdout), []byte(secret)) || bytes.Contains(bytes.ToUpper(stderr), []byte(secret)) {
			t.Error("stream contains identity prefix")
		}
	}

	t.Run("restore", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.bin")
		args := []string{"restore", "-identity", id, "-in", dirs[0], "-in", dirs[1], "-out", out}
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
		}
		check(t, stdout.Bytes(), stderr.Bytes())
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(got, marker) {
			t.Fatal("marker missing from restore")
		}
	})

	t.Run("verify", func(t *testing.T) {
		args := []string{"verify", "-identity", id, "-in", dirs[0], "-in", dirs[1]}
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
		}
		check(t, stdout.Bytes(), stderr.Bytes())
	})
}

// FR-MD-08: multi-dir diagnostics use filepath.Join on the given -in, not EvalSymlinks.
// Join cleans "./a/shard-01" to "a/shard-01"; the PRD's "./a/shard-01" spelling is not emitted.
func TestAsGivenDiagnosticPath(t *testing.T) {
	id, shards, _ := mustSplitFixture(t)
	root := t.TempDir()
	t.Chdir(root)
	copyDirFiles(t, shards, "a")
	copyDirFiles(t, shards, "b")
	xorFileByte(t, filepath.Join("a", "shard-01"), 0)

	out := filepath.Join(t.TempDir(), "out.bin")
	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", "./a", "-in", "./b", "-out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}
	got := stderr.String()
	cleaned := filepath.Join("./a", "shard-01") // "a/shard-01"; PRD "./a/shard-01" is not emitted
	if filepath.ToSlash(cleaned) != "a/shard-01" {
		t.Fatalf("filepath.Join cleaned %q, want a/shard-01", cleaned)
	}
	want := "failed digest at index 1: " + cleaned
	if !strings.Contains(got, want) {
		t.Fatalf("stderr %q missing %q", got, want)
	}
	if strings.Contains(got, "./a/shard-01") {
		t.Fatal("stderr used the PRD ./a/shard-01 spelling")
	}
	if strings.Contains(got, root) {
		t.Fatal("stderr resolved to an absolute path")
	}
}

// FR-MD-09: restore -h describes repeatable -in. verify shares the same prose.
func TestRestoreHelpDescribesRepeatableIn(t *testing.T) {
	for _, cmd := range []string{"restore", "verify"} {
		t.Run(cmd, func(t *testing.T) {
			help := commandHelp(t, []string{cmd, "-h"})
			if !strings.Contains(help, "repeat") && !strings.Contains(help, "repeated") {
				t.Errorf("%s -h missing repeat/repeated", cmd)
			}
			if !strings.Contains(help, "first usable copy") {
				t.Errorf("%s -h missing first-usable-wins sentence", cmd)
			}
			if !strings.Contains(help, "-in /mnt/a -in /mnt/b -in /mnt/c") {
				t.Errorf("%s -h missing three-directory example", cmd)
			}
			if strings.Contains(strings.ToUpper(help), "AGE-SECRET-KEY-") {
				t.Errorf("%s -h contains identity material", cmd)
			}
			for _, p := range []string{"/Users/", "/home/"} {
				if strings.Contains(help, p) {
					t.Errorf("%s -h contains %q", cmd, p)
				}
			}
		})
	}
}

func TestRepeatableInRejectsPositional(t *testing.T) {
	id, shards, out := mustSplitFixture(t)
	second := filepath.Join(t.TempDir(), "b")
	copyDirFiles(t, shards, second)
	var stdout, stderr bytes.Buffer
	code := run([]string{"restore", "-identity", id, "-in", shards, "-in", second, "-out", out, usageMark}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout has %d bytes, want 0", stdout.Len())
	}
	if !strings.Contains(stderr.String(), "unexpected positional argument") {
		t.Fatalf("stderr %q missing positional error", stderr.String())
	}
	if strings.Contains(stderr.String(), usageMark) || strings.Contains(stdout.String(), usageMark) {
		t.Fatalf("marker echoed")
	}
	assertContractOnStderr(t, stderr.String(), usageRestore)
}

func TestSliceSeparatorOnlyOnCommands(t *testing.T) {
	root := newApp(io.Discard, io.Discard)
	if root.DisableSliceFlagSeparator {
		t.Fatal("DisableSliceFlagSeparator set on the root")
	}
	for _, name := range []string{"restore", "verify", "split", "keygen"} {
		c := commandByName(root, name)
		if c == nil {
			t.Fatalf("missing command %s", name)
			continue
		}
		if !c.DisableSliceFlagSeparator {
			t.Errorf("%s: DisableSliceFlagSeparator = false", name)
		}
	}
	if help := commandByName(root, "help"); help != nil && help.DisableSliceFlagSeparator {
		t.Error("help: DisableSliceFlagSeparator set (help is not built by newCommand)")
	}
}

func commandByName(root *cli.Command, name string) *cli.Command {
	for _, c := range root.Commands {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func copyDirFiles(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		copyCLIFile(t, filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()))
	}
}

func copyCLIFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func scatterCLI(t *testing.T, src string, d int) []string {
	t.Helper()
	root := t.TempDir()
	dirs := make([]string, d)
	for i := range dirs {
		dirs[i] = filepath.Join(root, string(rune('a'+i)))
		if err := os.MkdirAll(dirs[i], 0o700); err != nil {
			t.Fatal(err)
		}
		copyCLIFile(t, filepath.Join(src, "manifest.age"), filepath.Join(dirs[i], "manifest.age"))
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "shard-") {
			continue
		}
		copyCLIFile(t, filepath.Join(src, e.Name()), filepath.Join(dirs[n%d], e.Name()))
		n++
	}
	return dirs
}
