package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// FR-P2-09
func TestHelpEquivalence(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
	}{
		{name: "help == --help", a: []string{"help"}, b: []string{"--help"}},
		{name: "h == --help", a: []string{"h"}, b: []string{"--help"}},
		{name: "help split == split --help", a: []string{"help", "split"}, b: []string{"split", "--help"}},
		{name: "h split == split --help", a: []string{"h", "split"}, b: []string{"split", "--help"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var aOut, aErr, bOut, bErr bytes.Buffer
			aCode := run(tt.a, &aOut, &aErr)
			bCode := run(tt.b, &bOut, &bErr)
			if aCode != exitOK {
				t.Errorf("%v: exit=%d want %d\nstdout=%q\nstderr=%q", tt.a, aCode, exitOK, aOut.String(), aErr.String())
			}
			if bCode != exitOK {
				t.Errorf("%v: exit=%d want %d\nstdout=%q\nstderr=%q", tt.b, bCode, exitOK, bOut.String(), bErr.String())
			}
			if aErr.Len() != 0 {
				t.Errorf("%v stderr = %q, want empty", tt.a, aErr.String())
			}
			if bErr.Len() != 0 {
				t.Errorf("%v stderr = %q, want empty", tt.b, bErr.String())
			}
			if !bytes.Equal(aOut.Bytes(), bOut.Bytes()) {
				t.Errorf("stdout %v != %v\n got %q\nwant %q", tt.a, tt.b, aOut.String(), bOut.String())
			}
		})
	}
}

// FR-P2-09
func TestHelpCommandUsageErrors(t *testing.T) {
	t.Run("help -bogus", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"help", "-bogus"}, &stdout, &stderr)
		if code != exitUsage {
			t.Errorf("exit=%d want %d\nstdout=%q\nstderr=%q", code, exitUsage, stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout has %d bytes, want 0: %q", stdout.Len(), stdout.String())
		}
		assertContractOnStderr(t, stderr.String(), usageHelp)
	})

	rows := []struct {
		name string
		args []string
	}{
		{name: "help MARK", args: []string{"help", usageMark}},
		{name: "help help", args: []string{"help", "help"}},
		{name: "help split extra", args: []string{"help", "split", "extra"}},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			out, errStr := stdout.String(), stderr.String()
			if code != exitUsage {
				t.Errorf("exit=%d want %d\nstdout=%q\nstderr=%q", code, exitUsage, out, errStr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout has %d bytes, want 0: %q", stdout.Len(), out)
			}
			if errStr != usageAll {
				t.Errorf("stderr = %q, want exactly %q", errStr, usageAll)
			}
			if strings.Contains(out, usageMark) || strings.Contains(errStr, usageMark) {
				t.Errorf("marker echoed: stdout=%q stderr=%q", out, errStr)
			}
		})
	}
}

// FR-P2-09
func TestRootHelpListsHelpOnce(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit=%d want %d\nstderr=%q", code, exitOK, stderr.String())
	}
	section := commandsSection(stdout.String())
	if section == "" {
		t.Fatal("root help missing COMMANDS:")
	}
	n := 0
	for _, line := range strings.Split(section, "\n") {
		fields := strings.Fields(strings.ReplaceAll(line, ",", " "))
		if len(fields) > 0 && fields[0] == "help" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("COMMANDS listed help %d times, want 1:\n%s", n, section)
	}

	for _, cmd := range []string{"keygen", "split", "restore", "help"} {
		var out, errBuf bytes.Buffer
		if code := run([]string{cmd, "--help"}, &out, &errBuf); code != exitOK {
			t.Fatalf("%s --help exit=%d\nstderr=%q", cmd, code, errBuf.String())
		}
		if strings.Contains(out.String(), "COMMANDS:") {
			t.Errorf("%s --help has COMMANDS:\n%s", cmd, out.String())
		}
	}
}

func commandsSection(help string) string {
	i := strings.Index(help, "COMMANDS:")
	if i < 0 {
		return ""
	}
	s := help[i:]
	for _, end := range []string{"GLOBAL OPTIONS:", "OPTIONS:"} {
		if j := strings.Index(s, end); j >= 0 {
			return s[:j]
		}
	}
	return s
}

// FR-P2-08
func TestHelpContent(t *testing.T) {
	pages := []struct {
		cmd  string
		want []string
	}{
		{cmd: "keygen", want: []string{"refuses to overwrite", "unrecoverable", "Examples:"}},
		{cmd: "split", want: []string{"(default: 3)", "(default: 5)", "1 ≤ k < n ≤ 256", "absent or empty", "written last", "Examples:"}},
		{cmd: "restore", want: []string{"is overwritten", ".partial", "Examples:"}},
	}
	for _, tt := range pages {
		t.Run(tt.cmd, func(t *testing.T) {
			help := commandHelp(t, []string{tt.cmd, "--help"})
			for _, s := range tt.want {
				if !strings.Contains(help, s) {
					t.Errorf("%s --help missing %q\n%s", tt.cmd, s, help)
				}
			}
		})
	}

	// Walk Commands (same list as TestEveryCommandHasHooks) so a later node
	// cannot introduce identity material or a machine path (C14).
	root := newApp(io.Discard, io.Discard)
	type helpArgs struct {
		name string
		args []string
	}
	scans := []helpArgs{{name: "root", args: []string{"--help"}}}
	var walk func(prefix []string, cmds []*cli.Command)
	walk = func(prefix []string, cmds []*cli.Command) {
		for _, c := range cmds {
			path := append(append([]string{}, prefix...), c.Name)
			scans = append(scans, helpArgs{name: strings.Join(path, " "), args: append(append([]string{}, path...), "--help")})
			walk(path, c.Commands)
		}
	}
	walk(nil, root.Commands)

	secret := "AGE-SECRET-KEY-"
	for _, s := range scans {
		t.Run("scan "+s.name, func(t *testing.T) {
			help := commandHelp(t, s.args)
			if strings.Contains(strings.ToUpper(help), secret) {
				t.Errorf("%s help contains identity material", s.name)
			}
			for _, p := range []string{"/Users/", "/home/"} {
				if strings.Contains(help, p) {
					t.Errorf("%s help contains %q", s.name, p)
				}
			}
		})
	}
}

func commandHelp(t *testing.T, args []string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("%v exit=%d want %d\nstdout=%q\nstderr=%q", args, code, exitOK, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("%v stderr = %q, want empty", args, stderr.String())
	}
	return stdout.String()
}
