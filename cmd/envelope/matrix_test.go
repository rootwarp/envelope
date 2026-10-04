package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// Synthetic argv token: never a path, never a usage* substring, so a leak is obvious.
const usageMark = "MARKERxyzzy"

type usageRow struct {
	name string
	args []string
	code int
	// stdoutNonEmpty is true for explicit help and -version.
	stdoutNonEmpty bool
	// contract is the usage* constant that must trail stderr on exit-2 rows.
	// Empty skips that usage-suffix pin. exactStderr and reason are the other stderr pins.
	contract string
	// exactStderr, if set, is the entire stderr (ExitCode()==3).
	exactStderr string
	// reason, if set, must appear in stderr (help -bogus: pin the reason, not the contract).
	reason string
}

// TestUsageMatrix pins exit 0 and exit 2 for flag syntax, missing flags,
// unknown tokens, help, and version. Operational failures (exit 1) are elsewhere.
func TestUsageMatrix(t *testing.T) {
	dir := t.TempDir()
	id := filepath.Join(dir, "id.txt")
	mustRun(t, "keygen", "-out", id)
	in := filepath.Join(dir, "in.bin")
	writeOpaque(t, in, 64)
	sp := func(extra ...string) []string {
		base := []string{"split", "-identity", id, "-in", in, "-out", filepath.Join(t.TempDir(), "s")}
		return append(base, extra...)
	}

	rows := []usageRow{
		{name: "bare", args: nil, code: exitUsage, contract: usageAll},
		{name: "unknown cmd (marker)", args: []string{usageMark}, code: exitUsage, contract: usageAll},
		// help, h, and help split exit 0 with help text and no contract pin.
		{name: "help", args: []string{"help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "h", args: []string{"h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "help split", args: []string{"help", "split"}, code: exitOK, stdoutNonEmpty: true},
		{name: "help unknown (marker)", args: []string{"help", usageMark}, code: exitUsage, contract: usageAll},
		{name: "help -bogus", args: []string{"help", "-bogus"}, code: exitUsage, reason: "flag provided but not defined: -bogus"},
		{name: "help -h", args: []string{"help", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "help -h nope", args: []string{"help", "-h", "nope"}, code: exitUsage, exactStderr: usageAll},
		{name: "h split", args: []string{"h", "split"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-h unknown (marker)", args: []string{"-h", usageMark}, code: exitUsage, exactStderr: usageAll},
		{name: "split -h unknown (marker)", args: []string{"split", "-h", usageMark}, code: exitUsage, exactStderr: usageAll},

		{name: "-h", args: []string{"-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-help", args: []string{"-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "--help", args: []string{"--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "keygen -h", args: []string{"keygen", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "keygen -help", args: []string{"keygen", "-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "keygen --help", args: []string{"keygen", "--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "split -h", args: []string{"split", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "split -help", args: []string{"split", "-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "split --help", args: []string{"split", "--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "restore -h", args: []string{"restore", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "restore -help", args: []string{"restore", "-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "restore --help", args: []string{"restore", "--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "recipient -h", args: []string{"recipient", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "verify -h", args: []string{"verify", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "bind -h", args: []string{"bind", "-h"}, code: exitOK, stdoutNonEmpty: true},

		{name: "-version", args: []string{"-version"}, code: exitOK, stdoutNonEmpty: true},
		{name: "--version", args: []string{"--version"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-version split", args: []string{"-version", "split"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-version -bogus", args: []string{"-version", "-bogus"}, code: exitOK, stdoutNonEmpty: true},
		{name: "--version=true", args: []string{"--version=true"}, code: exitUsage, contract: usageAll},
		{name: "-v", args: []string{"-v"}, code: exitUsage, contract: usageAll},
		{name: "version", args: []string{"version"}, code: exitUsage, contract: usageAll},
		{name: "split -version", args: []string{"split", "-version"}, code: exitUsage, contract: usageSplit},

		{name: "spl", args: []string{"spl"}, code: exitUsage, contract: usageAll},
		{name: "root -bogus", args: []string{"-bogus"}, code: exitUsage, contract: usageAll},
		{name: "keygen -bogus", args: []string{"keygen", "-bogus"}, code: exitUsage, contract: usageKeygen},
		// -h before an unknown flag still prints help.
		{name: "keygen -h -bogus", args: []string{"keygen", "-h", "-bogus"}, code: exitOK, stdoutNonEmpty: true},
		// An unknown flag before -h is usage; help is not reached.
		{name: "keygen -bogus -h", args: []string{"keygen", "-bogus", "-h"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen missing", args: []string{"keygen"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out=", args: []string{"keygen", "-out="}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out ''", args: []string{"keygen", "-out", ""}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out (missing value)", args: []string{"keygen", "-out"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen stray (marker)", args: []string{"keygen", "-out", filepath.Join(dir, "stray"), usageMark}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out x extra", args: []string{"keygen", "-out", filepath.Join(dir, "extra"), "extra"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen help positional", args: []string{"keygen", "-out", filepath.Join(dir, "helppos"), "help"}, code: exitUsage, contract: usageKeygen},

		{name: "split missing all", args: []string{"split"}, code: exitUsage, contract: usageSplit},
		{name: "split -k -1", args: sp("-k", "-1"), code: exitUsage, contract: usageSplit},
		{name: "split -k 1.5", args: sp("-k", "1.5"), code: exitUsage, contract: usageSplit},
		{name: "split -k abc", args: sp("-k", "abc"), code: exitUsage, contract: usageSplit},
		{name: "split -k 0", args: sp("-k", "0"), code: exitUsage, contract: usageSplit},
		{name: "split -n 2 -k 3", args: sp("-n", "2", "-k", "3"), code: exitUsage, contract: usageSplit},
		{name: "split -n 3 -k 3", args: sp("-n", "3", "-k", "3"), code: exitUsage, contract: usageSplit},
		{name: "split -n 257", args: sp("-n", "257"), code: exitUsage, contract: usageSplit},
		{name: "split -kn 3", args: sp("-kn", "3"), code: exitUsage, contract: usageSplit},
		{name: "split -identity ''", args: []string{"split", "-identity", "", "-in", in, "-out", filepath.Join(t.TempDir(), "s")}, code: exitUsage, contract: usageSplit},
		{name: "split -- -identity x", args: []string{"split", "--", "-identity", "x"}, code: exitUsage, contract: usageSplit},
		{name: "split -- tail (marker)", args: sp("--", usageMark), code: exitUsage, contract: usageSplit},
		{name: "split leading positional (marker)", args: append([]string{"split", usageMark}, sp()[1:]...), code: exitUsage, contract: usageSplit},
		{name: "split h positional", args: sp("h"), code: exitUsage, contract: usageSplit},

		{name: "recipient missing", args: []string{"recipient"}, code: exitUsage, contract: usageRecipient},
		{name: "recipient -identity=", args: []string{"recipient", "-identity="}, code: exitUsage, contract: usageRecipient},
		{name: "recipient stray (marker)", args: []string{"recipient", "-identity", id, usageMark}, code: exitUsage, contract: usageRecipient},
		{name: "recipient -identity id -k 3", args: []string{"recipient", "-identity", id, "-k", "3"}, code: exitUsage, contract: usageRecipient},

		{name: "bind missing", args: []string{"bind"}, code: exitUsage, contract: usageBind},
		{name: "bind stray (marker)", args: []string{"bind", usageMark}, code: exitUsage, contract: usageBind},
		{name: "verify missing", args: []string{"verify"}, code: exitUsage, contract: usageVerify, reason: `"identity, in"`},
		{name: "verify -k 3", args: []string{"verify", "-identity", id, "-in", dir, "-k", "3"}, code: exitUsage, contract: usageVerify},
		{name: "verify -out o", args: []string{"verify", "-identity", id, "-in", dir, "-out", "o"}, code: exitUsage, contract: usageVerify},
		{name: "verify stray (marker)", args: []string{"verify", "-identity", id, "-in", dir, usageMark}, code: exitUsage, contract: usageVerify},

		{name: "split -k=4 -n=6", args: sp("-k=4", "-n=6"), code: exitOK},
		{name: "split --k 4 --n 6", args: sp("--k", "4", "--n", "6"), code: exitOK},
		{name: "split --k=4 --n=6", args: sp("--k=4", "--n=6"), code: exitOK},
		{name: "split -k 4 -k 2 (last wins)", args: sp("-k", "4", "-k", "2"), code: exitOK},

		{name: "completion", args: []string{"completion"}, code: exitUsage, contract: usageCompletion},
		{name: "completion MARK", args: []string{"completion", usageMark}, code: exitUsage, contract: usageCompletion},
		{name: "completion bash extra", args: []string{"completion", "bash", "extra"}, code: exitUsage, contract: usageCompletion},
		{name: "completion bash -bogus", args: []string{"completion", "bash", "-bogus"}, code: exitUsage, contract: usageCompletion},
		{name: "completion bash", args: []string{"completion", "bash"}, code: exitOK, stdoutNonEmpty: true},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(r.args, &stdout, &stderr)
			out, errStr := stdout.String(), stderr.String()
			if code != r.code {
				t.Errorf("exit=%d want %d\nstdout=%q\nstderr=%q", code, r.code, out, errStr)
			}
			if r.code == exitUsage && stdout.Len() != 0 {
				t.Errorf("exit-2 stdout has %d bytes, want 0: %q", stdout.Len(), out)
			}
			switch {
			case r.stdoutNonEmpty:
				if stdout.Len() == 0 {
					t.Errorf("stdout empty, want help/version text")
				}
				if stderr.Len() != 0 {
					t.Errorf("help/version stderr = %q, want empty", errStr)
				}
			case r.code == exitOK:
				if stdout.Len() != 0 {
					t.Errorf("stdout = %q, want empty", out)
				}
			}
			if r.exactStderr != "" && errStr != r.exactStderr {
				t.Errorf("stderr = %q, want exactly %q", errStr, r.exactStderr)
			}
			if r.contract != "" {
				assertContractOnStderr(t, errStr, r.contract)
			}
			if r.reason != "" && !strings.Contains(errStr, r.reason) {
				t.Errorf("stderr missing reason %q: %q", r.reason, errStr)
			}
			if strings.Contains(out, usageMark) || strings.Contains(errStr, usageMark) {
				t.Errorf("marker echoed: stdout=%q stderr=%q", out, errStr)
			}
		})
	}
}

func assertContractOnStderr(t *testing.T, stderr, contract string) {
	t.Helper()
	got := strings.TrimSuffix(stderr, "\n")
	want := strings.TrimSuffix(contract, "\n")
	if lastLine(got) != lastLine(want) {
		t.Errorf("stderr last line = %q, want %q", lastLine(got), lastLine(want))
	}
	if !strings.HasSuffix(got, want) {
		t.Errorf("stderr does not end with contract:\n got: %q\nwant suffix: %q", stderr, want)
	}
}

func lastLine(s string) string {
	s = strings.TrimSuffix(s, "\n")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

type cmdNode struct {
	path []string
	cmd  *cli.Command
}

// TestEveryCommandHasHooks walks Commands (never VisibleCommands) so a later
// command that drops the hook, noArgs, or HideHelpCommand fails here.
func TestEveryCommandHasHooks(t *testing.T) {
	root := newApp(io.Discard, io.Discard)
	// Pre-Run: HideHelpCommand is inherited from the root after setup, so a
	// child-only drop would pass the behavioral probes. Pin the field on the
	// envelope-built tree before Run appends library commands such as completion.
	preNames := map[string]bool{}
	var assertHideHelpCommand func([]*cli.Command)
	assertHideHelpCommand = func(cmds []*cli.Command) {
		for _, c := range cmds {
			preNames[c.Name] = true
			if !c.HideHelpCommand {
				t.Errorf("pre-Run %s: HideHelpCommand is false", c.Name)
			}
			assertHideHelpCommand(c.Commands)
		}
	}
	assertHideHelpCommand(root.Commands)
	for _, want := range []string{"keygen", "split", "restore"} {
		if !preNames[want] {
			t.Errorf("pre-Run tree missed %s", want)
		}
	}

	if err := root.Run(context.Background(), []string{"envelope", "--help"}); err != nil {
		t.Fatalf("setup Run: %v", err)
	}

	var nodes []cmdNode
	names := map[string]bool{}
	var walk func(prefix []string, cmds []*cli.Command)
	walk = func(prefix []string, cmds []*cli.Command) {
		for _, c := range cmds {
			path := append(append([]string{}, prefix...), c.Name)
			names[c.Name] = true
			nodes = append(nodes, cmdNode{path: path, cmd: c})
			walk(path, c.Commands) // never VisibleCommands(); completion is Hidden
		}
	}
	walk(nil, root.Commands)

	for _, want := range []string{"keygen", "split", "restore"} {
		if !names[want] {
			t.Errorf("walk missed %s", want)
		}
	}

	for _, n := range nodes {
		path := n.path
		label := strings.Join(path, " ")

		t.Run(label+" -bogus", func(t *testing.T) {
			args := append(append([]string{}, path...), "-bogus")
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != exitUsage {
				t.Errorf("exit=%d want %d\nstdout=%q\nstderr=%q", code, exitUsage, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout has %d bytes, want 0: %q", stdout.Len(), stdout.String())
			}
		})

		t.Run(label+" help", func(t *testing.T) {
			dir := t.TempDir()
			args := append(append([]string{}, path...), requiredStringFlagArgs(n.cmd, dir)...)
			args = append(args, "help")
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != exitUsage {
				t.Errorf("exit=%d want %d\nstdout=%q\nstderr=%q", code, exitUsage, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout has %d bytes, want 0: %q", stdout.Len(), stdout.String())
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				got := make([]string, len(entries))
				for i, e := range entries {
					got[i] = e.Name()
				}
				t.Errorf("probe created files under temp dir: %v", got)
			}
		})
	}
}

func requiredStringFlagArgs(cmd *cli.Command, dir string) []string {
	var args []string
	for _, f := range cmd.Flags {
		sf, ok := f.(*cli.StringFlag)
		if !ok || !sf.Required {
			continue
		}
		args = append(args, "-"+sf.Name, filepath.Join(dir, sf.Name))
	}
	return args
}
