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

// Synthetic argv token for FR-P2-04: never a path, never a usage* substring.
const usageMark = "MARKERxyzzy"

type usageRow struct {
	name string
	// fr is the primary FR-P2 ID this row pins.
	fr   string
	args []string
	code int
	// stdoutNonEmpty is true for explicit help and -version (FR-P2-05, FR-P2-06).
	stdoutNonEmpty bool
	// contract is the usage* constant that must trail stderr on exit-2 rows.
	// Empty skips the pin (M2-flip rows, and help -bogus).
	contract string
	// exactStderr, if set, is the entire stderr (ExitCode()==3).
	exactStderr string
	// reason, if set, must appear in stderr (help -bogus: pin the reason, not the contract).
	reason string
}

// TestUsageMatrix is the P0 exit-0/exit-2 contract net (FR-P2-02, FR-P2-03,
// FR-P2-04, FR-P2-05, FR-P2-06). Exit-1 rows are M1.6.
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
		{name: "bare", fr: "FR-P2-03", args: nil, code: exitUsage, contract: usageAll},
		{name: "unknown cmd (marker)", fr: "FR-P2-04", args: []string{usageMark}, code: exitUsage, contract: usageAll},
		// M2 flips these three to exit 0; pin only exit and empty stdout here.
		{name: "help", fr: "FR-P2-03", args: []string{"help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "h", fr: "FR-P2-03", args: []string{"h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "help split", fr: "FR-P2-03", args: []string{"help", "split"}, code: exitOK, stdoutNonEmpty: true},
		{name: "help unknown (marker)", fr: "FR-P2-04", args: []string{"help", usageMark}, code: exitUsage, contract: usageAll},
		{name: "help -bogus", fr: "FR-P2-03", args: []string{"help", "-bogus"}, code: exitUsage, reason: "flag provided but not defined: -bogus"},
		{name: "help -h", fr: "FR-P2-05", args: []string{"help", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "help -h nope", fr: "FR-P2-05", args: []string{"help", "-h", "nope"}, code: exitUsage, exactStderr: usageAll},
		{name: "h split", fr: "FR-P2-09", args: []string{"h", "split"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-h unknown (marker)", fr: "FR-P2-05", args: []string{"-h", usageMark}, code: exitUsage, exactStderr: usageAll},
		{name: "split -h unknown (marker)", fr: "FR-P2-05", args: []string{"split", "-h", usageMark}, code: exitUsage, exactStderr: usageAll},

		{name: "-h", fr: "FR-P2-05", args: []string{"-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-help", fr: "FR-P2-05", args: []string{"-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "--help", fr: "FR-P2-05", args: []string{"--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "keygen -h", fr: "FR-P2-05", args: []string{"keygen", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "keygen -help", fr: "FR-P2-05", args: []string{"keygen", "-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "keygen --help", fr: "FR-P2-05", args: []string{"keygen", "--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "split -h", fr: "FR-P2-05", args: []string{"split", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "split -help", fr: "FR-P2-05", args: []string{"split", "-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "split --help", fr: "FR-P2-05", args: []string{"split", "--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "restore -h", fr: "FR-P2-05", args: []string{"restore", "-h"}, code: exitOK, stdoutNonEmpty: true},
		{name: "restore -help", fr: "FR-P2-05", args: []string{"restore", "-help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "restore --help", fr: "FR-P2-05", args: []string{"restore", "--help"}, code: exitOK, stdoutNonEmpty: true},
		{name: "recipient -h", fr: "FR-P2-05", args: []string{"recipient", "-h"}, code: exitOK, stdoutNonEmpty: true},

		{name: "-version", fr: "FR-P2-06", args: []string{"-version"}, code: exitOK, stdoutNonEmpty: true},
		{name: "--version", fr: "FR-P2-06", args: []string{"--version"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-version split", fr: "FR-P2-06", args: []string{"-version", "split"}, code: exitOK, stdoutNonEmpty: true},
		{name: "-version -bogus", fr: "FR-P2-06", args: []string{"-version", "-bogus"}, code: exitOK, stdoutNonEmpty: true},
		{name: "--version=true", fr: "FR-P2-06", args: []string{"--version=true"}, code: exitUsage, contract: usageAll},
		{name: "-v", fr: "FR-P2-06", args: []string{"-v"}, code: exitUsage, contract: usageAll},
		{name: "version", fr: "FR-P2-06", args: []string{"version"}, code: exitUsage, contract: usageAll},
		{name: "split -version", fr: "FR-P2-06", args: []string{"split", "-version"}, code: exitUsage, contract: usageSplit},

		{name: "spl", fr: "FR-P2-02", args: []string{"spl"}, code: exitUsage, contract: usageAll},
		{name: "root -bogus", fr: "FR-P2-03", args: []string{"-bogus"}, code: exitUsage, contract: usageAll},
		{name: "keygen -bogus", fr: "FR-P2-03", args: []string{"keygen", "-bogus"}, code: exitUsage, contract: usageKeygen},
		// pin-sensitive (research/01 §2)
		{name: "keygen -h -bogus", fr: "FR-P2-05", args: []string{"keygen", "-h", "-bogus"}, code: exitOK, stdoutNonEmpty: true},
		// pin-sensitive (research/01 §2)
		{name: "keygen -bogus -h", fr: "FR-P2-05", args: []string{"keygen", "-bogus", "-h"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen missing", fr: "FR-P2-03", args: []string{"keygen"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out=", fr: "FR-P2-02", args: []string{"keygen", "-out="}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out ''", fr: "FR-P2-02", args: []string{"keygen", "-out", ""}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out (missing value)", fr: "FR-P2-03", args: []string{"keygen", "-out"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen stray (marker)", fr: "FR-P2-04", args: []string{"keygen", "-out", filepath.Join(dir, "stray"), usageMark}, code: exitUsage, contract: usageKeygen},
		{name: "keygen -out x extra", fr: "FR-P2-02", args: []string{"keygen", "-out", filepath.Join(dir, "extra"), "extra"}, code: exitUsage, contract: usageKeygen},
		{name: "keygen help positional", fr: "FR-P2-02", args: []string{"keygen", "-out", filepath.Join(dir, "helppos"), "help"}, code: exitUsage, contract: usageKeygen},

		{name: "split missing all", fr: "FR-P2-03", args: []string{"split"}, code: exitUsage, contract: usageSplit},
		{name: "split -k -1", fr: "FR-P2-02", args: sp("-k", "-1"), code: exitUsage, contract: usageSplit},
		{name: "split -k 1.5", fr: "FR-P2-03", args: sp("-k", "1.5"), code: exitUsage, contract: usageSplit},
		{name: "split -k abc", fr: "FR-P2-03", args: sp("-k", "abc"), code: exitUsage, contract: usageSplit},
		{name: "split -k 0", fr: "FR-P2-03", args: sp("-k", "0"), code: exitUsage, contract: usageSplit},
		{name: "split -n 2 -k 3", fr: "FR-P2-03", args: sp("-n", "2", "-k", "3"), code: exitUsage, contract: usageSplit},
		{name: "split -n 3 -k 3", fr: "FR-P2-03", args: sp("-n", "3", "-k", "3"), code: exitUsage, contract: usageSplit},
		{name: "split -n 257", fr: "FR-P2-03", args: sp("-n", "257"), code: exitUsage, contract: usageSplit},
		{name: "split -kn 3", fr: "FR-P2-02", args: sp("-kn", "3"), code: exitUsage, contract: usageSplit},
		{name: "split -identity ''", fr: "FR-P2-02", args: []string{"split", "-identity", "", "-in", in, "-out", filepath.Join(t.TempDir(), "s")}, code: exitUsage, contract: usageSplit},
		{name: "split -- -identity x", fr: "FR-P2-02", args: []string{"split", "--", "-identity", "x"}, code: exitUsage, contract: usageSplit},
		{name: "split -- tail (marker)", fr: "FR-P2-04", args: sp("--", usageMark), code: exitUsage, contract: usageSplit},
		{name: "split leading positional (marker)", fr: "FR-P2-04", args: append([]string{"split", usageMark}, sp()[1:]...), code: exitUsage, contract: usageSplit},
		{name: "split h positional", fr: "FR-P2-02", args: sp("h"), code: exitUsage, contract: usageSplit},

		{name: "recipient missing", fr: "FR-P2-03", args: []string{"recipient"}, code: exitUsage, contract: usageRecipient},
		{name: "recipient -identity=", fr: "FR-P2-02", args: []string{"recipient", "-identity="}, code: exitUsage, contract: usageRecipient},
		{name: "recipient stray (marker)", fr: "FR-P2-04", args: []string{"recipient", "-identity", id, usageMark}, code: exitUsage, contract: usageRecipient},
		{name: "recipient -identity id -k 3", fr: "FR-P2-03", args: []string{"recipient", "-identity", id, "-k", "3"}, code: exitUsage, contract: usageRecipient},

		{name: "split -k=4 -n=6", fr: "FR-P2-02", args: sp("-k=4", "-n=6"), code: exitOK},
		{name: "split --k 4 --n 6", fr: "FR-P2-02", args: sp("--k", "4", "--n", "6"), code: exitOK},
		{name: "split --k=4 --n=6", fr: "FR-P2-02", args: sp("--k=4", "--n=6"), code: exitOK},
		{name: "split -k 4 -k 2 (last wins)", fr: "FR-P2-02", args: sp("-k", "4", "-k", "2"), code: exitOK},

		{name: "completion", fr: "FR-P2-11", args: []string{"completion"}, code: exitUsage, contract: usageCompletion},
		{name: "completion MARK", fr: "FR-P2-11", args: []string{"completion", usageMark}, code: exitUsage, contract: usageCompletion},
		{name: "completion bash extra", fr: "FR-P2-11", args: []string{"completion", "bash", "extra"}, code: exitUsage, contract: usageCompletion},
		{name: "completion bash -bogus", fr: "FR-P2-11", args: []string{"completion", "bash", "-bogus"}, code: exitUsage, contract: usageCompletion},
		{name: "completion bash", fr: "FR-P2-11", args: []string{"completion", "bash"}, code: exitOK, stdoutNonEmpty: true},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if r.fr == "" {
				t.Fatal("row missing FR-P2 ID")
			}
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
// command that drops the hook, noArgs, or HideHelpCommand fails here (FR-P2-03).
func TestEveryCommandHasHooks(t *testing.T) {
	root := newApp(io.Discard, io.Discard)
	// Pre-Run: HideHelpCommand is inherited from the root after setup, so a
	// child-only drop would pass the behavioral probes. Pin the field on the
	// envelope-built tree before Run appends library commands (M2 completion).
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
