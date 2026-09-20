package pipeline

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
	"github.com/rootwarp/envelope/test/fakeplugin"
)

const (
	budgetLinePDQ1      = "this run needs 3 plugin interactions, each of which may prompt"
	budgetLine3dir1copy = "3 shard directories hold 1 manifest copy;\n" +
		"this run needs 3 plugin interactions, each of which may prompt"
	budgetLine3dir2copyP1 = "3 shard directories hold 2 different manifest copies;\n" +
		"this run needs 4 plugin interactions, each of which may prompt"
	budgetLine3dir2copyP2 = "3 shard directories hold 2 different manifest copies;\n" +
		"this run needs 4 plugin interactions, up to 8 if every identity is tried — each may prompt"
)

func TestBudgetMessage(t *testing.T) {
	for _, tt := range []struct {
		name           string
		nDirs, d, p, q int
		want           string
		upTo           bool
	}{
		{name: "p=d=q=1 single dir", nDirs: 1, d: 1, p: 1, q: 1, want: budgetLinePDQ1},
		{name: "p=d=q=1 three dirs", nDirs: 3, d: 1, p: 1, q: 1, want: budgetLine3dir1copy},
		{name: "d=2 p=1", nDirs: 3, d: 2, p: 1, q: 1, want: budgetLine3dir2copyP1},
		{name: "d=2 p=2", nDirs: 3, d: 2, p: 2, q: 1, want: budgetLine3dir2copyP2, upTo: true},
		{name: "p=2 single dir", nDirs: 1, d: 1, p: 2, q: 1, want: "this run needs 3 plugin interactions, up to 6 if every identity is tried — each may prompt", upTo: true},
		{name: "q=0 omits pin site", nDirs: 1, d: 1, p: 1, q: 0, want: "this run needs 2 plugin interactions, each of which may prompt"},
		{name: "p=0 silent", nDirs: 1, d: 1, p: 0, q: 1, want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := budgetMessage(tt.nDirs, tt.d, tt.p, tt.q)
			if got != tt.want {
				t.Fatalf("budgetMessage(%d,%d,%d,%d) =\n%q\nwant\n%q", tt.nDirs, tt.d, tt.p, tt.q, got, tt.want)
			}
			assertBudgetWording(t, got, tt.p)
			if tt.upTo != strings.Contains(got, "up to") {
				t.Fatalf("up to present=%v, want %v", strings.Contains(got, "up to"), tt.upTo)
			}
		})
	}
}

func TestInteractionBudget(t *testing.T) {
	skipWindows(t)
	bundle, shards := v2PluginShardSet(t)
	bad := writePluginStub(t, "envtest", fakeplugin.ModeIncorrectIdentity)

	t.Run("a_p=d=q=1", func(t *testing.T) {
		st, n, catch, rep, err := pluginVerify(t, []string{bundle}, []string{shards})
		if err != nil {
			t.Fatal(err)
		}
		assertBudgetBeforePlugin(t, catch)
		best, bound := assertI21(t, st, n)
		if best != 3 || bound != 3 {
			t.Fatalf("best=%d bound=%d, want 3 3", best, bound)
		}
		if n != 3 {
			t.Fatalf("Interactions() = %d, want 3 (bound met exactly)", n)
		}
		if strings.Contains(st, "up to") {
			t.Fatalf("shape (a) status has up to:\n%s", st)
		}
		if strings.Contains(st, "shard director") {
			t.Fatalf("shape (a) single-dir status has preamble:\n%s", st)
		}
		assertBudgetWording(t, st, 1)
		assertVerifyNPlus4(t, rep)
	})

	t.Run("a_restore", func(t *testing.T) {
		st, n, catch, err := pluginRestore(t, []string{bundle}, []string{shards})
		if err != nil {
			t.Fatal(err)
		}
		assertBudgetBeforePlugin(t, catch)
		best, bound := assertI21(t, st, n)
		if best != 3 || bound != 3 || n != 3 {
			t.Fatalf("restore I-21 best=%d bound=%d measured=%d, want 3 3 3", best, bound, n)
		}
		if strings.Contains(st, "up to") {
			t.Fatalf("restore shape (a) has up to:\n%s", st)
		}
		if !strings.Contains(st, "restored") {
			t.Fatalf("restore status missing restored line:\n%s", st)
		}
	})

	t.Run("b_first_rejected", func(t *testing.T) {
		st, n, catch, rep, err := pluginVerify(t, []string{bad, bundle}, []string{shards})
		if err != nil {
			t.Fatal(err)
		}
		assertBudgetBeforePlugin(t, catch)
		best, bound := assertI21(t, st, n)
		if best != 3 || bound != 6 {
			t.Fatalf("best=%d bound=%d, want 3 6", best, bound)
		}
		if n <= best {
			t.Fatalf("shape (b): measured %d did not exceed best %d", n, best)
		}
		if n > bound {
			t.Fatalf("shape (b): measured %d > bound %d", n, bound)
		}
		assertBudgetWording(t, st, 2)
		assertVerifyNPlus4(t, rep)
	})

	t.Run("c_d=2_p=1", func(t *testing.T) {
		dirs := twoBlobDirs(t, bundle, shards)
		st, n, catch, rep, err := pluginVerify(t, []string{bundle}, dirs)
		if err != nil {
			t.Fatal(err)
		}
		assertBudgetBeforePlugin(t, catch)
		best, bound := assertI21(t, st, n)
		if best != 4 || bound != 4 {
			t.Fatalf("d=2 p=1: best=%d bound=%d, want 4 4", best, bound)
		}
		if !strings.Contains(st, budgetLine3dir2copyP1) {
			t.Fatalf("status missing d=2 p=1 form:\n%s", st)
		}
		if strings.Contains(st, "up to") {
			t.Fatalf("d=2 p=1 has up to:\n%s", st)
		}
		assertBudgetWording(t, st, 1)
		assertVerifyNPlus4(t, rep)
	})

	t.Run("c_d=2_p=2", func(t *testing.T) {
		dirs := twoBlobDirs(t, bundle, shards)
		st, n, catch, rep, err := pluginVerify(t, []string{bundle, bad}, dirs)
		if err != nil {
			t.Fatal(err)
		}
		assertBudgetBeforePlugin(t, catch)
		best, bound := assertI21(t, st, n)
		if best != 4 || bound != 8 {
			t.Fatalf("d=2 p=2: best=%d bound=%d, want 4 8", best, bound)
		}
		if !strings.Contains(st, budgetLine3dir2copyP2) {
			t.Fatalf("status missing exact two-line wording:\n%s", st)
		}
		assertBudgetWording(t, st, 2)
		assertVerifyNPlus4(t, rep)
	})

	t.Run("worst_working_last", func(t *testing.T) {
		st, n, catch, _, err := pluginVerify(t, []string{bad, bundle}, []string{shards})
		if err != nil {
			t.Fatal(err)
		}
		assertBudgetBeforePlugin(t, catch)
		_, bound := assertI21(t, st, n)
		if n != bound {
			t.Fatalf("worst case: measured %d, want bound %d exactly", n, bound)
		}
		if n != 6 {
			t.Fatalf("worst case p=2 d=1 q=1: measured %d, want 6", n)
		}
	})

	t.Run("three_dirs_one_blob", func(t *testing.T) {
		dirs := []string{shards, cloneSplitDir(t, shards, 5), cloneSplitDir(t, shards, 5)}
		st, n, catch, _, err := pluginVerify(t, []string{bundle}, dirs)
		if err != nil {
			t.Fatal(err)
		}
		assertBudgetBeforePlugin(t, catch)
		best, bound := assertI21(t, st, n)
		if best != 3 || bound != 3 {
			t.Fatalf("3 dirs 1 blob: best=%d bound=%d, want 3 3 (d tracks blobs)", best, bound)
		}
		if !strings.Contains(st, budgetLine3dir1copy) {
			t.Fatalf("status missing d=1 form:\n%s", st)
		}
		if n != 3 {
			t.Fatalf("3 dirs 1 blob Interactions() = %d, want 3", n)
		}
	})
}

func TestBudgetNonInteractiveAbsent(t *testing.T) {
	restore, _ := splitFixture(t)
	var status bytes.Buffer
	n := observeRun(t)
	rep, err := Verify(context.Background(), VerifyOptions{
		IdentityPaths: restore.IdentityPaths,
		InDirs:        restore.InDirs,
	}, &status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(status.String(), "plugin interactions") {
		t.Fatalf("non-interactive status has announcement:\n%s", status.String())
	}
	if *n != 0 {
		t.Fatalf("non-interactive Interactions() = %d, want 0", *n)
	}
	assertVerifyNPlus4(t, rep)
}

func TestBudgetV1WithHardwareBundle(t *testing.T) {
	skipWindows(t)
	restore, _ := splitFixture(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{writePluginStub(t, name, fakeplugin.ModeOK)},
		Recipients:    []string{fakeplugin.Recipient(name, fakeplugin.ModeOK)},
		OutPath:       bundle,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	openN := observeOpen(t)
	st, n, catch, _, err := pluginVerify(t, []string{restore.IdentityPaths[0], bundle}, restore.InDirs)
	if err != nil {
		t.Fatal(err)
	}
	assertBudgetBeforePlugin(t, catch)
	best, bound := assertI21(t, st, n)
	if best != 3 || bound != 3 {
		t.Fatalf("v1+bundle: best=%d bound=%d, want 3 3 (q from the pin record)", best, bound)
	}
	if *openN != 0 {
		t.Fatalf("v1+bundle manifest Interactions() = %d, want 0", *openN)
	}
	if n != 0 {
		t.Fatalf("v1+bundle run Interactions() = %d, want 0 (below both figures)", n)
	}
	if !strings.Contains(st, budgetLinePDQ1) {
		t.Fatalf("v1+bundle status missing announcement:\n%s", st)
	}
}

func TestBudgetNoPinOmitsQ(t *testing.T) {
	skipWindows(t)
	restore, _ := splitFixture(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	pluginPath := writePluginIdentity(t, name, fakeplugin.ModeOK)
	st, n, catch, _, err := pluginVerify(t, []string{restore.IdentityPaths[0], pluginPath}, restore.InDirs)
	if err != nil {
		t.Fatal(err)
	}
	assertBudgetBeforePlugin(t, catch)
	best, bound := assertI21(t, st, n)
	if best != 2 || bound != 2 {
		t.Fatalf("q=0: best=%d bound=%d, want 2 2", best, bound)
	}
	if n != 0 {
		t.Fatalf("native-first q=0 Interactions() = %d, want 0", n)
	}
	if strings.Contains(st, "up to") {
		t.Fatalf("q=0 p=1 has up to:\n%s", st)
	}
	if !strings.Contains(st, "this run needs 2 plugin interactions, each of which may prompt") {
		t.Fatalf("q=0 status missing 2-interaction line:\n%s", st)
	}
}

var (
	reNeeds = regexp.MustCompile(`this run needs (\d+) plugin interactions`)
	reUpTo  = regexp.MustCompile(`up to (\d+) if every identity is tried`)
)

func parseAnnounced(t *testing.T, status string) (best, bound int) {
	t.Helper()
	m := reNeeds.FindStringSubmatch(status)
	if m == nil {
		t.Fatalf("status has no budget line:\n%s", status)
	}
	best, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if u := reUpTo.FindStringSubmatch(status); u != nil {
		bound, err = strconv.Atoi(u[1])
		if err != nil {
			t.Fatal(err)
		}
		return best, bound
	}
	return best, best
}

func assertI21(t *testing.T, status string, measured int) (best, bound int) {
	t.Helper()
	if measured < 0 {
		t.Fatal("ObserveRunInteractions was not called")
	}
	best, bound = parseAnnounced(t, status)
	if measured > bound {
		t.Fatalf("I-21: Interactions() = %d > announced bound %d (best %d)\n%s", measured, bound, best, status)
	}
	return best, bound
}

func assertBudgetWording(t *testing.T, status string, p int) {
	t.Helper()
	if status == "" && p < 1 {
		return
	}
	if !strings.Contains(status, "plugin interactions") {
		t.Fatalf("status missing %q:\n%s", "plugin interactions", status)
	}
	lower := strings.ToLower(status)
	if strings.Contains(lower, "card") {
		t.Fatalf("status contains card (D11):\n%s", status)
	}
	// Assembled: D11 forbids the consecutive literal under internal/.
	banned := "yubi" + "key"
	if strings.Contains(lower, banned) {
		t.Fatalf("status contains %s (D11):\n%s", banned, status)
	}
	if p > 1 && !strings.Contains(status, "up to") {
		t.Fatalf("p=%d status missing up to:\n%s", p, status)
	}
	if p == 1 && strings.Contains(status, "up to") {
		t.Fatalf("p=1 status has up to:\n%s", status)
	}
}

func assertBudgetBeforePlugin(t *testing.T, catch *budgetCatch) {
	t.Helper()
	if !catch.saw {
		t.Fatalf("budget line was not written; status:\n%s", catch.buf.String())
	}
	if catch.atLine != 0 {
		t.Fatalf("plugin invocations at announcement = %d, want 0", catch.atLine)
	}
}

func assertVerifyNPlus4(t *testing.T, rep *VerifyReport) {
	t.Helper()
	if rep == nil {
		t.Fatal("verify report is nil")
	}
	report := formatVerifyReport(rep)
	lines := strings.Split(strings.TrimSuffix(report, "\n"), "\n")
	want := rep.N + 4
	if len(lines) != want {
		t.Fatalf("verify stdout lines = %d, want n+4=%d\n%s", len(lines), want, report)
	}
}

func observeRun(t *testing.T) *int {
	t.Helper()
	n := new(int)
	*n = -1
	ObserveRunInteractions = func(got int) { *n = got }
	t.Cleanup(func() { ObserveRunInteractions = nil })
	return n
}

type budgetCatch struct {
	t        *testing.T
	buf      bytes.Buffer
	baseline int
	atLine   int
	saw      bool
}

func (w *budgetCatch) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("plugin interactions")) {
		w.saw = true
		w.atLine = len(fakeplugin.Invocations(w.t)) - w.baseline
	}
	return w.buf.Write(p)
}

func pluginVerify(t *testing.T, ids, dirs []string) (status string, measured int, catch *budgetCatch, rep *VerifyReport, err error) {
	t.Helper()
	n := observeRun(t)
	catch = &budgetCatch{t: t, baseline: len(fakeplugin.Invocations(t))}
	rep, err = Verify(context.Background(), VerifyOptions{
		IdentityPaths: ids,
		InDirs:        dirs,
		Terminal:      stubTerm{},
	}, catch)
	return catch.buf.String(), *n, catch, rep, err
}

func pluginRestore(t *testing.T, ids, dirs []string) (status string, measured int, catch *budgetCatch, err error) {
	t.Helper()
	n := observeRun(t)
	catch = &budgetCatch{t: t, baseline: len(fakeplugin.Invocations(t))}
	_, err = Restore(context.Background(), RestoreOptions{
		IdentityPaths: ids,
		InDirs:        dirs,
		OutPath:       filepath.Join(t.TempDir(), "out.bin"),
		Terminal:      stubTerm{},
	}, catch)
	return catch.buf.String(), *n, catch, err
}

func twoBlobDirs(t *testing.T, bundle, shards string) []string {
	t.Helper()
	dirB := cloneSplitDir(t, shards, 5)
	dirC := t.TempDir()
	copyShards(t, shards, dirC, 5)
	resealV2(t, bundle, filepath.Join(shards, "manifest.age"), filepath.Join(dirC, "manifest.age"))
	return []string{shards, dirB, dirC}
}

func resealV2(t *testing.T, bundle, src, dst string) {
	t.Helper()
	blob, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	set, err := key.LoadSet([]string{bundle}, terminalSource(stubTerm{}))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Zero()
	m, err := manifest.Open(blob, set, set)
	if err != nil {
		t.Fatal(err)
	}
	ui := key.NewClientUI(terminalSource(stubTerm{}))
	rs, err := key.ParseRecipients(set.RecordedRecipients(), ui)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := set.KeyFor(m.Version, m.MACSource)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mac)
	out, err := manifest.Seal(m, mac, rs)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(out, blob) {
		t.Fatal("reseal produced a byte-identical blob; the fixture proves nothing")
	}
	if err := os.WriteFile(dst, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
