//go:build unix

package pipeline

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

type gateTerm struct {
	started chan struct{}
	release chan struct{}
}

func (g *gateTerm) Notify(string) {}
func (g *gateTerm) Close() error  { return nil }

func (g *gateTerm) ReadLine(string, bool) (string, error) {
	select {
	case <-g.started:
	default:
		close(g.started)
	}
	<-g.release
	return fakeplugin.PIN, nil
}

func TestPluginChildSharesProcessGroup(t *testing.T) {
	skipWindows(t)
	name := "envtest"
	fakeplugin.Install(t, name)
	stub := writePluginStub(t, name, fakeplugin.ModePIN)
	rec := fakeplugin.Recipient(name, fakeplugin.ModeOK)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{stub},
		Recipients:    []string{rec},
		OutPath:       bundle,
		Terminal:      stubTerm{},
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("pgid"), 0o600); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	term := &gateTerm{started: started, release: release}

	errc := make(chan error, 1)
	go func() {
		_, err := Split(context.Background(), SplitOptions{
			IdentityPath: bundle,
			InPath:       in,
			OutDir:       t.TempDir(),
			K:            3,
			N:            5,
			Terminal:     term,
		}, io.Discard)
		errc <- err
	}()

	select {
	case <-started:
	case err := <-errc:
		t.Fatalf("split returned before PIN prompt: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for PIN prompt")
	}

	our, err := syscall.Getpgid(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	var live []int
	for _, pid := range fakeplugin.PIDs(t) {
		if err := syscall.Kill(pid, 0); err == nil {
			live = append(live, pid)
		}
	}
	if len(live) == 0 {
		t.Fatal("no live plugin process during PIN prompt")
	}
	for _, pid := range live {
		got, err := syscall.Getpgid(pid)
		if err != nil {
			t.Fatalf("Getpgid(%d): %v", pid, err)
		}
		if got != our {
			t.Fatalf("plugin %d pgid=%d, ours=%d — a terminal Ctrl-C would not reach it", pid, got, our)
		}
	}

	close(release)
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("split did not finish after PIN")
	}
}
