package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rootwarp/envelope/test/fakeplugin"
)

// lateCancelCtx passes Bind's entry check and reports context.Canceled on
// every later Err, so the publish check is what aborts. No package hook.
type lateCancelCtx struct {
	context.Context
	calls int
}

func newLateCancelCtx() *lateCancelCtx {
	return &lateCancelCtx{Context: context.Background()}
}

func (c *lateCancelCtx) Err() error {
	c.calls++
	if c.calls == 1 {
		return nil
	}
	return context.Canceled
}

func TestBindCanceledBeforePublishWritesNothing(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		path, rec := mustNativeID(t)
		out := filepath.Join(t.TempDir(), "bundle.txt")
		_, err := Bind(newLateCancelCtx(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{path},
			Recipients:    []string{rec},
			OutPath:       out,
		}, io.Discard)
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		assertPathAbsent(t, out)
		assertPathAbsent(t, out+".tmp")
	})

	t.Run("add-recipient", func(t *testing.T) {
		pathA, recA := mustNativeID(t)
		_, recB := mustNativeID(t)
		bundle := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{pathA},
			Recipients:    []string{recA},
			OutPath:       bundle,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Bind(newLateCancelCtx(), BindOptions{
			Mode:       BindAddRecipient,
			BundlePath: bundle,
			Recipients: []string{recB},
		}, io.Discard)
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatal("errors.Is(., context.Canceled) = false")
		}
		after, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("canceled add-recipient changed the bundle")
		}
		assertPathAbsent(t, bundle+".tmp")
	})

	t.Run("replace-identity", func(t *testing.T) {
		pathA, recA := mustNativeID(t)
		pathB, _ := mustNativeID(t)
		bundle := filepath.Join(t.TempDir(), "bundle.txt")
		if _, err := Bind(context.Background(), BindOptions{
			Mode:          BindCreate,
			IdentityPaths: []string{pathA},
			Recipients:    []string{recA},
			OutPath:       bundle,
		}, io.Discard); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Bind(newLateCancelCtx(), BindOptions{
			Mode:          BindReplaceIdentity,
			BundlePath:    bundle,
			IdentityPaths: []string{pathB},
		}, io.Discard)
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatal("errors.Is(., context.Canceled) = false")
		}
		after, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("canceled replace-identity changed the bundle")
		}
		assertPathAbsent(t, bundle+".tmp")
	})
}

type promptCancelTerm struct {
	cancel context.CancelFunc
}

func (*promptCancelTerm) Notify(string) {}
func (t *promptCancelTerm) ReadLine(string, bool) (string, error) {
	t.cancel()
	return fakeplugin.PIN, nil
}
func (*promptCancelTerm) Close() error { panic("borrowed terminal Close called") }

func TestBindCancelDuringPromptCommitsNothing(t *testing.T) {
	skipWindows(t)
	fakeplugin.Install(t, "envtest")
	stub := writePluginStub(t, "envtest", fakeplugin.ModePIN)
	bundle := filepath.Join(t.TempDir(), "bundle.txt")
	if _, err := Bind(context.Background(), BindOptions{
		Mode:          BindCreate,
		IdentityPaths: []string{stub},
		Recipients:    []string{fakeplugin.Recipient("envtest", fakeplugin.ModeOK)},
		OutPath:       bundle,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	_, rec := mustNativeID(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = Bind(ctx, BindOptions{
		Mode:       BindAddRecipient,
		BundlePath: bundle,
		Recipients: []string{rec},
		Terminal:   &promptCancelTerm{cancel: cancel},
	}, io.Discard)
	after, rerr := os.ReadFile(bundle)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if err != context.Canceled || !bytes.Equal(before, after) {
		t.Fatalf("canceled bind committed update: err=%v, bundleChanged=%v", err, !bytes.Equal(before, after))
	}
	assertPathAbsent(t, bundle+".tmp")
}
