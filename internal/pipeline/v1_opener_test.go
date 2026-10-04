package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootwarp/envelope/internal/key"
	"github.com/rootwarp/envelope/internal/manifest"
)

// TestV1RestoreOwnerListedSecond restores a v1 set when the owner's identity
// is listed second, and when it is listed first. The MAC key has to be the
// identity that opened the manifest, not whichever scalar was loaded first.
func TestV1RestoreOwnerListedSecond(t *testing.T) {
	restore, split := splitFixture(t)
	owner := restore.IdentityPaths[0]
	other := filepath.Join(t.TempDir(), "other.txt")
	id, err := key.Create(other)
	if err != nil {
		t.Fatal(err)
	}
	id.Zero()
	want, err := os.ReadFile(split.InPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		paths []string
	}{
		{"owner second", []string{other, owner}},
		{"owner first", []string{owner, other}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := restore
			opts.IdentityPaths = tc.paths
			opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
			if _, err := Restore(context.Background(), opts, io.Discard); err != nil {
				t.Fatalf("owner cannot restore: %v", err)
			}
			got, err := os.ReadFile(opts.OutPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("restored %x, want %x", got, want)
			}
		})
	}
}

// TestV1ManifestMACKeyFollowsOpener refuses a manifest encrypted to X and
// authenticated under Y, in either identity order. Accepting the Y-then-X
// order would mean any loaded scalar may verify the blob.
func TestV1ManifestMACKeyFollowsOpener(t *testing.T) {
	restore, split := splitFixture(t)
	x := restore.IdentityPaths[0]
	y := filepath.Join(t.TempDir(), "y.txt")
	id, err := key.Create(y)
	if err != nil {
		t.Fatal(err)
	}
	id.Zero()
	rewriteManifestMAC(t, x, y, filepath.Join(split.OutDir, "manifest.age"))
	for _, tc := range []struct {
		name  string
		paths []string
	}{
		{"Y then X", []string{y, x}},
		{"X then Y", []string{x, y}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := restore
			opts.IdentityPaths = tc.paths
			opts.OutPath = filepath.Join(t.TempDir(), "out.bin")
			_, err := Restore(context.Background(), opts, io.Discard)
			if !errors.Is(err, manifest.ErrMACMismatch) {
				t.Fatalf("errors.Is(., ErrMACMismatch) = false: %v", err)
			}
			assertNoOutOrPartial(t, opts.OutPath)
		})
	}
}

// TestV1TwoOwnersConflictInEitherOrder reports a conflict when one run is
// given two owners' v1 manifests, in either identity order. One owner's
// identity alone still restores that owner's set.
func TestV1TwoOwnersConflictInEitherOrder(t *testing.T) {
	aDir, aID := splitWithPayload(t, []byte("owner-a"))
	bDir, bID := splitWithPayload(t, []byte("owner-b"))
	for _, tc := range []struct {
		name  string
		paths []string
	}{
		{"X then Y", []string{aID, bID}},
		{"Y then X", []string{bID, aID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out.bin")
			_, err := Restore(context.Background(), RestoreOptions{
				IdentityPaths: tc.paths,
				InDirs:        []string{aDir, bDir},
				OutPath:       out,
			}, io.Discard)
			if !errors.Is(err, ErrConflictingManifests) {
				t.Fatalf("errors.Is(., ErrConflictingManifests) = false: %v", err)
			}
			if !strings.Contains(err.Error(), "describe different shard sets") {
				t.Fatalf("err = %v, want same-version conflict", err)
			}
			assertNoOutOrPartial(t, out)
		})
	}

	t.Run("one owner", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.bin")
		_, err := Restore(context.Background(), RestoreOptions{
			IdentityPaths: []string{aID},
			InDirs:        []string{aDir, bDir},
			OutPath:       out,
		}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte("owner-a")) {
			t.Fatalf("restored %q, want owner-a", got)
		}
	})
}

func splitWithPayload(t *testing.T, payload []byte) (dir, idPath string) {
	t.Helper()
	dir = t.TempDir()
	idPath = filepath.Join(t.TempDir(), "identity.txt")
	id, err := key.Create(idPath)
	if err != nil {
		t.Fatal(err)
	}
	id.Zero()
	inPath := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(inPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Split(context.Background(), SplitOptions{
		IdentityPath: idPath,
		InPath:       inPath,
		OutDir:       dir,
		K:            3,
		N:            5,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	return dir, idPath
}

// rewriteManifestMAC keeps the body encrypted to encPath and replaces the MAC
// with macPath's scalar key. The shards stay the encrypting identity's.
func rewriteManifestMAC(t *testing.T, encPath, macPath, manifestPath string) {
	t.Helper()
	blob, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := key.Load(encPath)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Zero()
	m, err := manifest.Open(blob, enc, enc)
	if err != nil {
		t.Fatal(err)
	}
	macID, err := key.Load(macPath)
	if err != nil {
		t.Fatal(err)
	}
	defer macID.Zero()
	macKey, err := macID.ManifestMACKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(macKey)
	out, err := manifest.Seal(m, macKey, enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
