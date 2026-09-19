package main

import (
	"bytes"
	"runtime/debug"
	"testing"
)

// FR-P2-06
func TestVersionBuildInfoUnavailable(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := writeVersion(&out, nil, false)
	code := exitCode(err, &errBuf)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	if got, want := errBuf.String(), "build info unavailable\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
}

// FR-P2-06
func TestWriteVersionHonorsReplace(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-test"},
		Deps: []*debug.Module{
			{
				Path:    "filippo.io/age",
				Version: "v1.3.1",
				Replace: &debug.Module{Path: "example.com/age", Version: "v9.9.9-replace"},
			},
			{
				Path:    "github.com/klauspost/reedsolomon",
				Version: "v1.14.2",
			},
		},
	}
	var out bytes.Buffer
	if err := writeVersion(&out, info, true); err != nil {
		t.Fatal(err)
	}
	want := "envelope v0.0.0-test\nfilippo.io/age v9.9.9-replace\ngithub.com/klauspost/reedsolomon v1.14.2\n"
	if got := out.String(); got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}
