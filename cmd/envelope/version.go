package main

import (
	"errors"
	"fmt"
	"io"
	"runtime/debug"
)

func isVersionArg(args []string) bool {
	return len(args) > 0 && (args[0] == "-version" || args[0] == "--version")
}

func printVersion(w io.Writer) error {
	info, ok := debug.ReadBuildInfo()
	return writeVersion(w, info, ok)
}

func writeVersion(w io.Writer, info *debug.BuildInfo, ok bool) error {
	if !ok {
		return errors.New("build info unavailable")
	}
	fmt.Fprintf(w, "envelope %s\n", info.Main.Version)
	for _, m := range info.Deps {
		switch m.Path {
		case "filippo.io/age", "github.com/klauspost/reedsolomon":
			ver := m.Version
			if m.Replace != nil {
				ver = m.Replace.Version
			}
			fmt.Fprintf(w, "%s %s\n", m.Path, ver)
		}
	}
	return nil
}
