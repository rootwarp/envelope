package pipeline

import (
	"fmt"
	"os"
)

// inDir is one resolved -in directory. given is exactly what the operator
// typed; every diagnostic is built from it (FR-MD-08). Identity is
// st_dev/st_ino via os.SameFile, never the string (AD-2).
type inDir struct {
	given string
	info  os.FileInfo // nil for the single-directory case, which is not stat'ed
}

// resolveInDirs de-duplicates by identity (os.SameFile), not by string, and
// with two or more directories checks each one before anything is read.
// With exactly one directory nothing is checked: Phase 1 surfaces the case as
// ErrNoManifest and FR-MD-05 freezes that message.
func resolveInDirs(given []string) ([]inDir, error) {
	// I7: this is not an optimisation. Phase 1 surfaces a bad single -in as
	// ErrNoManifest naming the path; an earlier Stat would replace that frozen
	// message (FR-MD-05). info is legitimately nil; nothing calls SameFile on it.
	if len(given) == 1 {
		return []inDir{{given: given[0]}}, nil
	}
	out := make([]inDir, 0, len(given))
	for _, g := range given {
		fi, err := os.Stat(g)
		if err != nil {
			return nil, fmt.Errorf("-in %s: %w", g, err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("-in %s: not a directory", g)
		}
		// Mode 0000 passes Stat; the open is what rejects it (FR-MD-07).
		d, err := os.Open(g)
		if err != nil {
			return nil, fmt.Errorf("-in %s: %w", g, err)
		}
		d.Close()
		dup := false
		for _, kept := range out {
			if os.SameFile(kept.info, fi) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		out = append(out, inDir{given: g, info: fi})
	}
	return out, nil
}
