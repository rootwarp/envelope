#!/usr/bin/env bash
# Import-graph and grep gates (FR-20, FR-19, FR-24, FR-35).
# FR-20's AC mandates D1; D2–D5 extend the same go list -deps mechanism.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
	printf '%s\n' "$@" >&2
	exit 1
}

# go list on a missing directory is an error, not an empty set.
pkg_exists() {
	[ -d "$1" ] && go list "$1" >/dev/null 2>&1
}

# Broken packages still print the offending import path; keep that text.
list_deps() {
	go list -deps "$@" 2>&1 || true
}

mod=$(go list -m)

# D1: crypt and erasure never see each other, in either direction (FR-20 AC).
if [ -d internal/crypt ]; then
	if list_deps ./internal/crypt | grep -q 'internal/erasure'; then
		fail "D1: crypt depends on erasure"
	fi
fi
if [ -d internal/erasure ]; then
	if list_deps ./internal/erasure | grep -q 'internal/crypt'; then
		fail "D1: erasure depends on crypt"
	fi
fi

# D2: pipeline imports only key, crypt, erasure, manifest + stdlib.
if pkg_exists ./internal/pipeline; then
	while IFS= read -r imp; do
		[ -n "$imp" ] || continue
		case "$imp" in
		"$mod/internal/key" | "$mod/internal/crypt" | "$mod/internal/erasure" | "$mod/internal/manifest")
			continue
			;;
		esac
		if [ "$(go list -f '{{.Standard}}' "$imp")" != true ]; then
			fail "D2: pipeline imports $imp (only key, crypt, erasure, manifest + stdlib allowed)"
		fi
	done < <(go list -deps -f '{{if eq .ImportPath "'"$mod"'/internal/pipeline"}}{{range .Imports}}{{.}}{{"\n"}}{{end}}{{end}}' ./internal/pipeline)
fi

# D3: nothing under internal/ imports pipeline; cmd/envelope is its only importer.
d3_pkgs=()
for p in ./internal/key ./internal/crypt ./internal/erasure ./internal/manifest; do
	if pkg_exists "$p"; then
		d3_pkgs+=("$p")
	fi
done
if [ "${#d3_pkgs[@]}" -gt 0 ]; then
	if list_deps "${d3_pkgs[@]}" | grep -q 'internal/pipeline'; then
		fail "D3: an internal/ package imports pipeline"
	fi
fi
if pkg_exists ./internal/pipeline; then
	while IFS= read -r importer; do
		[ -n "$importer" ] || continue
		if [ "$importer" != "$mod/cmd/envelope" ]; then
			fail "D3: $importer imports pipeline (cmd/envelope is its only importer)"
		fi
	done < <(go list -f '{{range .Imports}}{{if eq . "'"$mod"'/internal/pipeline"}}{{$.ImportPath}}{{"\n"}}{{end}}{{end}}' ./...)
fi

# D4: manifest imports key and crypt, never erasure (ADR-0004).
if [ -d internal/manifest ]; then
	if list_deps ./internal/manifest | grep -q 'internal/erasure'; then
		fail "D4: manifest depends on erasure"
	fi
fi

# D5: internal/key/bech32 is imported by internal/key and nothing else.
if pkg_exists ./internal/key/bech32; then
	while IFS= read -r importer; do
		[ -n "$importer" ] || continue
		if [ "$importer" != "$mod/internal/key" ]; then
			fail "D5: $importer imports internal/key/bech32 (only internal/key may)"
		fi
	done < <(go list -deps -f '{{range .Imports}}{{if eq . "'"$mod"'/internal/key/bech32"}}{{$.ImportPath}}{{"\n"}}{{end}}{{end}}' ./...)
fi

# FR-35: no os.Stdout / os.Stderr below the entry point …
if matches=$(grep -rn 'os\.Std\(out\|err\)' --include='*.go' internal/); then
	fail "FR-35: os.Stdout/os.Stderr under internal/" "$matches"
fi
# … and at most one reference in cmd/envelope, which must be main's one-liner.
matches=$(grep -rn 'os\.Std\(out\|err\)' --include='*.go' cmd/envelope/ 2>/dev/null \
	| grep -v 'os.Exit(run(os.Args\[1:\], os.Stdout, os.Stderr))' || true)
if [ -n "$matches" ]; then
	fail "FR-35: os.Stdout/os.Stderr in cmd/envelope besides main's one-liner" "$matches"
fi

# FR-19: no t.Log of a payload variable.
if matches=$(grep -rn 't\.Logf\?(.*\(plaintext\|payload\|secret\|scalar\|macKey\)' --include='*_test.go' .); then
	fail "FR-19: t.Log of a payload variable" "$matches"
fi

# FR-24: no identity material in tracked files.
# Needle is assembled at runtime so this file never contains the prefix+1 string.
needle="AGE-SECRET-KEY-$((1))"
if matches=$(git ls-files -z | xargs -0 grep -l -- "$needle"); then
	fail "FR-24: $needle in tracked files" "$matches"
fi
