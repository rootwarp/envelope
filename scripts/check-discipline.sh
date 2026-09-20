#!/usr/bin/env bash
# Import-graph and grep gates (FR-20, FR-19, FR-24, FR-35, FR-YK-18, FR-YK-08).
# D1: crypt and erasure never depend on each other (FR-20 AC).
# D2: pipeline imports only key, crypt, erasure, manifest + stdlib.
# D3: nothing under internal/ imports pipeline; cmd/envelope is its only importer.
# D4: manifest imports no internal package.
# D5: internal/key/bech32 and internal/key/tty are imported by internal/key only.
# D6: only cmd/envelope may import github.com/urfave/cli/v3.
# D7: cmd/envelope imports only pipeline, urfave/cli/v3 + stdlib.
# D8: internal/key may import only internal/key/bech32, internal/key/tty, internal/crypt, filippo.io/age, filippo.io/age/plugin, golang.org/x/term + stdlib.
# D9: filippo.io/age/plugin is imported by internal/key and test/fakeplugin only.
# D10: test/fakeplugin is imported by _test.go files only.
# D11: the literal yubikey appears nowhere under internal/ or cmd/.
# D12: SysProcAttr / Setpgid appear nowhere in the tree.
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

# D2 (identifier): pipeline and cmd/envelope non-test sources never name an age.* type (AD-2).
age_id_paths=()
[ -d internal/pipeline ] && age_id_paths+=(internal/pipeline)
[ -d cmd/envelope ] && age_id_paths+=(cmd/envelope)
if [ "${#age_id_paths[@]}" -gt 0 ]; then
	if matches=$(grep -rn --include='*.go' --exclude='*_test.go' '\bage\.[A-Z]' "${age_id_paths[@]}"); then
		fail "D2: age. identifier in pipeline or cmd/envelope" "$matches"
	fi
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

# D4: manifest imports no $mod/internal/... package at all (ADR-0004).
if pkg_exists ./internal/manifest; then
	while IFS= read -r dep; do
		[ -n "$dep" ] || continue
		case "$dep" in
		"$mod/internal/manifest") continue ;;
		"$mod/internal/"*)
			fail "D4: manifest imports $dep (no internal package allowed)"
			;;
		esac
	done < <(list_deps ./internal/manifest)
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

# D5: internal/key/tty is imported by internal/key and nothing else.
if pkg_exists ./internal/key/tty; then
	while IFS= read -r importer; do
		[ -n "$importer" ] || continue
		if [ "$importer" != "$mod/internal/key" ]; then
			fail "D5: $importer imports internal/key/tty (only internal/key may)"
		fi
	done < <(go list -deps -f '{{range .Imports}}{{if eq . "'"$mod"'/internal/key/tty"}}{{$.ImportPath}}{{"\n"}}{{end}}{{end}}' ./...)
fi

# D6: only cmd/envelope may import github.com/urfave/cli/v3.
while IFS= read -r rec; do
	[ -n "$rec" ] || continue
	imp=${rec%% *}
	pkg=${rec#* }
	case "$imp" in
	github.com/urfave/cli/v3 | github.com/urfave/cli/v3/*) ;;
	*) continue ;;
	esac
	if [ "$pkg" != "$mod/cmd/envelope" ]; then
		fail "D6: $pkg imports github.com/urfave/cli/v3 (only cmd/envelope may)"
	fi
done < <(go list -f '{{range .Imports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}{{range .TestImports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}{{range .XTestImports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}' ./...)

# D7: cmd/envelope imports only pipeline, github.com/urfave/cli/v3 + stdlib.
if pkg_exists ./cmd/envelope; then
	while IFS= read -r imp; do
		[ -n "$imp" ] || continue
		case "$imp" in
		"$mod/internal/pipeline" | "github.com/urfave/cli/v3")
			continue
			;;
		esac
		if [ "$(go list -f '{{.Standard}}' "$imp")" != true ]; then
			fail "D7: cmd/envelope imports $imp (only pipeline, github.com/urfave/cli/v3 + stdlib allowed)"
		fi
	done < <(go list -deps -f '{{if eq .ImportPath "'"$mod"'/cmd/envelope"}}{{range .Imports}}{{.}}{{"\n"}}{{end}}{{end}}' ./cmd/envelope)
fi

# D8: internal/key may import only internal/key/bech32, internal/key/tty, internal/crypt, filippo.io/age, filippo.io/age/plugin, golang.org/x/term + stdlib.
# Inspect Imports+TestImports+XTestImports (D6's form) of the key package itself.
# test/fakeplugin is TestMain dispatch; D10 already forbids it from non-test sources.
if pkg_exists ./internal/key; then
	while IFS= read -r rec; do
		[ -n "$rec" ] || continue
		imp=${rec%% *}
		pkg=${rec#* }
		if [ "$pkg" != "$mod/internal/key" ]; then
			continue
		fi
		case "$imp" in
		"$mod/internal/key/bech32" | "$mod/internal/key/tty" | "$mod/internal/crypt" | "filippo.io/age" | "filippo.io/age/plugin" | "golang.org/x/term" | "$mod/test/fakeplugin")
			continue
			;;
		esac
		if [ "$(go list -f '{{.Standard}}' "$imp")" != true ]; then
			fail "D8: internal/key imports $imp (only internal/key/bech32, internal/key/tty, internal/crypt, filippo.io/age, filippo.io/age/plugin, golang.org/x/term + stdlib allowed)"
		fi
	done < <(go list -f '{{range .Imports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}{{range .TestImports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}{{range .XTestImports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}' ./internal/key)
fi

# D9: filippo.io/age/plugin is imported by internal/key and test/fakeplugin only.
# Inspect .Imports, .TestImports and .XTestImports (D6's form, not D5's).
while IFS= read -r rec; do
	[ -n "$rec" ] || continue
	imp=${rec%% *}
	pkg=${rec#* }
	case "$imp" in
	filippo.io/age/plugin | filippo.io/age/plugin/*) ;;
	*) continue ;;
	esac
	case "$pkg" in
	"$mod/internal/key" | "$mod/test/fakeplugin") continue ;;
	esac
	fail "D9: $pkg imports filippo.io/age/plugin (only internal/key and test/fakeplugin may)"
done < <(go list -f '{{range .Imports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}{{range .TestImports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}{{range .XTestImports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}' ./...)

# D10: test/fakeplugin is imported by _test.go files only (.Imports, not test imports).
while IFS= read -r rec; do
	[ -n "$rec" ] || continue
	imp=${rec%% *}
	pkg=${rec#* }
	if [ "$imp" = "$mod/test/fakeplugin" ]; then
		fail "D10: $pkg imports test/fakeplugin from non-test sources (only _test.go files may)"
	fi
done < <(go list -f '{{range .Imports}}{{.}} {{$.ImportPath}}{{"\n"}}{{end}}' ./...)

# D11: the literal yubikey appears nowhere under internal/ or cmd/.
d11_paths=()
[ -d internal ] && d11_paths+=(internal)
[ -d cmd ] && d11_paths+=(cmd)
if [ "${#d11_paths[@]}" -gt 0 ]; then
	if matches=$(grep -rniI 'yubikey' "${d11_paths[@]}"); then
		fail "D11: yubikey literal under internal/ or cmd/" "$matches"
	fi
fi

# D12: SysProcAttr / Setpgid appear nowhere in the tree.
if matches=$(grep -rnE --include='*.go' 'SysProcAttr|Setpgid' .); then
	fail "D12: SysProcAttr / Setpgid in the tree" "$matches"
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

# U1: no framework-global assignment in cmd/envelope (non-test).
if matches=$(grep -rnE --include='*.go' --exclude='*_test.go' 'cli\.[A-Z][A-Za-z]* *=([^=]|$)' cmd/envelope/); then
	fail "U1: framework-global assignment in cmd/envelope" "$matches"
fi
# U2: no cli.Exit( in cmd/envelope (non-test).
if matches=$(grep -rn --include='*.go' --exclude='*_test.go' 'cli\.Exit(' cmd/envelope/); then
	fail "U2: cli.Exit( in cmd/envelope" "$matches"
fi
# U3: no signal.Notify( in cmd/envelope (non-test).
if matches=$(grep -rn --include='*.go' --exclude='*_test.go' 'signal\.Notify(' cmd/envelope/); then
	fail "U3: signal.Notify( in cmd/envelope" "$matches"
fi
# U4: no os.Remove in cmd/envelope (non-test).
if matches=$(grep -rn --include='*.go' --exclude='*_test.go' 'os\.Remove' cmd/envelope/); then
	fail "U4: os.Remove in cmd/envelope" "$matches"
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
