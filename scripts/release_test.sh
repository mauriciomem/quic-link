#!/usr/bin/env bash
#
# @spec-handoff
# @interface scripts/release.sh VERSION [--check]  (exit 0 on success, non-zero on refusal)
# @behavior
#   - Clean checkout: `release.sh v0.0.0-test --check` exits 0, builds every
#     target, and reports the build reproducible; stderr has no "unbound variable".
#   - Modified tracked file: exits non-zero before building, stderr contains
#     "FAIL: tracked files are modified" and no "unbound variable".
# @edge-cases
#   - Untracked non-Go files only: not refused (not exercised here).
#   - Runs against a local clone of the committed HEAD in a mktemp dir: no
#     network, nothing written outside the temp dir (GOCACHE is shared, by design
#     of the Go toolchain, but is a cache, not repo state).
# @see ./release.sh
#
# Usage:
#   scripts/release_test.sh
#
# Tests the committed HEAD, not the working tree: uncommitted changes to
# release.sh are not seen. Commit before running.

set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failed=0

pass() { echo "PASS: $1"; }
fail() {
	echo "FAIL: $1" >&2
	failed=1
}

fresh_clone() {
	local dir="$work/$1"
	git clone --quiet --no-hardlinks "$repo" "$dir"
	echo "$dir"
}

# Case 1: clean checkout builds and verifies reproducibility.
case1="clean checkout: release.sh --check succeeds"
dir=$(fresh_clone clean)
status=0
"$dir/scripts/release.sh" v0.0.0-test --check >"$work/clean.out" 2>"$work/clean.err" || status=$?
if grep -q 'unbound variable' "$work/clean.err"; then
	fail "$case1 (stderr has 'unbound variable')"
	sed 's/^/    /' "$work/clean.err" >&2
elif grep -q 'FAIL: tracked files are modified' "$work/clean.err"; then
	fail "$case1 (clean tree refused as dirty)"
elif [ "$status" -ne 0 ]; then
	fail "$case1 (exit $status)"
	sed 's/^/    /' "$work/clean.err" >&2
elif ! grep -q 'identical from two directories' "$work/clean.out"; then
	fail "$case1 (reproducibility check did not run)"
else
	pass "$case1"
fi

# Case 2: a modified tracked file is refused by the dirty-tree guard.
case2="modified tracked file: release.sh refuses"
dir=$(fresh_clone dirty)
echo "# local modification" >>"$dir/README.md"
status=0
"$dir/scripts/release.sh" v0.0.0-test >"$work/dirty.out" 2>"$work/dirty.err" || status=$?
if grep -q 'unbound variable' "$work/dirty.err"; then
	fail "$case2 (stderr has 'unbound variable')"
	sed 's/^/    /' "$work/dirty.err" >&2
elif [ "$status" -eq 0 ]; then
	fail "$case2 (exit 0)"
elif ! grep -q 'FAIL: tracked files are modified' "$work/dirty.err"; then
	fail "$case2 (no dirty-tree FAIL on stderr)"
	sed 's/^/    /' "$work/dirty.err" >&2
else
	pass "$case2"
fi

exit "$failed"
