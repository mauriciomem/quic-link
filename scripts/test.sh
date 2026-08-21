#!/usr/bin/env bash
#
# Run the test suite the way CI runs it, and vice versa.
#
# This script is the single definition of "run the tests". The GitHub Actions
# workflow calls it rather than repeating its steps, so local and CI results
# cannot drift apart by accident.
#
# Usage:
#   scripts/test.sh              # build, vet, test, and assert the result counts
#   scripts/test.sh --race       # the same, with the race detector
#   scripts/test.sh --tags TAGS  # the same, with extra build tags
#
# THE ORDER OF THE STEPS IS THE POINT
#
# Build first, on its own. A package that fails to compile makes `go test` report
# far fewer results while still failing, and the cheapest way to tell "the tree
# is broken" from "a test is broken" is to try building it — which takes a
# fraction of a second and cannot be misread.
#
# Then test, capturing output to a file, and check the exit status BEFORE counting
# anything. Piping `go test` straight into a counter reports the counter's exit
# status, so a failing suite can look like a passing one. That is not theoretical:
# it is what a first draft of this script did.
#
# Then count, from the saved file. Counting is a check for results going missing,
# not a check that they passed.

set -euo pipefail

cd "$(dirname "$0")/.."

race=""
tags=""
while [ $# -gt 0 ]; do
	case "$1" in
	--race)
		race="-race"
		shift
		;;
	--tags)
		tags="-tags $2"
		shift 2
		;;
	*)
		echo "usage: $0 [--race] [--tags TAGS]" >&2
		exit 2
		;;
	esac
done

# shellcheck disable=SC2086 # $race and $tags are deliberately word-split.
goflags="$race $tags"

expected_file="scripts/expected-counts.txt"
want_cli=$(sed -n 's/^cmd_quic_link=//p' "$expected_file")
want_tree=$(sed -n 's/^tree_wide=//p' "$expected_file")
if [ -z "$want_cli" ] || [ -z "$want_tree" ]; then
	echo "FAIL: could not read expected counts from $expected_file" >&2
	exit 1
fi

# countResults counts reported top-level test results in a saved log.
#
# awk rather than `grep -c`, for two reasons that both cost real time to
# rediscover: `grep -c` exits 1 when it matches nothing, which under `set -e`
# aborts the script before it can print the diagnostic that would explain why;
# and the obvious guard for that, `grep -c ... || echo 0`, prints "0" twice
# because grep prints its zero before exiting non-zero. awk has neither problem.
countResults() {
	awk '/^--- (PASS|SKIP|FAIL): Test/ { n++ } END { print n + 0 }' "$1"
}

step() { printf '\n=== %s\n' "$1"; }

step "build"
go build $goflags ./...

step "gofmt"
unformatted=$(gofmt -l . || true)
if [ -n "$unformatted" ]; then
	echo "FAIL: these files are not gofmt-clean:" >&2
	echo "$unformatted" >&2
	exit 1
fi

step "vet"
go vet $goflags ./...

log_dir=$(mktemp -d)
trap 'rm -rf "$log_dir"' EXIT

# checkPackage runs one scope, checks its status, then compares its count.
checkPackage() {
	local label="$1" pattern="$2" want="$3" log="$log_dir/$1.log" status=0

	step "test $label (expecting $want reported results)"
	go test -v -count=1 $goflags "$pattern" >"$log" 2>&1 || status=$?

	local got
	got=$(countResults "$log")

	if [ "$status" -ne 0 ]; then
		echo "FAIL: go test exited $status for $pattern; $got results were reported." >&2
		echo "" >&2

		# Print each failing test with the lines that precede it, because that is
		# where the reason is. Go writes a t.Errorf message indented, BEFORE the
		# "--- FAIL:" line it belongs to, so listing only the FAIL lines reports
		# which tests failed and not one word about why — which is useless on a
		# platform the maintainer cannot reproduce locally.
		awk '
			/^(--- FAIL|    --- FAIL)/ {
				print "  " $0
				for (i = 1; i <= n; i++) print "      " buf[i]
				n = 0
				next
			}
			/^(=== RUN|=== PAUSE|=== CONT|--- PASS|    --- PASS|--- SKIP|    --- SKIP|ok  |PASS|=== NAME)/ { n = 0; next }
			{ if (n < 40) buf[++n] = $0 }
		' "$log" >&2

		# Build failures, panics and timeouts produce no result line at all, so
		# they are reported separately.
		grep -E '\[build failed\]|^panic:|test timed out|^FAIL[[:space:]]' "$log" >&2 || true

		echo "" >&2
		echo "      Full log: $log" >&2
		return 1
	fi

	if [ "$got" -ne "$want" ]; then
		echo "FAIL: $pattern reported $got results, expected $want (difference $((got - want)))." >&2
		echo "      go test passed, so nothing failed — results appeared or went missing." >&2
		echo "      If the change is intended, update $expected_file in this commit." >&2
		return 1
	fi

	echo "ok: $got results, as expected"
}

failures=0
checkPackage "cli" "./cmd/quic-link/" "$want_cli" || failures=1
checkPackage "tree" "./..." "$want_tree" || failures=1

if [ "$failures" -ne 0 ]; then
	exit 1
fi

printf '\n=== all checks passed\n'
