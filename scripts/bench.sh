#!/usr/bin/env bash
#
# Run the benchmarks.
#
# Two modes, because they answer different questions:
#
#   scripts/bench.sh            measure, and print the numbers
#   scripts/bench.sh --check    only verify the benchmarks still compile and run
#
# The second is what belongs in CI. Timings on a shared runner may vary enough to 
# hide any regression worth finding and narrow enough to look meaningful, so 
# gating on them would produce noise with a decimal point. 
# What CI can usefully assert is that a benchmark has not silently
# stopped compiling, because a benchmark nobody can run is a benchmark nobody has.
#
# For an actual comparison, run this on both sides of a change with -count=10 or
# more and put the two outputs through benchstat, which reports whether a
# difference is statistically distinguishable from noise:
#
#   go install golang.org/x/perf/cmd/benchstat@latest
#   git stash && scripts/bench.sh > /tmp/base.txt && git stash pop
#   scripts/bench.sh > /tmp/new.txt
#   benchstat /tmp/base.txt /tmp/new.txt
#
# Read the allocation columns first. B/op and allocs/op are properties of the
# code and do not move between runs; ns/op is a hint.

set -euo pipefail

cd "$(dirname "$0")/.."

packages=(./internal/names/ ./internal/proto/)

if [ "${1:-}" = "--check" ]; then
	# One iteration each: enough to prove every benchmark builds and runs.
	go test -run '^$' -bench . -benchtime 1x "${packages[@]}"
	echo "every benchmark compiles and runs"
	exit 0
fi

count="${1:-10}"
go test -run '^$' -bench . -benchmem -count="$count" "${packages[@]}"
