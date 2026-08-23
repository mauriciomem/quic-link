#!/usr/bin/env bash
#
# Check that every module compiled into the binary is named in
# THIRD-PARTY-NOTICES.md.
#
# That file states its own obligation plainly: a dependency added without
# updating it is a licence violation in any shipped binary, not an administrative
# omission. It drifted anyway — google.golang.org/genproto/googleapis/rpc was
# compiled in and absent for months — which is the argument for checking rather
# than remembering.
#
# It compares against the BUILD CLOSURE (`go list -deps`), not the module graph
# (`go list -m all`). The closure is the set whose licences actually attach to a
# shipped artifact; the graph additionally contains test-only and tooling modules
# that are never distributed.
#
# NAMES ONLY, DELIBERATELY
#
# Versions are not checked. A licence obligation attaches to a module rather than
# to a particular release of one, so comparing versions bought no legal precision
# and made every routine dependency bump falsify the notices file — which turned
# each bump into a two-file change and, with ungrouped dependency updates, made
# overlapping upgrades invalidate one another's notices. What this checks is the
# thing that is actually true or false: whether every module inside the shipped
# binary is attributed.

set -euo pipefail

cd "$(dirname "$0")/.."

notices="THIRD-PARTY-NOTICES.md"
if [ ! -f "$notices" ]; then
	echo "FAIL: $notices does not exist" >&2
	exit 1
fi

missing=0

# The main module is in its own build closure and needs no third-party notice for
# itself, so it is excluded by name. Previously this fell out of skipping entries
# with an empty version, which no longer applies now that versions are not read.
own_module=$(go list -m)

while read -r module; do
	if [ "$module" = "$own_module" ]; then
		continue
	fi
	# The module is expected inside backticks, which is how every entry is
	# written; matching that way avoids a substring hit on a longer path.
	if ! grep -qF "\`$module\`" "$notices"; then
		echo "MISSING: $module is compiled into the binary but is not named in $notices" >&2
		missing=$((missing + 1))
	fi
done < <(go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./cmd/quic-link | sort -u)

if [ "$missing" -ne 0 ]; then
	echo "" >&2
	echo "$missing module(s) missing." >&2
	echo "Add them to $notices under the right licence heading, in the same commit" >&2
	echo "as the dependency change. If a new module is Apache-2.0, check whether it" >&2
	echo "ships a NOTICE file that must be reproduced." >&2
	exit 1
fi

echo "every compiled-in module is named in $notices"
