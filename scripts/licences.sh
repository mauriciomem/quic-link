#!/usr/bin/env bash
#
# Check that every module compiled into the binary is named in
# THIRD-PARTY-NOTICES.md, at the version actually being built.
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
# Versions are compared too, not just names. The file pins them, so a routine
# dependency bump makes it stale even when the set of modules has not changed.

set -euo pipefail

cd "$(dirname "$0")/.."

notices="THIRD-PARTY-NOTICES.md"
if [ ! -f "$notices" ]; then
	echo "FAIL: $notices does not exist" >&2
	exit 1
fi

missing=0
stale=0

while read -r module version; do
	# The main module carries no version and needs no third-party notice.
	if [ -z "$version" ]; then
		continue
	fi

	# The module is expected inside backticks, which is how every entry is
	# written; matching that way avoids a substring hit on a longer path.
	if ! grep -qF "\`$module\`" "$notices"; then
		echo "MISSING: $module $version is compiled into the binary but is not named in $notices" >&2
		missing=$((missing + 1))
		continue
	fi

	# Take the first version-looking token on the module's line.
	noted=$(grep -F "\`$module\`" "$notices" | head -1 |
		grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+[^ |]*' | head -1 || true)
	if [ "$noted" != "$version" ]; then
		echo "STALE: $module is built at $version but $notices says ${noted:-nothing}" >&2
		stale=$((stale + 1))
	fi
done < <(go list -deps -f '{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/quic-link | sort -u)

if [ "$missing" -ne 0 ] || [ "$stale" -ne 0 ]; then
	echo "" >&2
	echo "$missing module(s) missing, $stale at the wrong version." >&2
	echo "Update $notices in the same commit as the dependency change." >&2
	exit 1
fi

echo "every compiled-in module is named in $notices at the version being built"
