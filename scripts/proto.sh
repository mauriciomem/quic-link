#!/usr/bin/env bash
#
# Protocol checks: style, then compatibility.
#
# The second is the one worth having. The wire protocol is versioned, and the
# rule is that any change to frame layout, field semantics or status codes bumps
# the version. Until now that rule was enforced by a human noticing. `buf
# breaking` enforces it mechanically, and it is not vacuous: renaming a single
# response field makes it fail, naming both the field and the changed json_name.
#
# Two style rules are excluded in buf.yaml, with reasons, because obeying them
# would move the proto directory and rename the service — both of which change
# what peers see on the wire, to satisfy a linter.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v buf >/dev/null; then
	echo "buf is not on PATH. Install it with:" >&2
	echo "  go install github.com/bufbuild/buf/cmd/buf@v1.72.0" >&2
	exit 1
fi

# The ref to compare against. Locally the default branch is the useful baseline;
# in CI the base of the pull request is passed in.
against="${1:-.git#ref=origin/main}"

echo "=== buf lint"
buf lint

echo "=== buf breaking against $against"
buf breaking --against "$against"

echo "protocol checks passed"
