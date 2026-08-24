#!/usr/bin/env bash
#
# Protocol checks: style, then compatibility.
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
