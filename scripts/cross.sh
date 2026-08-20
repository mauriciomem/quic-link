#!/usr/bin/env bash
#
# Check that every platform this project ships for still compiles.
#
# `go build`, not `go vet`. Vet is slower here and, more importantly, it also
# type-checks test files, which fails on 32-bit targets over a deliberate
# boundary value in a test (a port number of 1<<33, chosen to prove an
# impossible port is refused, does not fit a 32-bit int). Those targets build
# and ship correctly; only their tests cannot be compiled for them.
#
# Windows is absent on purpose. The tree does not compile for it, and that is
# currently load-bearing: the unix-socket peer-credential check has no Windows
# equivalent, so a Windows binary would start a daemon that refuses every
# connection from its own CLI. A build failure is the better of those two.

set -euo pipefail

cd "$(dirname "$0")/.."

targets=(
	linux/amd64
	linux/arm64
	darwin/amd64
	darwin/arm64
	freebsd/amd64
)

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

failed=0
for target in "${targets[@]}"; do
	goos=${target%/*}
	goarch=${target#*/}
	printf '%-16s ' "$target"
	if CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -o "$out/quic-link-$goos-$goarch" ./cmd/quic-link 2>"$out/err"; then
		printf 'ok  %s bytes\n' "$(wc -c <"$out/quic-link-$goos-$goarch" | tr -d ' ')"
	else
		printf 'FAILED\n'
		sed 's/^/    /' "$out/err"
		failed=1
	fi
done

if [ "$failed" -ne 0 ]; then
	echo "cross-compilation failed for at least one target" >&2
	exit 1
fi

echo "all ${#targets[@]} targets build"
