#!/usr/bin/env bash
#
# Build the release artifacts for a version.
#
# Usage:
#   scripts/release.sh v0.1.0            # build into dist/
#   scripts/release.sh v0.1.0 --check    # build, then verify reproducibility
#
# Called by the release workflow and usable by hand, so what CI publishes and what
# can be reproduced locally are the same bytes.
#
#   CGO_ENABLED=0   a static binary with no host C toolchain in its inputs.
#   -trimpath       removes build directory paths, so two people building the
#                   same commit in different directories get the same bytes.
#   -buildvcs=false required for that to actually hold: without it the toolchain
#                   stamps the commit and the dirty flag, which differ between a
#                   checkout and an export. The cost is real and is accepted
#                   deliberately — see below.
#   -tags grpcnotrace  drops an unused tracing package from gRPC, and with it
#                   html/template, for 475 KB. Upstream-supported; changes no
#                   observable output, verified across every JSON surface.
#   -ldflags "-s -w"  strips the symbol and DWARF tables for about a third of the
#                   size. Panic traces are unaffected, because those use a
#                   different table that these flags do not touch.
#   -X ...version   the tag, and the commit, injected as strings.
#
# WHAT -buildvcs=false COSTS
#
# It removes vcs.revision and vcs.modified from the binary. The commit is put
# back by -X, but vcs.modified is not: that flag is the toolchain's own
# observation that the tree was clean, and nothing can restore it. This script
# therefore refuses to build from a dirty tree.
#
# Given the same source, the same toolchain build, and this recipe, the output is
# byte-identical regardless of build directory. It is not reproducible across
# toolchain builds: GOEXPERIMENT is recorded in the binary, so a distro toolchain
# with a non-default experiment set produces a different hash from an upstream one
# even after stripping. The workflow prints `go version` for that reason.

set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-}"
if [ -z "$version" ]; then
	echo "usage: $0 VERSION [--check]" >&2
	exit 2
fi
check="${2:-}"

# A tag identifies bytes only if the bytes are the tag's.
#
# Modified tracked files are refused outright: they are in the build and not in
# the commit, so a stamped version would name something that does not exist
# anywhere. This replaces the vcs.modified flag that -buildvcs=false removes
if [ -n "$modified" ]; then
	echo "FAIL: tracked files are modified, so a version stamped into these binaries" >&2
	echo "      would not identify what is in them:" >&2
	echo "$modified" >&2
	exit 1
fi

untracked_go=$(git ls-files --others --exclude-standard | grep '\.go$' || true)
if [ -n "$untracked_go" ]; then
	echo "FAIL: these Go files are untracked but would be compiled in:" >&2
	echo "$untracked_go" >&2
	exit 1
fi

untracked=$(git ls-files --others --exclude-standard || true)
if [ -n "$untracked" ]; then
	echo "note: untracked files present; none is Go, so none is in the build:" >&2
	echo "$untracked" | sed 's/^/  /' >&2
fi

commit=$(git rev-parse HEAD)
module=github.com/mauriciomem/quic-link/internal/buildinfo

targets=(
	linux/amd64
	linux/arm64
	darwin/amd64
	darwin/arm64
)

out=dist
rm -rf "$out"
mkdir -p "$out"

echo "building $version ($commit) with $(go version)"

for target in "${targets[@]}"; do
	goos=${target%/*}
	goarch=${target#*/}
	name="quic-link-$version-$goos-$goarch"

	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
		-trimpath \
		-buildvcs=false \
		-tags grpcnotrace \
		-ldflags "-s -w -X $module.version=$version -X $module.commit=$commit" \
		-o "$out/$name/quic-link" \
		./cmd/quic-link

	# One archive per platform, containing the binary and the two documents a
	# recipient needs in order to know what they have and what it permits.
	cp LICENSE THIRD-PARTY-NOTICES.md "$out/$name/"

	# --sort=name keeps entry order independent of the filesystem. GNU tar is
	# assumed: the release runs on Linux, and bsdtar on macOS neither accepts
	# --sort nor spells --mtime the same way, so a maintainer reproducing this on
	# macOS needs gtar.
	tar --sort=name \
		--mtime='UTC 1970-01-01' \
		--owner=0 --group=0 --numeric-owner \
		-C "$out" -cf - "$name" | gzip -n >"$out/$name.tar.gz"
	rm -rf "$out/$name"
	printf '  %-34s %s bytes\n' "$name.tar.gz" "$(wc -c <"$out/$name.tar.gz" | tr -d ' ')"
done

# Checksums over the archives, in the format sha256sum -c expects.
(cd "$out" && if command -v sha256sum >/dev/null; then
	sha256sum ./*.tar.gz >SHA256SUMS
else
	shasum -a 256 ./*.tar.gz >SHA256SUMS
fi)
echo "  SHA256SUMS"

if [ "$check" = "--check" ]; then
	echo "verifying the build is reproducible from a different directory"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	git archive --format=tar HEAD | tar -C "$tmp" -xf -

	native="$(go env GOOS)/$(go env GOARCH)"
	goos=${native%/*}
	goarch=${native#*/}
	(cd "$tmp" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
		-trimpath -buildvcs=false -tags grpcnotrace \
		-ldflags "-s -w -X $module.version=$version -X $module.commit=$commit" \
		-o "$tmp/quic-link" ./cmd/quic-link)

	# Rebuild the same target in-tree to a temp path and compare, which isolates
	# the build directory as the only difference between the two.
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
		-trimpath -buildvcs=false -tags grpcnotrace \
		-ldflags "-s -w -X $module.version=$version -X $module.commit=$commit" \
		-o "$tmp/in-tree" ./cmd/quic-link

	if cmp -s "$tmp/quic-link" "$tmp/in-tree"; then
		echo "  identical from two directories"
	else
		echo "FAIL: the same source built in two directories produced different bytes" >&2
		exit 1
	fi
fi

echo "artifacts in $out/"
