#!/usr/bin/env sh
#
# Install quic-link into ~/local/bin.
#
#   curl -fsSL https://raw.githubusercontent.com/mauriciomem/quic-link/main/scripts/install.sh | sh
#
# WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT
#
# It downloads one release archive, checks it against the release's own
# SHA256SUMS, and copies a single binary into ~/local/bin. That is all.
#
# It does not use sudo, write anything outside your home directory, edit your
# shell profile, install a service, or start anything. That is not modesty about
# scope — it is the project's privilege model. Exactly one quic-link operation
# ever needs root, and it is `sudo quic-link init`, which registers a single
# resolver file so that *.internal names resolve. That prompt is the product's
# promise: setup asks once, visibly, and usage never asks. An installer that
# quietly did the same work would remove the one moment a user is told what is
# being changed on their machine.
#
# Likewise it will not edit your PATH. It prints the line to add and where to add
# it, because a script that silently rewrites a shell profile is a script you
# cannot audit after the fact.
#
# Written for POSIX sh, so it runs the same under sh, bash, dash and zsh.

set -eu

REPO="mauriciomem/quic-link"
# Deliberately NOT prefixed QUIC_LINK_. The binary treats that prefix as its own
# configuration namespace and warns about any name in it that it does not
# recognise, so an installer variable left set in a shell would make every
# later quic-link command print a warning.
INSTALL_DIR="${QLINK_INSTALL_DIR:-$HOME/local/bin}"
VERSION="${QLINK_VERSION:-latest}"

say()  { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

need curl
need tar
need uname

# ---------------------------------------------------------------- platform ----
os=$(uname -s)
case "$os" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported operating system: $os (this project builds for Linux and macOS)" ;;
esac

arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture: $arch (releases cover x86_64 and arm64)" ;;
esac

step "Platform: ${os}-${arch}"

# ----------------------------------------------------------------- version ----
# GitHub's "latest" endpoint deliberately excludes drafts and pre-releases, so
# this resolves to the newest full release. Set QLINK_VERSION to install a
# specific tag, including a pre-release, via QLINK_VERSION.
if [ "$VERSION" = latest ]; then
	step "Finding the latest release"
	VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1) ||
		die "could not reach the GitHub API"
	[ -n "$VERSION" ] ||
		die "no full release found. If only a pre-release exists, choose it explicitly:
       QLINK_VERSION=v0.1.0-rc.1 sh install.sh
     Releases: https://github.com/${REPO}/releases"
fi
say "    ${VERSION}"

name="quic-link-${VERSION}-${os}-${arch}"
base="https://github.com/${REPO}/releases/download/${VERSION}"

# ---------------------------------------------------------------- download ----
tmp=$(mktemp -d)
# shellcheck disable=SC2064 # $tmp is expanded now on purpose.
trap "rm -rf '$tmp'" EXIT INT TERM

step "Downloading ${name}.tar.gz"
curl -fSL --progress-bar -o "${tmp}/${name}.tar.gz" "${base}/${name}.tar.gz" ||
	die "download failed. Does ${VERSION} have a build for ${os}-${arch}?
     See https://github.com/${REPO}/releases/tag/${VERSION}"

# ----------------------------------------------------------------- verify -----
# The release publishes one SHA256SUMS covering every archive. Checking it means
# a corrupted or truncated download fails here rather than at first run.
step "Verifying the checksum"
# Retry once: a transient TLS or network fault must not be reported as "this
# release has no checksums", which would quietly downgrade the check.
sums_ok=no
if curl -fsSL --retry 2 --retry-delay 1 -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS"; then
	sums_ok=yes
elif curl -fsSL --retry 2 --retry-delay 1 -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS"; then
	sums_ok=yes
fi
if [ "$sums_ok" = yes ]; then
	if command -v sha256sum >/dev/null 2>&1; then
		sumcmd="sha256sum"
	elif command -v shasum >/dev/null 2>&1; then
		sumcmd="shasum -a 256"
	else
		sumcmd=""
	fi
	if [ -n "$sumcmd" ]; then
		want=$(sed -n "s/^\([0-9a-f]\{64\}\) .*${name}\.tar\.gz$/\1/p" "${tmp}/SHA256SUMS" | head -1)
		got=$(cd "$tmp" && $sumcmd "${name}.tar.gz" | cut -d' ' -f1)
		[ -n "$want" ] || die "SHA256SUMS does not list ${name}.tar.gz"
		[ "$want" = "$got" ] || die "checksum mismatch — do not use this download.
     expected $want
     got      $got"
		say "    ok"
	else
		say "    skipped: neither sha256sum nor shasum is available"
	fi
else
	# Not fatal, but say which of the two it is rather than guessing.
	say "    WARNING: could not fetch SHA256SUMS from the release."
	say "    The archive was NOT verified. Either the release publishes no"
	say "    checksums, or the download failed. Check by hand before trusting it:"
	say "        ${base}/SHA256SUMS"
fi

# ---------------------------------------------------------------- install -----
step "Unpacking"
tar -C "$tmp" -xzf "${tmp}/${name}.tar.gz"
[ -f "${tmp}/${name}/quic-link" ] || die "archive did not contain the expected binary"

step "Installing to ${INSTALL_DIR}/quic-link"
mkdir -p "$INSTALL_DIR"
# Copy then move, so an existing binary is replaced atomically and a running
# daemon is never reading a half-written file.
cp "${tmp}/${name}/quic-link" "${INSTALL_DIR}/.quic-link.new"
chmod 0755 "${INSTALL_DIR}/.quic-link.new"
mv "${INSTALL_DIR}/.quic-link.new" "${INSTALL_DIR}/quic-link"

installed=$("${INSTALL_DIR}/quic-link" version 2>/dev/null || echo "installed")
say "    ${installed}"

# ------------------------------------------------------------------- PATH -----
# Checked rather than assumed. Note that ~/local/bin is NOT a location any
# operating system adds to PATH for you — unlike ~/.local/bin, the XDG
# user-level equivalent of /usr/local, which systemd and most distributions add
# automatically. So this branch is the normal case here rather than the
# exception, which is why the guidance below is written to be followed rather
# than skimmed.
case ":${PATH}:" in
*":${INSTALL_DIR}:"*)
	on_path=yes
	;;
*)
	on_path=no
	;;
esac

if [ "$on_path" = yes ]; then
	step "Done"
	say "    quic-link is on your PATH. Try:  quic-link version"
else
	# Name the file the user's own shell reads, rather than guessing one profile.
	shellname=$(basename "${SHELL:-sh}")
	case "$shellname" in
	zsh) profile="~/.zshrc" ;;
	bash) profile="~/.bashrc" ;;
	fish) profile="~/.config/fish/config.fish" ;;
	*) profile="your shell's startup file" ;;
	esac

	step "One step left: put ${INSTALL_DIR} on your PATH"
	say ""
	say "    ${INSTALL_DIR} is not on your PATH, so your shell cannot find"
	say "    quic-link by name yet. This script does not edit shell profiles, so"
	say "    that you can see exactly what changes."
	say ""
	if [ "$shellname" = fish ]; then
		say "    Add it by running:"
		say ""
		say "        fish_add_path ${INSTALL_DIR}"
	else
		say "    Add this line to ${profile}:"
		say ""
		if [ "$INSTALL_DIR" = "$HOME/local/bin" ]; then
			say "        export PATH=\"\$HOME/local/bin:\$PATH\""
		else
			say "        export PATH=\"${INSTALL_DIR}:\$PATH\""
		fi
		say ""
		say "    Then reload it:"
		say ""
		say "        . ${profile}"
	fi
	say ""
	say "    Or skip PATH entirely and use the full path:"
	say ""
	say "        ${INSTALL_DIR}/quic-link version"
fi

# ------------------------------------------------------------- next steps -----
step "Next"
say "    1. quic-link keygen           create this machine's identity, print its pin"
say "    2. sudo quic-link init        register *.internal with the system resolver"
say ""
say "    Step 2 is the only command that needs root, and it writes exactly one"
say "    file, which 'quic-link init --undo' removes. Skip it if you do not want"
say "    name resolution: everything else works without it."
say ""
say "    Verify what you downloaded came from the release workflow:"
say ""
say "        gh attestation verify <archive> -R ${REPO}"
say ""
say "    Docs: https://github.com/${REPO}#readme"
