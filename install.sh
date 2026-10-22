#!/bin/sh
# install.sh - install the open-source Benmore framework binary (`benmore`).
#
#   curl -fsSL https://raw.githubusercontent.com/Benmore-Studio/benmore/main/install.sh | sh
#
# Downloads the latest release archive for your OS/arch from GitHub Releases,
# verifies it against checksums.txt, and installs `benmore` to a directory on
# your PATH (/usr/local/bin if writable, else ~/.local/bin).
#
# Override the install dir:   BENMORE_INSTALL_DIR=/opt/bin sh install.sh
# Install a specific version: BENMORE_VERSION=v2.7.151   sh install.sh
set -eu

REPO="Benmore-Studio/benmore"
BINARY="benmore"

say()  { printf '%s\n' "$*"; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- detect OS / arch, mapped to GoReleaser's naming -------------------------
os="$(uname -s)"
case "$os" in
  Linux)  OS="linux" ;;
  Darwin) OS="darwin" ;;
  *)      err "unsupported OS '$os' - Windows users: download the .zip from https://github.com/$REPO/releases" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)   ARCH="amd64" ;;
  arm64|aarch64)  ARCH="arm64" ;;
  *)              err "unsupported architecture '$arch'" ;;
esac

# --- pick a downloader -------------------------------------------------------
if have curl; then
  dl() { curl -fsSL "$1"; }
  dlo() { curl -fsSL -o "$2" "$1"; }
elif have wget; then
  dl() { wget -qO- "$1"; }
  dlo() { wget -qO "$2" "$1"; }
else
  err "need curl or wget"
fi

# --- resolve version ---------------------------------------------------------
VERSION="${BENMORE_VERSION:-}"
if [ -z "$VERSION" ]; then
  say "→ resolving latest release…"
  VERSION="$(dl "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [ -n "$VERSION" ] || err "could not determine the latest release (rate-limited? set BENMORE_VERSION=vX.Y.Z)"
fi
# GoReleaser archive names use the version WITHOUT the leading 'v'.
VER_NOV="${VERSION#v}"

ASSET="${BINARY}_${VER_NOV}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"

say "→ installing $BINARY $VERSION ($OS/$ARCH)"

# --- download + verify + extract --------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

dlo "$BASE/$ASSET" "$tmp/$ASSET" || err "download failed: $BASE/$ASSET"

# Verification is mandatory: a missing checksums.txt, a missing entry or a
# missing hash tool must stop the install, not silently skip the check (an
# attacker who can 404 one URL would otherwise choose the unverified path).
dlo "$BASE/checksums.txt" "$tmp/checksums.txt" 2>/dev/null || err "checksums.txt unavailable: $BASE/checksums.txt"
# checksums.txt only proves the archive matches a file published beside it in
# the same release. When the release carries a keyless Sigstore bundle and
# cosign is installed, also prove checksums.txt came from this repository's
# release workflow on a v* tag. BENMORE_REQUIRE_SIGNATURE=1 makes a missing
# cosign or bundle fatal.
REQUIRE_SIG="${BENMORE_REQUIRE_SIGNATURE:-}"
if ! have cosign; then
  [ "$REQUIRE_SIG" != 1 ] || err "BENMORE_REQUIRE_SIGNATURE=1 but cosign is not installed"
  say "note: cosign not installed; skipped signature verification (checksum still enforced)"
elif ! dlo "$BASE/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json" 2>/dev/null; then
  [ "$REQUIRE_SIG" != 1 ] || err "release $VERSION has no checksums.txt.sigstore.json"
  say "warning: release $VERSION has no Sigstore bundle; skipped signature verification"
else
  cosign verify-blob --bundle "$tmp/checksums.txt.sigstore.json" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp "^https://github\\.com/$REPO/\\.github/workflows/release\\.yml@refs/tags/v" \
    "$tmp/checksums.txt" >/dev/null 2>&1 || err "signature verification of checksums.txt failed"
  say "✓ checksums.txt signature verified"
fi
expected="$(awk -v name="$ASSET" '$2 == name { print $1; exit }' "$tmp/checksums.txt")"
[ -n "$expected" ] || err "checksums.txt has no entry for $ASSET"
if have sha256sum; then
  actual="$(sha256sum "$tmp/$ASSET" | awk '{print $1}')"
elif have shasum; then
  actual="$(shasum -a 256 "$tmp/$ASSET" | awk '{print $1}')"
else
  err "sha256sum or shasum is required to verify the download"
fi
[ "$actual" = "$expected" ] || err "checksum mismatch for $ASSET (expected $expected, got $actual)"
say "✓ checksum verified"

tar -xzf "$tmp/$ASSET" -C "$tmp" "$BINARY" || err "archive did not contain $BINARY"
[ -f "$tmp/$BINARY" ] && [ ! -L "$tmp/$BINARY" ] || err "archive did not contain a safe $BINARY"
chmod +x "$tmp/$BINARY"

# --- choose install dir ------------------------------------------------------
DEST="${BENMORE_INSTALL_DIR:-}"
if [ -z "$DEST" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    DEST="/usr/local/bin"
  else
    DEST="$HOME/.local/bin"
  fi
fi
mkdir -p "$DEST"

if mv "$tmp/$BINARY" "$DEST/$BINARY" 2>/dev/null; then
  :
elif have sudo && [ "$DEST" = "/usr/local/bin" ]; then
  say "→ /usr/local/bin needs sudo"
  sudo mv "$tmp/$BINARY" "$DEST/$BINARY"
else
  err "could not write to $DEST (set BENMORE_INSTALL_DIR to a writable dir)"
fi

say ""
say "✓ installed $BINARY → $DEST/$BINARY"
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) say "! $DEST is not on your PATH - add it:  export PATH=\"$DEST:\$PATH\"" ;;
esac
say ""
say "Get started:"
say "  $BINARY new myapp        # scaffold a runnable app"
say "  $BINARY serve myapp      # run it"
say "  $BINARY docs             # the full guide"
