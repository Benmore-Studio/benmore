#!/bin/sh
# Install the hosted Benmore CLI. The Claude plugin has a separate install.sh.
set -eu

REPO=Benmore-Studio/benmore-cli

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need tar
need install

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS: $(uname -s) (download manually from https://github.com/$REPO/releases)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

version=${BENMORE_VERSION:-}
case "$version" in *[!A-Za-z0-9._-]*) die "invalid BENMORE_VERSION: $version" ;; esac
requested_version=$version
version=${version#cli-}
[ -z "$requested_version" ] || [ -n "$version" ] || die "invalid BENMORE_VERSION: $requested_version"
if [ -n "$version" ]; then
  case "$version" in v*) release_version=${version#v} ;; *) die "invalid BENMORE_VERSION: $requested_version" ;; esac
  core=${release_version%%-*}
  prerelease=
  if [ "$core" != "$release_version" ]; then
    prerelease=${release_version#*-}
    [ -n "$prerelease" ] || die "invalid BENMORE_VERSION: $requested_version"
  fi
  major=${core%%.*}
  rest=${core#*.}
  minor=${rest%%.*}
  patch=${rest#*.}
  [ "$rest" != "$core" ] && [ "$patch" != "$rest" ] || die "invalid BENMORE_VERSION: $requested_version"
  for part in "$major" "$minor" "$patch"; do
    case "$part" in ''|*[!0-9]*) die "invalid BENMORE_VERSION: $requested_version" ;; esac
  done
  case "$prerelease" in .*|*.|*..*|*[!A-Za-z0-9.-]*) die "invalid BENMORE_VERSION: $requested_version" ;; esac
  release_url="https://api.github.com/repos/$REPO/releases/tags/$version"
else
  release_url="https://api.github.com/repos/$REPO/releases/latest"
fi

release=$(curl -fsSL "$release_url") || die "could not resolve the Benmore CLI release"
tag=$(printf '%s\n' "$release" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
archive_url=$(printf '%s\n' "$release" | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | grep "_${os}_${arch}\.tar\.gz$" | head -1 || true)
checksums_url=$(printf '%s\n' "$release" | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | grep '/checksums\.txt$' | head -1 || true)
[ -n "$tag" ] || die "release metadata did not include a tag"
[ -n "$archive_url" ] || die "release $tag has no $os/$arch archive"
[ -n "$checksums_url" ] || die "release $tag has no checksums.txt"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
asset=${archive_url##*/}
curl -fsSL -o "$tmp/$asset" "$archive_url" || die "download failed: $archive_url"
curl -fsSL -o "$tmp/checksums.txt" "$checksums_url" || die "download failed: $checksums_url"
expected=$(awk -v name="$asset" '$2 == name { print $1; exit }' "$tmp/checksums.txt")
[ -n "$expected" ] || die "checksums.txt has no entry for $asset"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
else
  die "sha256sum or shasum is required to verify the download"
fi
[ "$actual" = "$expected" ] || die "checksum mismatch for $asset"

tar -xzf "$tmp/$asset" -C "$tmp" benmore || die "archive did not contain a safe benmore binary"
[ -f "$tmp/benmore" ] && [ ! -L "$tmp/benmore" ] || die "archive did not contain a safe benmore binary"
dest=${BENMORE_INSTALL_DIR:-}
if [ -z "$dest" ]; then
  if [ -w /usr/local/bin ]; then dest=/usr/local/bin; else dest="$HOME/.local/bin"; fi
fi
mkdir -p "$dest" || die "could not create $dest"
install -m 0755 "$tmp/benmore" "$dest/benmore" || die "could not install to $dest"

say "installed benmore $tag to $dest/benmore"
case ":${PATH:-}:" in *":$dest:"*) ;; *) say "add $dest to PATH" ;; esac
