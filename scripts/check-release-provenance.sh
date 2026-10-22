#!/usr/bin/env bash
# Read build metadata only; never execute a release binary, including foreign targets.
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 <binary> <commit> <version>" >&2; exit 2; }
binary="$1"
revision="$2"
version="$3"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid release revision" >&2; exit 1; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9][A-Za-z0-9.-]*)?$ ]] || { echo "invalid release version" >&2; exit 1; }
[[ "$(git rev-parse HEAD)" == "$revision" ]] || { echo "release revision differs from checkout" >&2; exit 1; }
status="$(git status --porcelain=v1 --untracked-files=all)" || { echo "cannot inspect release checkout" >&2; exit 1; }
[[ -z "$status" ]] || { echo "release checkout is dirty" >&2; exit 1; }
toolchain="$(sed -n 's/^go /go/p' go.mod)"
[[ "$toolchain" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "missing exact release toolchain" >&2; exit 1; }

# Require one exact value per field. In particular, neither a dirty stamp nor
# duplicate/suffixed version linker assignments can pass this gate.
go version -m "$binary" | awk -F '\t' \
  -v revision="$revision" -v version="$version" -v toolchain="$toolchain" '
  BEGIN {
    expected["path"] = "github.com/benmore-studio/benmore"
    expected["mod"] = expected["path"]
    expected["-buildmode"] = "exe"
    expected["-compiler"] = "gc"
    expected["CGO_ENABLED"] = "1"
    expected["-tags"] = "sqlite_fts5"
    expected["-ldflags"] = "\"-s -w -X main.version=" version "\""
    expected["vcs"] = "git"
    expected["vcs.revision"] = revision
    expected["vcs.modified"] = "false"
  }
  NR == 1 { if (substr($0, length($0)-length(toolchain)-1) != ": " toolchain) bad=1; next }
  $2 == "path" || $2 == "mod" {
    key=$2; count[key]++; if ($3 != expected[key]) bad=1
    if (key == "mod" && $4 ~ /\+dirty$/) bad=1
  }
  $2 == "build" {
    pos=index($3, "="); key=substr($3, 1, pos-1)
    if (key in expected) { count[key]++; if (substr($3, pos+1) != expected[key]) bad=1 }
  }
  END {
    for (key in expected) if (count[key] != 1) bad=1
    if (bad) { print "release binary provenance differs from clean source" > "/dev/stderr"; exit 1 }
  }'
echo "release binary provenance: verified"
