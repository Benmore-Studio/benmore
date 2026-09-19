#!/usr/bin/env bash
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: scripts/stage-bm-package.sh <empty-output-dir>" >&2
  exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=$1
mkdir -p "$out"
if [ -n "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  echo "stage-bm-package: output directory must be empty: $out" >&2
  exit 2
fi

cp "$root/embedded/bm.js" "$out/index.js"
cp "$root/packages/bm/index.d.ts" "$out/index.d.ts"
cp "$root/packages/bm/package.json" "$out/package.json"
cp "$root/packages/bm/README.md" "$out/README.md"
