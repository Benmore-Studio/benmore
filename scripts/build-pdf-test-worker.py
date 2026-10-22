#!/usr/bin/env python3
"""Build the exact clean Linux test checkout's non-race PDF child for race tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--edition", choices=("framework", "cloud", "platform"), required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    out = args.output_directory.resolve()
    if sys.platform != "linux" or out == root or root in out.parents:
        raise SystemExit("Use Linux and an output directory outside the source checkout")
    if os.environ.get("GOFLAGS"):
        raise SystemExit("Refusing ambient GOFLAGS for the bound test helper")

    def command(*argv):
        return subprocess.check_output(argv, cwd=root, text=True, timeout=30).strip()

    def source():
        if command("git", "status", "--porcelain", "--untracked-files=all"):
            raise SystemExit("PDF helper requires the exact clean committed test checkout")
        return command("git", "rev-parse", "HEAD"), command("git", "rev-parse", "HEAD^{tree}")

    head, tree = source()
    directive = re.search(r"(?m)^go (\d+\.\d+\.\d+)$", (root / "go.mod").read_text())
    if not directive:
        raise SystemExit("Expected an exact Go patch version in go.mod")
    version = command("go", "env", "GOVERSION")
    goos, goarch = command("go", "env", "GOOS"), command("go", "env", "GOARCH")
    if version != "go" + directive[1] or goos != "linux" or goarch not in ("amd64", "arm64"):
        raise SystemExit("Go toolchain/platform does not match the qualified checkout")
    tags = sorted(["sqlite_fts5"] + ([] if args.edition == "framework" else [args.edition]))
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = out / "pdf-worker.test"
    subprocess.run(["go", "test", "-c", "-buildvcs=true", "-race=false", "-tags", " ".join(tags), "-o", str(binary), "."], cwd=root, check=True, timeout=600)
    if source() != (head, tree):
        raise SystemExit("Source changed while the PDF helper was built")
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    manifest = dict(schema=1, binary=binary.name, sha256=digest.hexdigest(), source_commit=head, source_tree=tree,
                    go_version=version, edition=args.edition, goos=goos, goarch=goarch, tags=tags)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
