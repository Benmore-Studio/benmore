#!/usr/bin/env python3
"""Build the exact clean Linux test checkout's non-race PDF child for race tests.

With --verify, check a worker built elsewhere (CI builds it once and every race
shard downloads it) against its manifest and this checkout, then mark it
executable. Artifact transfer drops the executable bit, so the verified copy is
the one the race tests may run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

BINARY = "pdf-worker.test"
MANIFEST = "manifest.json"
MAX_MANIFEST = 64 << 10
MAX_BINARY = 512 << 20


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(directory, expected):
    """Accept only the two built files, bound to this checkout by the manifest."""
    names = sorted(path.name for path in directory.iterdir())
    if names != sorted([BINARY, MANIFEST]):
        raise SystemExit(f"PDF worker directory must hold exactly {BINARY} and {MANIFEST}; found {names}")
    manifest_path, binary = directory / MANIFEST, directory / BINARY
    for path in (manifest_path, binary):
        if not stat.S_ISREG(path.lstat().st_mode):
            raise SystemExit(f"{path.name} is not a regular file")
    if manifest_path.lstat().st_size > MAX_MANIFEST:
        raise SystemExit("PDF worker manifest is too large")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict):
        raise SystemExit("PDF worker manifest is not an object")
    digest = manifest.pop("sha256", None)
    if manifest != expected:
        raise SystemExit("PDF worker manifest does not match this checkout, toolchain and edition")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("PDF worker manifest has no binary digest")
    size = binary.lstat().st_size
    if size <= 0 or size > MAX_BINARY:
        raise SystemExit("PDF worker binary has an implausible size")
    if sha256_file(binary) != digest:
        raise SystemExit("PDF worker binary does not match its manifest digest")
    binary.chmod(0o700)
    directory.chmod(0o700)
    return digest


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("output_directory", type=Path, help="where to build the worker, or with --verify where it was downloaded")
    parser.add_argument("--edition", choices=("framework", "cloud", "platform"), required=True)
    parser.add_argument("--verify", action="store_true", help="verify a downloaded worker instead of building one")
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
    identity = dict(schema=1, binary=BINARY, source_commit=head, source_tree=tree,
                    go_version=version, edition=args.edition, goos=goos, goarch=goarch, tags=tags)
    if args.verify:
        digest = verify(out, identity)
        print(json.dumps(dict(identity, sha256=digest, verified=str(out / BINARY))))
        return
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = out / BINARY
    subprocess.run(["go", "test", "-c", "-buildvcs=true", "-race=false", "-tags", " ".join(tags), "-o", str(binary), "."], cwd=root, check=True, timeout=600)
    if source() != (head, tree):
        raise SystemExit("Source changed while the PDF helper was built")
    manifest = dict(identity, sha256=sha256_file(binary))
    # Key order matches earlier manifests: schema, binary, sha256, then identity.
    manifest = {key: manifest[key] for key in ("schema", "binary", "sha256", "source_commit", "source_tree",
                                                 "go_version", "edition", "goos", "goarch", "tags")}
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
