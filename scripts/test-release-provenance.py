#!/usr/bin/env python3
"""Exercise the exported ignore rules and pre-publication guard without running binaries."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(argv, cwd, *, ok=True, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=90)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"unexpected exit {result.returncode}: {argv}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    source = args.source_root.resolve()
    guard = Path(__file__).resolve().with_name("check-release-provenance.sh")
    toolchain = next(line for line in (source / "go.mod").read_text().splitlines() if line.startswith("go "))
    checks = 0
    with tempfile.TemporaryDirectory(prefix="benmore-release-provenance-") as temp:
        root = Path(temp)
        fixture = root / "source"
        fixture.mkdir()
        shutil.copyfile(source / ".gitignore", fixture / ".gitignore")
        (fixture / "go.mod").write_text("module github.com/benmore-studio/benmore\n\n" + toolchain + "\n")
        original = 'package main\nvar version = "development"\nfunc main() {}\n'
        (fixture / "main.go").write_text(original)
        run(["git", "init", "-q"], fixture)
        run(["git", "add", "."], fixture)
        run(["git", "-c", "user.name=Release Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture"], fixture)
        revision = run(["git", "rev-parse", "HEAD"], fixture)
        version = "2.7.301"

        def build(label):
            output = root / label
            run(["go", "build", "-mod=readonly", "-buildvcs=true", "-tags=sqlite_fts5",
                 "-ldflags", f"-s -w -X main.version={version}", "-o", str(output), "."], fixture,
                env=dict(os.environ, CGO_ENABLED="1"))
            return output

        def verify(binary, *, ok=True, env=None):
            nonlocal checks
            run(["bash", str(guard), str(binary), revision, version], fixture, ok=ok, env=env)
            checks += 1

        clean = build("clean")
        verify(clean)
        (fixture / "dist").mkdir()
        (fixture / "dist/metadata.json").write_text('{"generated":true}\n')
        assert run(["git", "status", "--porcelain=v1", "--untracked-files=all"], fixture) == "", "generated dist makes release checkout dirty"
        generated = build("with-dist")
        verify(generated)
        (fixture / "untracked_source.go").write_text("package main\n")
        dirty_untracked = build("with-untracked-source")
        verify(dirty_untracked, ok=False)
        (fixture / "untracked_source.go").unlink()
        # The clean checkout must not bless a previously dirty artifact either.
        verify(dirty_untracked, ok=False)
        (fixture / "main.go").write_text(original + "// tracked source change\n")
        dirty_tracked = build("with-tracked-change")
        verify(dirty_tracked, ok=False)
        (fixture / "main.go").write_text(original)
        verify(dirty_tracked, ok=False)
        verify(generated)

        # Adversarial metadata controls isolate the parser from the real builds.
        info = run(["go", "version", "-m", str(generated)], fixture) + "\n"
        shim = root / "shim"
        shim.mkdir()
        (shim / "go").write_text('#!/bin/sh\ncat "$PROVENANCE_TEST_INFO"\n')
        (shim / "go").chmod(0o700)
        info_file = root / "buildinfo"
        env = dict(os.environ, PATH=str(shim) + os.pathsep + os.environ["PATH"], PROVENANCE_TEST_INFO=str(info_file))
        mutations = [
            info.replace("vcs.modified=false", "vcs.modified=true"),
            info.replace("vcs.revision=" + revision, "vcs.revision=" + "0" * 40),
            "\n".join(line for line in info.splitlines() if "vcs.modified=" not in line) + "\n",
            info + "\tbuild\tvcs.modified=false\n",
            info.replace("main.version=" + version, "main.version=" + version + "-wrong"),
            info.replace("main.version=" + version, "main.version=9" + version),
            info.replace("main.version=" + version, "main.version=" + version + " -X main.version=" + version),
            info.replace("-tags=sqlite_fts5", "-tags=sqlite_fts5,platform"),
            info.replace("CGO_ENABLED=1", "CGO_ENABLED=0"),
            info.replace(toolchain.replace("go ", "go"), "go1.26.9", 1),
        ]
        for changed in mutations:
            info_file.write_text(changed)
            verify(generated, ok=False, env=env)
        info_file.write_text(info)
        verify(generated, env=env)
        # A failed status query with empty stdout must never count as clean.
        real_git = shutil.which("git")
        assert real_git is not None
        (shim / "git").write_text('#!/bin/sh\nif [ "$1" = status ]; then exit 23; fi\nexec "$PROVENANCE_TEST_GIT" "$@"\n')
        (shim / "git").chmod(0o700)
        verify(generated, ok=False, env=dict(env, PROVENANCE_TEST_GIT=real_git))
    print(f"release provenance: {checks} controls passed; binaries inspected, never executed")


if __name__ == "__main__":
    main()
