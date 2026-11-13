#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check_manifest.py inside a git worktree or a submodule, where `.git` is a FILE ("gitdir: …"), not a directory.

On a temporary copy of the suite with a `.git` file: the verification must pass, `--genera` must not record `.git`,
and a planted undeclared file must still be caught (the exclusion must not open a hole). Measured on 13/11/2026
before the fix: the verification failed with "NON DICHIARATO .git" and `--genera` wrote `.git` into manifest.json.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(d, *args):
    p = subprocess.run([sys.executable, os.path.join(d, "tools", "check_manifest.py"), *args], cwd=d,
                       capture_output=True, text=True, timeout=300)
    return p.returncode, p.stdout


def main():
    tmp = tempfile.mkdtemp(prefix="x402-manifest-wt-")
    try:
        d = os.path.join(tmp, "s")
        shutil.copytree(BASE, d, ignore=shutil.ignore_patterns(".git", "__pycache__", ".xval"))
        with open(os.path.join(d, ".git"), "w") as f:
            f.write("gitdir: /nonexistent/.git/worktrees/s\n")
        rc, out = run(d)
        assert rc == 0, f"worktree: la verifica deve passare con un FILE .git\n{out}"
        rc, out = run(d, "--genera")
        assert rc == 0, out
        files = json.load(open(os.path.join(d, "manifest.json")))["files"]
        assert ".git" not in files, "--genera ha registrato il file .git"
        with open(os.path.join(d, "vectors", "zzz-planted.txt"), "w") as f:
            f.write("x\n")
        rc, out = run(d)
        assert rc == 1 and "NON DICHIARATO  vectors/zzz-planted.txt" in out, f"file piantato non visto\n{out}"
        print("check_manifest in una worktree: FILE .git ignorato in verifica e in --genera; file piantato ancora visto")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
