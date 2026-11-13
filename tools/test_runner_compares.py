#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The runner compares what it must compare: on a temporary copy, a vector whose `expected` block is wrong in one
field must make verify.py red (exit 1) with exactly that vector FALLITO; the intact copy stays green.

Planted, one at a time: a wrong reject class (009: signature_high_s -> signer_mismatch), a wrong recovered address
(005), a flipped verdict (003 accept -> reject/signer_mismatch). Found by tools/positive_control.py on 13/11/2026:
with the runner's class comparison or address comparison switched off, every other gate stayed green, because the
committed vectors are all correct and no gate fed the runner a wrong expectation.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLANTS = [
    ("009-ecdsa-malleability-high-s", "reject_reason", "signer_mismatch"),
    ("005-mutated-value", "recovered_address", "0x" + "11" * 20),
    ("003-eip3009-generated-valid", "verdict", "reject"),
]


def run(d):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, os.path.join(d, "verify.py")], cwd=d, capture_output=True, text=True,
                       timeout=600, env=env)
    return p.returncode, p.stdout


def main():
    tmp = tempfile.mkdtemp(prefix="x402-runner-compares-")
    try:
        d = os.path.join(tmp, "s")
        shutil.copytree(BASE, d, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))
        rc, out = run(d)
        assert rc == 0, "suite intatta: il runner deve essere verde\n" + out[-600:]
        for vid, field, value in PLANTS:
            p = os.path.join(d, "vectors", vid + ".json")
            orig = open(p, encoding="utf-8").read()
            v = json.loads(orig)
            v["expected"][field] = value
            if field == "verdict":
                v["expected"]["reject_reason"] = "signer_mismatch"
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(v, fh, indent=2, ensure_ascii=False)
            rc, out = run(d)
            rows = [ln for ln in out.splitlines() if "FALLITO" in ln]
            assert rc == 1 and len(rows) == 1 and rows[0].startswith(vid), (vid, field, rc, rows)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(orig)
        print(f"runner: {len(PLANTS)}/{len(PLANTS)} attese sbagliate (classe, indirizzo, verdetto) -> FALLITO sul vettore "
              f"giusto; suite intatta verde")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
