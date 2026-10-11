#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controllo del runner chiuso (10-11/10/2026): su una copia temporanea della suite, un vettore con un campo che lo schema
non prevede — al primo livello, in `eip712`, in `expected` — rende `verify.py` rosso (exit 1) e la riga NOMINA il campo;
la copia non toccata resta verde (exit 0: controllo che deve passare). La copia viene rimossa alla fine."""
import json, os, shutil, subprocess, sys, tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "x_unknown_2026"


def run(d):
    p = subprocess.run([sys.executable, os.path.join(d, "verify.py")], cwd=d, capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout


def main():
    tmp = tempfile.mkdtemp(prefix="x402-runner-schema-")
    try:
        d = os.path.join(tmp, "s")
        shutil.copytree(BASE, d, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        rc, out = run(d)
        assert rc == 0, "suite non toccata: il runner deve essere verde\n" + out[-800:]
        vdir = os.path.join(d, "vectors"); first = sorted(f for f in os.listdir(vdir) if f.endswith(".json"))[0]
        orig = open(os.path.join(vdir, first), encoding="utf-8").read()
        for where in ("", "eip712", "expected"):
            v = json.loads(orig)
            (v if not where else v[where])[KEY] = 1
            with open(os.path.join(vdir, first), "w", encoding="utf-8") as f:
                json.dump(v, f, ensure_ascii=False, indent=1)
            rc, out = run(d)
            row = [l for l in out.splitlines() if "FALLITO" in l]
            assert rc == 1 and len(row) == 1 and KEY in row[0], (where or "top", rc, row)
            with open(os.path.join(vdir, first), "w", encoding="utf-8") as f:
                f.write(orig)
        print("runner chiuso: 3/3 campi non previsti -> FALLITO con il campo nominato; suite intatta verde")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
