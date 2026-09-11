#!/usr/bin/env python3
"""Gate di integrita' FAIL-CLOSED sul manifest: ogni file dichiarato deve combaciare byte per byte.

Senza questo, una suite di vettori e' solo una cartella di file: nulla impedisce che un vettore
cambi silenziosamente e che i verdetti di ieri non siano piu' quelli di oggi.
"""
import hashlib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256(percorso):
    with open(percorso, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def genera():
    voci = {}
    for radice, _, file in os.walk(BASE):
        # Esclusi: .git, cache e il venv locale di cross-validazione (.xval); .github resta dentro.
        if any(p in radice for p in ("/.git/", "__pycache__", "/.xval")) or radice.endswith("/.git"):
            continue
        for f in sorted(file):
            if f in ("manifest.json",) or f.endswith((".pyc", ".log")):
                continue
            rel = os.path.relpath(os.path.join(radice, f), BASE)
            voci[rel] = sha256(os.path.join(BASE, rel))
    vettori = sorted(v for v in voci if v.startswith("vectors/"))
    return {"suite": "x402-signature-vectors", "version": "1.1.0",
            "counts": {"files": len(voci), "vectors": len(vettori)},
            "files": dict(sorted(voci.items()))}


def verifica():
    p = os.path.join(BASE, "manifest.json")
    if not os.path.exists(p):
        print("manifest assente: FAIL-CLOSED"); return 2
    m = json.load(open(p))
    atteso, problemi = m["files"], []
    for rel, h in atteso.items():
        f = os.path.join(BASE, rel)
        if not os.path.exists(f):
            problemi.append(f"MANCANTE  {rel}")
        elif sha256(f) != h:
            problemi.append(f"ALTERATO  {rel}")
    presenti = set(genera()["files"])
    for extra in sorted(presenti - set(atteso)):
        problemi.append(f"NON DICHIARATO  {extra}")
    n_vec = len([v for v in atteso if v.startswith("vectors/")])
    if n_vec != m["counts"]["vectors"]:
        problemi.append(f"conteggio vettori incoerente: {n_vec} != {m['counts']['vectors']}")
    if problemi:
        print("INTEGRITA' VIOLATA:"); [print("  " + x) for x in problemi]; return 1
    print(f"manifest integro: {m['counts']['files']} file, {m['counts']['vectors']} vettori, "
          f"tutti gli sha256 combaciano")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--genera":
        json.dump(genera(), open(os.path.join(BASE, "manifest.json"), "w"), indent=2)
        print("manifest generato")
        sys.exit(0)
    sys.exit(verifica())
