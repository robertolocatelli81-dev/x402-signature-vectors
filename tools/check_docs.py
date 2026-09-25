#!/usr/bin/env python3
"""Gate sui NUMERI scritti in prosa: README e commento devono dire cio' che i vettori dicono.

Perche' esiste: l'11/09/2026 il README ha dichiarato "48 vectors compared" per tre release di fila
mentre i vettori confrontabili erano 50, poi 53. Il numero era vero quando fu scritto e nessun gate lo
rileggeva: i gate controllavano hash, schema e firme — mai una frase. Un numero in prosa che non
deriva dai dati diventa falso in silenzio. Qui i numeri del README si RICALCOLANO dai vettori.
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    vdir = os.path.join(BASE, "vectors")
    vec = [json.load(open(os.path.join(vdir, f))) for f in sorted(os.listdir(vdir)) if f.endswith(".json")]
    n = len(vec)
    acc = sum(v["expected"]["verdict"] == "accept" for v in vec)
    rej = n - acc
    encodabili = sum(v["expected"]["signing_digest"] is not None for v in vec)
    versione = json.load(open(os.path.join(BASE, "manifest.json")))["version"]
    readme = open(os.path.join(BASE, "README.md")).read()
    problemi = []

    m = re.search(r"Current set: \*\*(\d+) vectors — (\d+) `accept`, (\d+) `reject`\*\* \(v([\d.]+)\)", readme)
    if not m:
        problemi.append("README: riga 'Current set' non trovata nel formato atteso")
    else:
        att = (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4))
        if att != (n, acc, rej, versione):
            problemi.append(f"README 'Current set' dice {att}, i vettori dicono {(n, acc, rej, versione)}")

    m = re.search(r"eth-account.*?\| (\d+) vectors compared", readme)
    if not m:
        problemi.append("README: riga di cross-validazione eth-account non trovata")
    elif int(m.group(1)) != encodabili:
        problemi.append(f"README dice '{m.group(1)} vectors compared' con eth-account, "
                        f"ma i vettori con messaggio codificabile sono {encodabili}")

    # Le note di ogni vettore non devono contraddire i suoi dati (caso 027: "recupero definito" con
    # recovered_address null).
    for v in vec:
        note = " ".join(v.get("notes", [])).lower()
        if v["expected"]["recovered_address"] is None and "recupero e' definito" in note:
            problemi.append(f"{v['id']}: la nota dice 'recupero definito' ma recovered_address e' null")

    # Le classi di reject sono enumerate in TRE posti (tools/reject_reasons.py, lo schema, il README):
    # una classe aggiunta in uno solo e' un filtro a valle che la ignora in silenzio. Devono coincidere.
    sys.path.insert(0, os.path.join(BASE, "tools"))
    from reject_reasons import CLASSI                                   # noqa: E402
    schema = json.load(open(os.path.join(BASE, "schema", "vector.schema.json")))
    enum = set(schema["properties"]["expected"]["properties"]["reject_reason"]["enum"])
    m = re.search(r"declares \*\*`reject_reason`\*\* — one of (.*?) \(defined in", readme, re.S)
    nel_readme = set(re.findall(r"`([a-z_]+)`", m.group(1))) if m else set()
    if not m:
        problemi.append("README: elenco delle classi di reject non trovato nel formato atteso")
    elif not (set(CLASSI) == enum == nel_readme):
        problemi.append(f"classi di reject incoerenti: reject_reasons={sorted(CLASSI)} "
                        f"schema={sorted(enum)} README={sorted(nel_readme)}")
    usate = {v["expected"].get("reject_reason") for v in vec} - {None}
    if not usate <= set(CLASSI):
        problemi.append(f"vettori con classi non definite: {sorted(usate - set(CLASSI))}")

    changelog = open(os.path.join(BASE, "CHANGELOG.md")).read()
    if f"## {versione} — " not in changelog:
        problemi.append(f"CHANGELOG: manca la voce per la versione {versione} del manifest")

    if problemi:
        print("DOCUMENTAZIONE NON COERENTE CON I DATI:")
        for p in problemi:
            print("  " + p)
        return 1
    print(f"docs coerenti: {n} vettori ({acc} accept / {rej} reject), v{versione}, "
          f"{encodabili} confrontabili con eth-account, changelog presente")
    return 0


if __name__ == "__main__":
    sys.exit(main())
