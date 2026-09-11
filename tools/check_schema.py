#!/usr/bin/env python3
"""Valida ogni vettore contro schema/vector.schema.json.

Validatore minimale in stdlib: copre required, additionalProperties, enum, pattern, type e le
regole annidate usate dallo schema. Non e' un validatore JSON Schema generico — e' abbastanza per
questo schema, e non introduce una dipendenza in una suite che ha fatto della loro assenza un punto.
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIPI = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float),
        "boolean": bool, "null": type(None)}


def valida(dato, schema, percorso=""):
    errori = []
    tipi = schema.get("type")
    if tipi:
        attesi = tipi if isinstance(tipi, list) else [tipi]
        if not any(isinstance(dato, TIPI[t]) for t in attesi if t in TIPI):
            if not (dato is None and "null" in attesi):
                errori.append(f"{percorso}: atteso {tipi}, trovato {type(dato).__name__}")
                return errori
    if "enum" in schema and dato not in schema["enum"]:
        errori.append(f"{percorso}: '{dato}' non e' fra {schema['enum']}")
    if "pattern" in schema and isinstance(dato, str) and not re.match(schema["pattern"], dato):
        errori.append(f"{percorso}: non rispetta il pattern {schema['pattern']}")
    if isinstance(dato, dict):
        for req in schema.get("required", []):
            if req not in dato:
                errori.append(f"{percorso}: campo obbligatorio mancante '{req}'")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for k in dato:
                if k not in props:
                    errori.append(f"{percorso}: campo non previsto '{k}'")
        for k, sub in props.items():
            if k in dato:
                errori += valida(dato[k], sub, f"{percorso}/{k}")
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict):
            for k, val in dato.items():
                if k not in props:
                    errori += valida(val, extra, f"{percorso}/{k}")
    if isinstance(dato, list):
        if "minItems" in schema and len(dato) < schema["minItems"]:
            errori.append(f"{percorso}: servono almeno {schema['minItems']} elementi")
        if "items" in schema:
            for i, el in enumerate(dato):
                errori += valida(el, schema["items"], f"{percorso}[{i}]")
    return errori


def main():
    schema = json.load(open(os.path.join(BASE, "schema", "vector.schema.json")))
    vdir = os.path.join(BASE, "vectors")
    tot = ko = 0
    for nome in sorted(os.listdir(vdir)):
        if not nome.endswith(".json"):
            continue
        tot += 1
        errori = valida(json.load(open(os.path.join(vdir, nome))), schema, nome)
        if errori:
            ko += 1
            print(f"  {nome}:")
            for e in errori:
                print(f"      {e}")
    print(f"schema: {tot} vettori, {tot-ko} validi, {ko} non conformi")
    return 0 if ko == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
