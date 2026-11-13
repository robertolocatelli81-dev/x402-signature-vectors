#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate: SPEC.md and the two schemas describe the same fields and the same reject classes.

Every field of schema/vector.schema.json and of schema/adapter-result.schema.json (the latter under `/adapter`) must
have exactly one clause in SPEC.md — a heading "### `<path>`" — and every such heading must name a field of one of
the two schemas. The classes listed in SPEC.md §4 must be the schemas' enum. Without this gate a field added to a
schema has no meaning written anywhere, and a clause can survive the field it describes.

Before measuring, the gate proves it can fail: on an in-memory copy of SPEC.md with one clause removed and one
invented clause added, it must report exactly those two orphans.
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAUSE = re.compile(r"^### `(/[^`]+)`\s*$", re.M)


def fields(schema, prefix=""):
    """JSON paths of every property the schema defines; `*` stands for a map key (additionalProperties)."""
    out = []
    for name, sub in schema.get("properties", {}).items():
        path = f"{prefix}/{name}"
        out.append(path)
        out += fields(sub, path)
        if isinstance(sub.get("items"), dict):
            out += fields(sub["items"], path)
    extra = schema.get("additionalProperties")
    if isinstance(extra, dict):
        star = f"{prefix}/*"
        out += fields(extra, star)
        if isinstance(extra.get("items"), dict):
            out += fields(extra["items"], star)
    return out


def classes_in_spec(text):
    m = re.search(r"^## 4\..*?$(.*?)^## 5\.", text, re.S | re.M)
    if not m:
        return None
    return set(re.findall(r"^\| `([a-z_]+)` \|", m.group(1), re.M))


def check(spec_text, vec_schema, ad_schema):
    problems = []
    declared = fields(vec_schema) + [f"/adapter{p}" for p in fields(ad_schema)]
    clauses = CLAUSE.findall(spec_text)
    for c in sorted({c for c in clauses if clauses.count(c) > 1}):
        problems.append(f"clause repeated: {c}")
    for f in declared:
        if f not in clauses:
            problems.append(f"field without clause: {f}")
    for c in clauses:
        if c not in declared:
            problems.append(f"clause without field: {c}")
    in_spec = classes_in_spec(spec_text)
    enum_v = set(vec_schema["properties"]["expected"]["properties"]["reject_reason"]["enum"])
    enum_a = set(ad_schema["properties"]["reject_reason"]["enum"]) - {None}
    if in_spec is None:
        problems.append("SPEC.md §4 not found")
    elif not (in_spec == enum_v == enum_a):
        problems.append(f"reject classes differ: SPEC §4 {sorted(in_spec)}, vector schema {sorted(enum_v)}, "
                        f"adapter schema {sorted(enum_a)}")
    return problems, len(declared), len(clauses)


def main():
    spec = open(os.path.join(BASE, "SPEC.md"), encoding="utf-8").read()
    vec_schema = json.load(open(os.path.join(BASE, "schema", "vector.schema.json"), encoding="utf-8"))
    ad_schema = json.load(open(os.path.join(BASE, "schema", "adapter-result.schema.json"), encoding="utf-8"))

    # Positive control: the gate must see a removed clause and an invented one.
    removed = "/expected/signing_digest"
    planted = spec.replace(f"### `{removed}`", "### removed clause") + "\n### `/expected/invented_field`\nx\n"
    got, _, _ = check(planted, vec_schema, ad_schema)
    want = {f"field without clause: {removed}", "clause without field: /expected/invented_field"}
    if set(got) != want:
        print(f"CONTROLLO POSITIVO FALLITO: atteso {sorted(want)}, ottenuto {got}")
        return 2

    problems, n_fields, n_clauses = check(spec, vec_schema, ad_schema)
    if problems:
        print("SPEC.md E SCHEMI NON COINCIDONO:")
        for p in problems:
            print("  " + p)
        return 1
    print(f"spec coerente: {n_fields} campi, {n_clauses} clausole, 0 orfani; classi di reject = enum degli schemi; "
          f"controllo positivo 2/2 orfani piantati visti")
    return 0


if __name__ == "__main__":
    sys.exit(main())
