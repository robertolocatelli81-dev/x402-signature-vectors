#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the vectors through the official x402 SDKs (SPEC.md §5) and compare their verdicts with the expected ones.

    X402_TS_ENV=<dir with node_modules/@x402/evm> X402_PY=<venv python with x402[evm]> \\
        python3 tools/run_sdk_adapters.py            # gate: exit 1 if any result differs from audit/sdk_results.json
        python3 tools/run_sdk_adapters.py --scrivi   # rewrite audit/sdk_results.json

Pinned SDKs: npm @x402/evm 2.31.0 and PyPI x402 2.28.0, both released from the tags npm-@x402/evm@v2.31.0 and
pypi-x402@v2.28.0 on commit 07c4caf of x402-foundation/x402, the parent of 2178d4b (which changes go/ only). The
exact environments: tools/adapters/typescript/package-lock.json and tools/adapters/python/requirements.txt.

Every divergence must carry a classification in tools/sdk_divergences.py (SPEC.md §5.4), and every classification
must match a divergence that occurred: the list is closed in both directions.
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "tools"))
from check_schema import valida                                   # noqa: E402
sys.path.insert(0, BASE)
from verify import leggi_json_stretto                             # noqa: E402

SDKS = ("typescript", "python")
ENTRIES = ("typed-data", "facilitator-exact")
OUT = os.path.join(BASE, "audit", "sdk_results.json")
SCHEMA = json.load(open(os.path.join(BASE, "schema", "adapter-result.schema.json"), encoding="utf-8"))
VERSIONS = {"typescript": "@x402/evm 2.31.0 (npm, tag npm-@x402/evm@v2.31.0 = 07c4caf), viem 2.57.19",
            "python": "x402 2.28.0 (PyPI, tag pypi-x402@v2.28.0 = 07c4caf), eth-account 0.14.0, eth-keys 0.8.0"}


def line_errors(obj):
    if not isinstance(obj, dict):
        return ["not an object"]
    return valida(obj, SCHEMA, "")


def run_adapter(sdk, entry, paths, ts_env=None, py=None):
    if sdk == "typescript":
        cmd = ["node", os.path.join(BASE, "tools", "adapters", "typescript", "adapter.mjs"), entry, *paths]
        env = {**os.environ, "X402_TS_ENV": ts_env or ""}
    else:
        cmd = [py, "-I", os.path.join(BASE, "tools", "adapters", "python", "adapter.py"), entry, *paths]
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)
    lines = []
    for raw in p.stdout.splitlines():
        try:
            # SPEC.md §5.2: a line is one JSON object, read strictly (a repeated member or NaN is not an answer).
            lines.append(leggi_json_stretto(raw))
        except ValueError:
            lines.append({"unparsable": raw[:200]})
    return p.returncode, lines


def classify(line, exp):
    v, ev = line["verdict"], exp["verdict"]
    if v in ("not_applicable", "not_reached"):
        return v
    if v == "error" or v != ev:
        return "divergence"
    if v == "reject" and line["reject_reason"] is not None and line["reject_reason"] != exp.get("reject_reason"):
        return "reason_divergence"
    return "match"


def main(argv):
    ts_env, py = os.environ.get("X402_TS_ENV"), os.environ.get("X402_PY")
    if not ts_env or not py:
        print("X402_TS_ENV e X402_PY non impostati: nessun risultato (exit 2)")
        return 2
    from sdk_divergences import CLASSIFICATION                  # noqa: E402
    vdir = os.path.join(BASE, "vectors")
    paths = [os.path.join(vdir, f) for f in sorted(os.listdir(vdir)) if f.endswith(".json")]
    expected = {}
    for p in paths:
        v = json.load(open(p, encoding="utf-8"))
        expected[v["id"]] = v["expected"]
    results, problems = [], []
    for sdk in SDKS:
        for entry in ENTRIES:
            rc, lines = run_adapter(sdk, entry, paths, ts_env=ts_env, py=py)
            if rc != 0 or len(lines) != len(paths):
                problems.append(f"{sdk}/{entry}: exit {rc}, {len(lines)} lines for {len(paths)} vectors")
                continue
            for line in lines:
                errs = line_errors(line)
                if errs:
                    problems.append(f"{sdk}/{entry}: line rejected: {errs[0]}")
                    continue
                exp = expected[line["id"]]
                if exp.get("reject_reason") == "json_ambiguous":
                    # SPEC.md §5.3: an object-input entry cannot see a repeated member; the adapter's reader chose one.
                    line = {**line, "verdict": "not_applicable", "reject_reason": None,
                            "detail": f"runner: entry takes a parsed object (adapter answered {line['verdict']})"}
                cat = classify(line, exp)
                rec = {**line, "expected": exp["verdict"], "expected_reason": exp.get("reject_reason"),
                       "category": cat}
                key = (sdk, entry, line["id"])
                if cat in ("divergence", "reason_divergence"):
                    if key not in CLASSIFICATION:
                        problems.append(f"divergence without classification: {key} -> {line['verdict']} "
                                        f"{line['sdk_reason']} {line['detail']}")
                    else:
                        rec["class"], rec["rule"] = CLASSIFICATION[key]
                results.append(rec)
    seen = {(r["sdk"], r["entry"], r["id"]) for r in results if r["category"] in ("divergence", "reason_divergence")}
    for key in sorted(set(CLASSIFICATION) - seen):
        problems.append(f"classification without a divergence: {key}")

    summary = {}
    for r in results:
        s = summary.setdefault(f"{r['sdk']}/{r['entry']}", {})
        s[r["category"]] = s.get(r["category"], 0) + 1
    print(f"{'sdk/entry':30s} " + " ".join(f"{c:>17s}" for c in
                                            ("match", "divergence", "reason_divergence", "not_applicable",
                                             "not_reached")))
    for k, s in summary.items():
        print(f"{k:30s} " + " ".join(f"{s.get(c, 0):>17d}" for c in
                                     ("match", "divergence", "reason_divergence", "not_applicable", "not_reached")))
    for r in results:
        if r.get("class"):
            print(f"  ({r['class']}) {r['sdk']}/{r['entry']} {r['id']}: expected {r['expected']}"
                  f"{'/' + r['expected_reason'] if r['expected_reason'] else ''}, got {r['verdict']} "
                  f"[{r['sdk_reason']}]")
    if problems:
        print("\nRISULTATI NON UTILIZZABILI:")
        for p in problems:
            print("  " + p)
        return 1
    data = {"sdk_versions": VERSIONS, "summary": summary, "results": results}
    if argv[:1] == ["--scrivi"]:
        with open(OUT, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
        print("scritto", os.path.relpath(OUT, BASE))
        return 0
    if json.load(open(OUT, encoding="utf-8")) != json.loads(json.dumps(data, ensure_ascii=False)):
        print("RISULTATI DIVERSI DA audit/sdk_results.json")
        return 1
    print("audit/sdk_results.json coincide con l'esecuzione")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
