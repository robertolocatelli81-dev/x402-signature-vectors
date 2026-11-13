#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test of the SDK adapters (SPEC.md §5): they exist, answer every vector with one closed line, and give the known
answers on the vectors that check their own plumbing.

    X402_TS_ENV=<dir with node_modules/@x402/evm> X402_PY=<venv python with x402[evm]> python3 tools/test_sdk_adapters.py

Exit 2 when an environment variable is missing: a test that cannot run says so, it does not pass.

Known answers (not SDK findings; they fail when the ADAPTER is wrong):
  - 003 (EIP-3009, generated, valid) accept on every entry; 005 (value mutated) reject on every entry;
  - 009 (high-s) reject with class signature_high_s on every entry: both SDKs have a low-s check with its own code;
  - typed-data: 004, 011, 031, 041 accept — they carry integers above 2^53, which reach the SDK exact only if the
    adapter reads the vector without losing digits;
  - facilitator-exact: 019 (not an EIP-3009 message) and 067 (a domain no server holds) not_applicable; 056
    (fractional value) reject, from the SDK's payload check;
  - an unknown entry name exits 2; the runner rejects a line with a member the schema does not define.
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "tools"))

ENTRIES = ("typed-data", "facilitator-exact")


def main():
    ts_env, py = os.environ.get("X402_TS_ENV"), os.environ.get("X402_PY")
    if not ts_env or not py:
        print("X402_TS_ENV e X402_PY non impostati: test NON eseguito (exit 2)")
        return 2
    import run_sdk_adapters as R                                         # noqa: E402

    vdir = os.path.join(BASE, "vectors")
    paths = [os.path.join(vdir, f) for f in sorted(os.listdir(vdir)) if f.endswith(".json")]
    ids = [json.load(open(p, encoding="utf-8"))["id"] for p in paths]
    errors = []
    for sdk in ("typescript", "python"):
        for entry in ENTRIES:
            rc, lines = R.run_adapter(sdk, entry, paths, ts_env=ts_env, py=py)
            if rc != 0:
                errors.append(f"{sdk}/{entry}: exit {rc}")
                continue
            if [r["id"] for r in lines] != ids:
                errors.append(f"{sdk}/{entry}: ids out of order or missing")
            by = {r["id"]: r for r in lines}

            def want(vid, verdict, cls="any"):
                r = by.get(vid)
                if r is None or r["verdict"] != verdict or (cls != "any" and r["reject_reason"] != cls):
                    errors.append(f"{sdk}/{entry} {vid}: expected {verdict}/{cls}, got "
                                  f"{None if r is None else (r['verdict'], r['reject_reason'], r['detail'])}")
            want("003-eip3009-generated-valid", "accept")
            want("005-mutated-value", "reject")
            want("009-ecdsa-malleability-high-s", "reject", "signature_high_s")
            if entry == "typed-data":
                for vid in ("004-eip2612-generated-valid", "011-value-max-uint256", "031-domain-chainid-max",
                            "041-permit2-witness-transfer"):
                    want(vid, "accept")
            else:
                want("019-eip712-array-of-structs", "not_applicable")
                # a domain value a server cannot hold is not sent to the SDK (it raised on 067 before);
                # a fractional amount must reach the SDK's payload check, not break the adapter (056 raised before)
                want("067-domain-verifying-contract-bad-prefix", "not_applicable")
                want("056-uint-float-fraction", "reject")
        rc, _ = R.run_adapter(sdk, "no-such-entry", paths[:1], ts_env=ts_env, py=py)
        if rc != 2:
            errors.append(f"{sdk}: unknown entry gave exit {rc}, expected 2")
    bad = {"id": "003-eip3009-generated-valid", "sdk": "python", "entry": "typed-data", "verdict": "accept",
           "reject_reason": None, "sdk_reason": "True", "detail": None, "extra_member": 1}
    if not R.line_errors(bad):
        errors.append("runner accepted a line with an undefined member")
    if errors:
        print("ADATTATORI NON CONFORMI:")
        for e in errors:
            print("  " + e)
        return 1
    print(f"adattatori: 2 SDK x {len(ENTRIES)} entry x {len(paths)} vettori, righe chiuse, risposte note corrette")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
