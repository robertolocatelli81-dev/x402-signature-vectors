#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Positive control of the gates: sabotage the library and the runner, one defect at a time, on a fresh copy, and
show that the gates catch every one (n of n) — and that every sabotage is a real change of behaviour.

    python3 tools/positive_control.py          # exit 0 iff the intact copy passes every gate, every sabotage is
                                               # caught by at least one gate, and none is equivalent on the batch

For each sabotage: a copy of the suite (no .git, no caches), one textual patch that must apply exactly once, the
copy's manifest regenerated (so the hash gate cannot catch it by construction), then every offline gate of the
verify job run in the copy. Non-equivalence is measured apart from the gates, on a batch that is not the vectors:
  - B1, verdict level: seeded inputs built here (random EIP-3009 messages signed by the test key with random nonces
    k, their high-s twins, raw v, r = 0, s = N/2, point-at-infinity constructions, nested types declared out of
    order, NUL in strings, wrong fixed-array lengths, repeated JSON members, mixed-case signers, domains without
    version); every input goes through verdetto_da_testo() of the intact copy and of the sabotaged one;
  - B2, runner level: the vectors with their `expected` block corrupted in one way each (wrong class, wrong
    address, flipped verdict, a member the schema does not define), run through the copy's verify.py.
A sabotage is non-equivalent when some B1 answer (verdict, class, recovered address) or some B2 row differs.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SABOTAGES = [
    ("keccak-padding", "lib/eip712.py", "    m.append(0x01)                                   # padding Keccak, NON 0x06",
     "    m.append(0x06)", "Keccak padding byte 0x06 (SHA3-256) instead of 0x01"),
    ("low-s-skipped", "verify.py", "    if s > S.N // 2:\n        return \"signature_high_s\"",
     "    if False:\n        return \"signature_high_s\"", "EIP-2 low-s check removed"),
    ("low-s-boundary", "verify.py", "    if s > S.N // 2:\n        return \"signature_high_s\"",
     "    if s >= S.N // 2:\n        return \"signature_high_s\"", "low-s bound off by one (s = N/2 rejected)"),
    ("domain-version-dropped", "verify.py",
     '_ORDINE_DOMINIO = [("name", "string"), ("version", "string"), ("chainId", "uint256"),',
     '_ORDINE_DOMINIO = [("name", "string"), ("chainId", "uint256"),',
     "EIP712Domain derived without `version`"),
    ("encodetype-unsorted", "lib/eip712.py", "    ordinati = [primary] + sorted(deps(primary, set()) - {primary})",
     "    ordinati = [primary] + [t for t in types if t in deps(primary, set()) - {primary}]",
     "referenced types in declaration order, not alphabetical"),
    ("v-raw-admitted", "verify.py", "    if v not in (27, 28):", "    if v not in (0, 1, 27, 28):",
     "raw recovery id v = 0/1 admitted"),
    ("r-zero-admitted", "verify.py", "    if not (1 <= r < S.N):", "    if not (0 <= r < S.N):",
     "r = 0 not rejected as out of range"),
    ("json-reader-lax", "verify.py",
     "    return json.loads(testo, object_pairs_hook=_no_duplicati, parse_constant=_no_costanti)",
     "    return json.loads(testo)", "strict reader replaced by json.loads (repeated members, NaN)"),
    ("array-length-unchecked", "lib/eip712.py", "        if lunghezza and len(valore) != int(lunghezza):",
     "        if False:", "fixed-size array length not checked"),
    ("string-nul-truncated", "lib/eip712.py", "        return keccak256(valore.encode(\"utf-8\"))",
     "        return keccak256(valore.split(\"\\x00\")[0].encode(\"utf-8\"))", "string hashed up to the first NUL"),
    ("infinity-serialised", "lib/secp256k1.py",
     "        raise ValueError(\"recupero al punto all'infinito: nessuna chiave pubblica\")",
     "        return (0, 0)", "point at infinity returned as (0, 0) instead of failing"),
    ("signer-case-sensitive", "verify.py", "    ok = rec.lower() == str(firmatario).lower()",
     "    ok = rec == str(firmatario)", "signer compared case-sensitively"),
    ("runner-reason-ignored", "verify.py",
     "            ok_ragione = att_classe is not None and classe == att_classe",
     "            ok_ragione = True", "runner: reject class not compared"),
    ("runner-address-ignored", "verify.py", "        ok_addr = (rec is None and att_addr is None) or (",
     "        ok_addr = True or (", "runner: recovered address not compared"),
    ("runner-schema-skipped", "verify.py",
     "        errori_schema = _valida_schema(vec, schema, \"\") if isinstance(vec, dict) else [\"non e' un oggetto\"]",
     "        errori_schema = []", "runner: vector schema not enforced"),
    # 13/11/2026 (review): three sabotages no gate saw before the runner checked the four intermediate values and
    # tools/fuzz_runner.py read NaN/Infinity and every atomic struct name.
    ("nan-admitted", "verify.py",
     "    return json.loads(testo, object_pairs_hook=_no_duplicati, parse_constant=_no_costanti)",
     "    return json.loads(testo, object_pairs_hook=_no_duplicati)", "NaN/Infinity read as numbers"),
    ("struct-named-string", "lib/eip712.py", 'r"u?int[0-9]*|address|bool|string|bytes[0-9]*"',
     'r"u?int[0-9]*|address|bytes[0-9]*"', "a struct named `string` or `bool` admitted"),
    ("runner-layers-ignored", "verify.py", "        ok_strati = all((calc is None and vec[\"expected\"][k] is None) or (",
     "        ok_strati = True or all((calc is None and vec[\"expected\"][k] is None) or (",
     "runner: the four intermediate values not compared"),
]

GATES = [
    ["tools/check_manifest.py"], ["tools/test_check_manifest.py"], ["tools/check_schema.py"], ["tools/check_spec.py"],
    ["tools/check_docs.py"], ["verify.py"], ["tools/genera_vettori_onchain.py", "--confronta"], ["tools/test_runner_schema.py"],
    ["tools/test_runner_compares.py"], ["tools/audit_spec_examples.py"], ["tools/fuzz_runner.py"],
    ["tools/discriminate_infinity.py"],
]


def copy_suite(dst):
    shutil.copytree(BASE, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", ".xval"))


def run(root, args, timeout=900):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, *args], cwd=root, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, p.stdout + p.stderr


def gates(root):
    failed = []
    for g in GATES:
        if not os.path.exists(os.path.join(root, g[0])):
            failed.append(f"{g[0]} (missing)")
            continue
        rc, _ = run(root, g)
        if rc != 0:
            failed.append(" ".join(g))
    return failed


# ----------------------------------------------------------------------------------------------- batches
def build_b1(seed=20261113, n=24):
    sys.path.insert(0, os.path.join(BASE, "lib"))
    sys.path.insert(0, os.path.join(BASE, "tools"))
    from eip712 import keccak256, hash_struct
    import secp256k1 as S
    from genera_vettori import CHIAVE_TEST, CAMPI_DOMINIO, TIPI_3009, indirizzo_test
    rnd = random.Random(seed)
    addr = indirizzo_test()

    def sign(dom, types, primary, msg, cd=None):
        cd = cd or [c for c in CAMPI_DOMINIO if c["name"] in dom]
        d = keccak256(b"\x19\x01" + hash_struct("EIP712Domain", {"EIP712Domain": cd}, dom)
                      + hash_struct(primary, types, msg))
        r, s, rec = S.sign(d, CHIAVE_TEST, rnd.randrange(1, S.N))
        return r, s, rec, d

    def hx(r, s, v):
        return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex()

    def vec(dom, types, primary, msg, sig, signer=addr):
        return {"signer": signer, "eip712": {"domain": dom, "types": types, "primaryType": primary, "message": msg},
                "signature": sig}

    out = []
    for i in range(n):
        dom = {"name": rnd.choice(["USDC", "USD Coin", "Tést €", ""]), "chainId": rnd.choice([1, 8453, 84532]),
               "verifyingContract": "0x" + rnd.randbytes(20).hex()}
        if rnd.random() < 0.7:
            dom = {"name": dom["name"], "version": rnd.choice(["1", "2"]), "chainId": dom["chainId"],
                   "verifyingContract": dom["verifyingContract"]}
        msg = {"from": addr, "to": "0x" + rnd.randbytes(20).hex(), "value": rnd.randrange(0, 2 ** 256),
               "validAfter": rnd.randrange(0, 2 ** 40), "validBefore": rnd.randrange(0, 2 ** 40),
               "nonce": "0x" + rnd.randbytes(32).hex()}
        r, s, rec, d = sign(dom, TIPI_3009, "TransferWithAuthorization", msg)
        T = "TransferWithAuthorization"
        out.append(json.dumps(vec(dom, TIPI_3009, T, msg, hx(r, s, 27 + rec))))                     # valid
        out.append(json.dumps(vec(dom, TIPI_3009, T, msg, hx(r, S.N - s, 28 - rec))))               # high-s twin
        out.append(json.dumps(vec(dom, TIPI_3009, T, msg, hx(r, s, rec))))                          # raw v
        out.append(json.dumps(vec(dom, TIPI_3009, T, msg, hx(0, s, 27 + rec))))                     # r = 0
        out.append(json.dumps(vec(dom, TIPI_3009, T, msg, hx(r, S.N // 2, 27 + rec))))              # s = N/2
        out.append(json.dumps(vec(dom, TIPI_3009, T, msg, hx(r, s, 27 + rec), signer=addr.upper().replace("0X", "0x"))))
        # point at infinity: R = kG, s = e/k, the recovery id of R
        k = rnd.randrange(1, S.N)
        R = S._mul(k, (S.GX, S.GY))
        e = int.from_bytes(d, "big") % S.N
        out.append(json.dumps(vec(dom, TIPI_3009, T, msg, hx(R[0] % S.N, e * pow(k, -1, S.N) % S.N, 27 + (R[1] & 1)))))
        # nested types declared out of alphabetical order
        tn = {"Root": [{"name": "z", "type": "Zed"}, {"name": "a", "type": "Alpha"}],
              "Zed": [{"name": "v", "type": "uint256"}], "Alpha": [{"name": "w", "type": "string"}]}
        mn = {"z": {"v": rnd.randrange(2 ** 64)}, "a": {"w": "x" * rnd.randrange(1, 9)}}
        r2, s2, rec2, _ = sign(dom, tn, "Root", mn)
        out.append(json.dumps(vec(dom, tn, "Root", mn, hx(r2, s2, 27 + rec2))))
        # NUL inside a string, signed whole
        ts = {"Note": [{"name": "t", "type": "string"}]}
        ms = {"t": "ab\x00" + rnd.randbytes(4).hex()}
        r3, s3, rec3, _ = sign(dom, ts, "Note", ms)
        out.append(json.dumps(vec(dom, ts, "Note", ms, hx(r3, s3, 27 + rec3))))
        # fixed array with one element too many
        ta = {"Pair": [{"name": "v", "type": "uint256[2]"}]}
        out.append(json.dumps(vec(dom, ta, "Pair", {"v": [1, 2, rnd.randrange(9)]}, hx(r, s, 27 + rec))))
        # repeated member in the text
        t = json.dumps(vec(dom, TIPI_3009, T, msg, hx(r, s, 27 + rec)))
        out.append(t.replace('"value": ', '"value": 1, "value": ', 1))
        # a non-JSON constant in a member EIP-712 ignores; a struct named like an atomic type
        out.append(t.replace('"validAfter": ', '"x": ' + rnd.choice(["NaN", "Infinity", "-Infinity"]) + ', "validAfter": ', 1))
        ta2 = dict(TIPI_3009, **{rnd.choice(["string", "bool"]): [{"name": "a", "type": "uint256"}]})
        out.append(json.dumps(vec(dom, ta2, T, msg, hx(r, s, 27 + rec))))
    return out


def corrupt_b2(vdir):
    """The vectors with `expected` corrupted, one way per vector, cycling over five ways."""
    files = sorted(f for f in os.listdir(vdir) if f.endswith(".json"))
    for i, f in enumerate(files):
        p = os.path.join(vdir, f)
        text = open(p, encoding="utf-8").read()
        if '"value": 99999999999,' in text:          # 077: keep its text, it is a reader test
            continue
        v = json.loads(text)
        e = v["expected"]
        way = i % 5
        if way == 0 and e["verdict"] == "reject":
            e["reject_reason"] = "signer_mismatch" if e["reject_reason"] != "signer_mismatch" else "encoding_error"
        elif way == 1 and e["recovered_address"] is not None:
            e["recovered_address"] = "0x" + "11" * 20
        elif way == 2:
            e["verdict"] = "accept" if e["verdict"] == "reject" else "reject"
            if e["verdict"] == "accept":
                e.pop("reject_reason", None)
            else:
                e["reject_reason"] = "signer_mismatch"
        elif way == 3 and e["type_hash"] is not None:
            e["type_hash"] = "0x" + "ab" * 32
        else:
            v["x_planted"] = 1
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(v, fh, indent=2, ensure_ascii=False)


def probe(root, b1_path, tmp):
    """Answers of the copy at `root` on B1 (verdetto_da_testo) and on B2 (its verify.py rows)."""
    code = ("import json,sys; sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[1] + '/lib');"
            "import verify as V\n"
            "out=[]\n"
            "for t in json.load(open(sys.argv[2])):\n"
            "    try: out.append(list(V.verdetto_da_testo(t)[:3]))\n"
            "    except Exception as e: out.append(['raised', type(e).__name__])\n"
            "print(json.dumps(out))")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, "-c", code, root, b1_path], capture_output=True, text=True, env=env,
                       timeout=900)
    b1 = json.loads(p.stdout) if p.returncode == 0 else ["probe failed", p.stderr[-300:]]
    d2 = os.path.join(tmp, "b2-" + os.path.basename(root))
    shutil.copytree(root, d2)
    corrupt_b2(os.path.join(d2, "vectors"))
    rc, out = run(d2, ["verify.py"])
    rows = [ln.split()[:5] for ln in out.splitlines() if ln[:3].isdigit()]
    shutil.rmtree(d2, ignore_errors=True)
    return b1, rows


def main():
    t0 = time.time()
    tmp = tempfile.mkdtemp(prefix="x402-pc-")
    try:
        b1_path = os.path.join(tmp, "b1.json")
        b1 = build_b1()
        json.dump(b1, open(b1_path, "w"))
        intact = os.path.join(tmp, "intact")
        copy_suite(intact)
        run(intact, ["tools/check_manifest.py", "--genera"])       # same treatment as every sabotaged copy
        failed = gates(intact)
        if failed:
            print(f"CONTROLLO NEGATIVO FALLITO: la copia intatta non passa {failed}")
            return 1
        ref_b1, ref_b2 = probe(intact, b1_path, tmp)
        print(f"copia intatta: {len(GATES)} gate verdi; lotto B1 {len(b1)} input, lotto B2 {len(ref_b2)} righe\n")
        print(f"{'sabotage':26s} {'caught by':58s} {'B1 diff':>8s} {'B2 diff':>8s}")
        caught = noneq = 0
        for sid, rel, old, new, desc in SABOTAGES:
            d = os.path.join(tmp, sid)
            copy_suite(d)
            p = os.path.join(d, rel)
            src = open(p, encoding="utf-8").read()
            if src.count(old) != 1:
                print(f"{sid}: patch target found {src.count(old)} times in {rel}")
                return 1
            open(p, "w", encoding="utf-8").write(src.replace(old, new))
            run(d, ["tools/check_manifest.py", "--genera"])
            f = gates(d)
            b1d, b2d = probe(d, b1_path, tmp)
            n1 = sum(a != b for a, b in zip(ref_b1, b1d)) if isinstance(b1d, list) and len(b1d) == len(ref_b1) else -1
            n2 = sum(a != b for a, b in zip(ref_b2, b2d)) + abs(len(ref_b2) - len(b2d))
            if n1 < 0:
                # the sabotaged copy could not even answer B1 (a patch that breaks the import): that is not a
                # change of behaviour to measure, it is a broken control (13/11/2026: it was counted as non-equivalent)
                print(f"{sid}: la copia sabotata non risponde sul lotto B1 — controllo non valido")
                return 1
            caught += bool(f)
            noneq += (n1 != 0 or n2 != 0)
            names = ", ".join(os.path.basename(x.split()[0]) for x in f) or "NOT CAUGHT"
            print(f"{sid:26s} {names[:58]:58s} {n1:>8d} {n2:>8d}")
            shutil.rmtree(d, ignore_errors=True)
        n = len(SABOTAGES)
        print(f"\ncatturati {caught}/{n}; non equivalenti sul lotto {noneq}/{n}; {time.time() - t0:.0f} s")
        return 0 if caught == n and noneq == n else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
