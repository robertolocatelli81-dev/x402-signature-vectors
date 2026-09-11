#!/usr/bin/env python3
"""Cross-validazione delle primitive di lib/ contro librerie di riferimento indipendenti.

La critica piu' seria a una suite di conformita' che implementa la crypto da sola: se l'unica
implementazione ha un bug, i vettori sono sbagliati e il difetto si propaga a chi li usa. Questo
script risponde con un confronto byte-per-byte contro implementazioni di mercato:

    Keccak-256   ->  eth-hash (pycryptodome backend)
    secp256k1    ->  coincurve (binding a libsecp256k1, la stessa libreria di Bitcoin Core)

Le librerie NON sono una dipendenza della suite: `verify.py` gira senza. Servono solo qui, per
dimostrare che lib/ non ha un punto cieco proprio. Si installano in un venv separato:

    python3 -m venv .xval && .xval/bin/pip install coincurve "eth-hash[pycryptodome]"
    .xval/bin/python tools/crossvalidate.py
"""
import json
import os
import secrets
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))

from eip712 import keccak256 as keccak_nostro, hash_struct   # noqa: E402
import secp256k1 as S                                        # noqa: E402

try:
    from eth_hash.auto import keccak as keccak_rif
    from coincurve import PrivateKey, PublicKey
except ImportError:
    print("librerie di riferimento assenti: creare il venv indicato nel docstring")
    sys.exit(2)


def cross_keccak(n=2000):
    """Keccak-256 su input casuali di lunghezza variabile, inclusi i bordi dei blocchi (rate 136)."""
    casi = [b"", b"a", b"abc", bytes(135), bytes(136), bytes(137), bytes(271), bytes(272)]
    casi += [secrets.token_bytes(secrets.randbelow(400)) for _ in range(n - len(casi))]
    diff = [c for c in casi if keccak_nostro(c) != keccak_rif(c)]
    return {"casi": len(casi), "divergenze": len(diff), "ok": not diff}


def cross_recover(n=500):
    """Firma con coincurve (libsecp256k1), recupera con lib/secp256k1: gli indirizzi devono combaciare."""
    divergenze = []
    for _ in range(n):
        priv = PrivateKey()
        msg = secrets.token_bytes(32)
        sig = priv.sign_recoverable(msg, hasher=None)         # 65 byte: r||s||v (v in 0..3)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:64], "big")
        rec = sig[64]
        try:
            pub = S.recover_public_key(msg, r, s, rec)
            nostro = S.public_key_to_address(pub, keccak_nostro)
        except Exception as e:                                # noqa: BLE001
            divergenze.append(f"eccezione {type(e).__name__}")
            continue
        atteso_pub = PublicKey.from_signature_and_message(sig, msg, hasher=None).format(compressed=False)[1:]
        atteso = "0x" + keccak_rif(atteso_pub).hex()[-40:]
        if nostro.lower() != atteso.lower():
            divergenze.append(f"{nostro} != {atteso}")
    return {"casi": n, "divergenze": len(divergenze), "esempi": divergenze[:3], "ok": not divergenze}


def cross_vettori():
    """I vettori della suite, ri-verificati con le librerie di riferimento invece che con lib/."""
    vdir = os.path.join(BASE, "vectors")
    campi = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
             {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]
    esiti = []
    for nome in sorted(os.listdir(vdir)):
        if not nome.endswith(".json"):
            continue
        v = json.load(open(os.path.join(vdir, nome)))
        e = v["eip712"]
        ds = hash_struct("EIP712Domain", {"EIP712Domain": campi}, e["domain"])
        digest = keccak_nostro(b"\x19\x01" + ds + hash_struct(e["primaryType"], e["types"], e["message"]))
        raw = bytes.fromhex(v["signature"][2:])
        sig = raw[:64] + bytes([raw[64] - 27])
        try:
            pub = PublicKey.from_signature_and_message(sig, digest, hasher=None).format(compressed=False)[1:]
            rec_rif = "0x" + keccak_rif(pub).hex()[-40:]
        except Exception as e2:                               # noqa: BLE001
            rec_rif = f"errore: {type(e2).__name__}"
        atteso = v["expected"]["recovered_address"]
        esiti.append({"vettore": v["id"], "atteso": atteso, "riferimento": rec_rif,
                      "ok": str(rec_rif).lower() == str(atteso).lower()})
    return esiti


def main():
    print("CROSS-VALIDAZIONE di lib/ contro implementazioni di riferimento indipendenti\n")
    k = cross_keccak()
    print(f"Keccak-256 vs eth-hash          : {k['casi']} casi, {k['divergenze']} divergenze -> "
          f"{'IDENTICI' if k['ok'] else 'DIVERGENZA'}")
    r = cross_recover()
    print(f"recover vs coincurve/libsecp256k1: {r['casi']} firme reali, {r['divergenze']} divergenze -> "
          f"{'IDENTICI' if r['ok'] else 'DIVERGENZA ' + str(r['esempi'])}")
    v = cross_vettori()
    ko = [x for x in v if not x["ok"]]
    print(f"vettori ri-verificati con coincurve: {len(v)} vettori, {len(ko)} discordanti -> "
          f"{'TUTTI CONCORDI' if not ko else str(ko)}")
    ok = k["ok"] and r["ok"] and not ko
    json.dump({"keccak": k, "recover": r, "vettori": v, "ok": ok},
              open(os.path.join(BASE, "audit", "crossvalidation.json"), "w"), indent=2)
    print(f"\nesito: {'lib/ CONCORDA con le implementazioni di riferimento' if ok else 'DIVERGENZA — non usare i vettori'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
