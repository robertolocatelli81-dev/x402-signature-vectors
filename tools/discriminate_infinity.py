#!/usr/bin/env python3
"""Controllo POSITIVO dei vettori 051/052: dimostra che SMASCHERANO un'implementazione difettosa.

Un vettore `reject` che il nostro runner rifiuta non prova nulla da solo: potrebbe essere rifiutato da
chiunque, per qualunque motivo. Qui si simulano le due mappature difettose che i vettori dichiarano
di catturare — il recupero al punto all'infinito serializzato come address(0) (la sentinella di
`ecrecover` in Solidity) o come keccak256 di 64 byte zero (l'identita' rappresentata come (0,0)) —
e si verifica che ENTRAMBE accetterebbero. Se una non accetta, il vettore non discrimina e il test
fallisce. (Rilievo di Gemini 3.1 Pro, 11/09/2026: "stai testando il tuo hard-coding".)
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "lib"))
import secp256k1 as S                                          # noqa: E402
import verify as V                                             # noqa: E402
from eip712 import keccak256                                   # noqa: E402


def recupero_difettoso(vec, mappa_infinito):
    """Replica un recupero che NON rifiuta l'identita': la mappa su un indirizzo e lo confronta."""
    digest = V.digest_di(vec)
    raw = bytes.fromhex(vec["signature"][2:])
    r, s, rec = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64] - 27
    alpha = (pow(r, 3, S.P) + 7) % S.P
    beta = pow(alpha, (S.P + 1) // 4, S.P)
    y = beta if beta % 2 == (rec & 1) else S.P - beta
    e = int.from_bytes(digest, "big") % S.N
    Q = S._mul(S._inv(r, S.N), S._add(S._mul(s, (r, y)), S._mul(S.N - e, (S.GX, S.GY))))
    return mappa_infinito if Q is None else S.public_key_to_address(Q, keccak256)


CASI = [
    ("051-recovery-point-at-infinity-address-zero", "0x" + "00" * 20, "ecrecover -> address(0)"),
    ("052-recovery-point-at-infinity-zero-point-address",
     "0x" + keccak256(b"\x00" * 64).hex()[-40:], "identita' come (0,0) -> keccak(64 byte zero)"),
]


def main():
    ko = 0
    for vid, mappa, nome in CASI:
        vec = json.load(open(os.path.join(BASE, "vectors", vid + ".json")))
        addr = recupero_difettoso(vec, mappa)
        difettosa_accetta = addr.lower() == vec["signer"].lower()
        nostro = V.verdetto(vec)
        ok = difettosa_accetta and nostro[0] == "reject" and nostro[2] == "recovery_undefined"
        ko += not ok
        print(f"  {vid[:3]} {nome:48s} impl. difettosa: {'ACCETTA' if difettosa_accetta else 'rifiuta'} "
              f"| runner: {nostro[0]} ({nostro[2]}) -> {'OK, il vettore discrimina' if ok else 'NON DISCRIMINA'}")
    print("esito:", "i vettori ∞ smascherano entrambe le mappature difettose" if ko == 0
          else f"{ko} vettore/i non discriminano")
    return 1 if ko else 0


if __name__ == "__main__":
    sys.exit(main())
