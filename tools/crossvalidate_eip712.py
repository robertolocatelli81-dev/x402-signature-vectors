#!/usr/bin/env python3
"""Cross-validazione dell'ENCODING EIP-712 contro eth-account (implementazione di riferimento).

Fino a qui l'encoding era validato contro un solo oracolo esterno: l'esempio canonico `Mail`
pubblicato nella EIP-712. Un esempio non e' una copertura. Questo script confronta, per OGNI vettore,
i due valori che decidono tutto — `hash_struct` e `signing_digest` — con quelli calcolati da
eth-account, che e' l'implementazione usata dalla maggior parte degli strumenti Python del settore.

Serve un venv separato:
    python3 -m venv .xval && .xval/bin/pip install eth-account
    .xval/bin/python tools/crossvalidate_eip712.py
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))

try:
    from eth_account.messages import encode_typed_data
except ImportError:
    print("eth-account assente: creare il venv indicato nel docstring")
    sys.exit(2)


def main():
    vdir = os.path.join(BASE, "vectors")
    confrontati = saltati = divergenze = 0
    problemi = []
    for nome in sorted(os.listdir(vdir)):
        if not nome.endswith(".json"):
            continue
        v = json.load(open(os.path.join(vdir, nome)))
        e = v["eip712"]
        atteso_hs = v["expected"]["hash_struct"]
        atteso_sd = v["expected"]["signing_digest"]
        if atteso_hs is None:
            # Messaggio non codificabile: non c'e' nulla da confrontare, ed e' dichiarato nel vettore.
            saltati += 1
            continue
        try:
            sm = encode_typed_data(full_message={"domain": e["domain"], "types": e["types"],
                                                 "primaryType": e["primaryType"],
                                                 "message": e["message"]})
        except Exception as ex:                                # noqa: BLE001
            problemi.append(f"{v['id']}: eth-account solleva {type(ex).__name__}: {str(ex)[:70]}")
            divergenze += 1
            continue
        # SignableMessage: body = hashStruct(message), header = domainSeparator
        rif_hs = "0x" + sm.body.hex()
        from eip712 import keccak256                            # noqa: E402
        rif_sd = "0x" + keccak256(b"\x19\x01" + sm.header + sm.body).hex()
        confrontati += 1
        if rif_hs.lower() != atteso_hs.lower():
            divergenze += 1
            problemi.append(f"{v['id']}: hash_struct {atteso_hs[:18]}… vs eth-account {rif_hs[:18]}…")
        elif rif_sd.lower() != atteso_sd.lower():
            divergenze += 1
            problemi.append(f"{v['id']}: signing_digest diverso")

    print(f"encoding EIP-712 vs eth-account {__import__('eth_account').__version__}:")
    print(f"  {confrontati} vettori confrontati, {saltati} saltati (messaggio non codificabile per "
          f"costruzione), {divergenze} divergenze")
    for p in problemi:
        print(f"    {p}")
    ok = divergenze == 0
    json.dump({"confrontati": confrontati, "saltati": saltati, "divergenze": divergenze,
               "problemi": problemi, "ok": ok},
              open(os.path.join(BASE, "audit", "crossvalidation_eip712.json"), "w"), indent=2)
    print(f"\nesito: {'ENCODING CONCORDE' if ok else 'DIVERGENZA sull ENCODING — non usare i vettori'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
