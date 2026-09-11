#!/usr/bin/env python3
"""Runner di conformita': ricalcola ogni vettore e confronta col verdetto dichiarato.

    python3 verify.py            # exit 0 = conforme, 1 = non conforme, 2 = banco non affidabile

Il banco si valida PRIMA di emettere qualunque verdetto (Keccak-256 contro valori pubblici, EIP-712
contro i digest pubblicati nella EIP-712 stessa, secp256k1 contro un controllo di firma non
circolare). Un banco che non dimostra di funzionare non ha titolo per dire se altri sono conformi.
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "lib"))

from eip712 import keccak256, hash_struct, self_test as banco_eip712    # noqa: E402
import secp256k1 as S                                                    # noqa: E402

CAMPI_DOMINIO = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                 {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]


def recupera(vec):
    e = vec["eip712"]
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, e["domain"])
    digest = keccak256(b"\x19\x01" + ds + hash_struct(e["primaryType"], e["types"], e["message"]))
    raw = bytes.fromhex(vec["signature"][2:])
    pub = S.recover_public_key(digest, int.from_bytes(raw[:32], "big"),
                               int.from_bytes(raw[32:64], "big"), raw[64] - 27)
    return S.public_key_to_address(pub, keccak256)


def verdetto(vec):
    """accept sse la firma recupera all'indirizzo dichiarato come firmatario del messaggio."""
    try:
        rec = recupera(vec)
    except Exception as e:                                   # noqa: BLE001
        return "reject", f"errore di recupero: {type(e).__name__}"
    msg = vec["eip712"]["message"]
    firmatario = msg.get("from") or msg.get("owner")
    return ("accept" if rec.lower() == str(firmatario).lower() else "reject"), rec


def main():
    banco = banco_eip712()
    if not banco.get("ok"):
        print("BANCO NON AFFIDABILE — nessun verdetto emesso:", banco.get("checks"))
        return 2
    prova = S.self_test(keccak256)
    if not prova.get("ok"):
        print("BANCO NON AFFIDABILE — secp256k1:", prova)
        return 2
    print(f"banco: Keccak-256 ok · EIP-712 ok (esempio canonico riprodotto) · secp256k1 ok "
          f"({prova['indirizzo_recuperato'][:10]}…)\n")

    vdir = os.path.join(BASE, "vectors")
    file = sorted(f for f in os.listdir(vdir) if f.endswith(".json"))
    righe, falliti = [], 0
    for nome in file:
        vec = json.load(open(os.path.join(vdir, nome)))
        v, rec = verdetto(vec)
        atteso = vec["expected"]["verdict"]
        ok = v == atteso
        ok_addr = str(rec).lower() == str(vec["expected"]["recovered_address"]).lower()
        if not (ok and ok_addr):
            falliti += 1
        righe.append((vec["id"], vec["origin"], atteso, v, "OK" if (ok and ok_addr) else "FALLITO"))

    print(f"{'vettore':32s} {'origine':10s} {'atteso':8s} {'ottenuto':9s} esito")
    for r in righe:
        print(f"{r[0]:32s} {r[1]:10s} {r[2]:8s} {r[3]:9s} {r[4]}")
    print(f"\n{len(righe)} vettori · {len(righe)-falliti} conformi · {falliti} falliti")
    return 0 if falliti == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
