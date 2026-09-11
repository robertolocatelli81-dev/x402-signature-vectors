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

# Ordine canonico dei campi di EIP712Domain. I campi sono OPZIONALI: il typeHash si calcola su
# quelli effettivamente presenti. Una lista fissa a quattro campi sbaglia su ogni dominio parziale —
# per esempio quello del contratto Permit2, che non ha `version` (vettore 035).
_ORDINE_DOMINIO = [("name", "string"), ("version", "string"), ("chainId", "uint256"),
                   ("verifyingContract", "address"), ("salt", "bytes32")]


def campi_dominio(dominio):
    return [{"name": n, "type": t} for n, t in _ORDINE_DOMINIO if n in dominio]


def controlli_firma(sig_hex):
    """Regole che una firma deve rispettare PRIMA del recupero (EIP-2 e range di secp256k1).

    Un verificatore che si limita a ecrecover accetta anche la firma malleabile (r, N-s), cioe' la
    stessa autorizzazione in due forme con hash diversi: e' la porta d'ingresso del replay.
    """
    # L'input arriva dalla rete: ogni assunzione va verificata PRIMA di usarla. Un fromhex() su una
    # stringa arbitraria solleva ValueError, e un verificatore che solleva invece di rifiutare e' un
    # denial of service. (Misurato: 79 eccezioni non gestite su 600 input malevoli, prima di questo.)
    if not isinstance(sig_hex, str) or not sig_hex.startswith("0x"):
        return "firma non e' una stringa 0x"
    corpo = sig_hex[2:]
    if len(corpo) % 2 or any(c not in "0123456789abcdefABCDEF" for c in corpo):
        return "firma non esadecimale"
    raw = bytes.fromhex(corpo)
    if len(raw) != 65:
        return "lunghezza != 65 byte"
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64]
    if v not in (27, 28):
        return f"v = {v} fuori dai valori ammessi (27/28)"
    if not (1 <= r < S.N):
        return "r fuori dal range [1, N-1]"
    if not (1 <= s < S.N):
        return "s fuori dal range [1, N-1]"
    if s > S.N // 2:
        return "s alto: viola la regola low-s di EIP-2 (firma malleabile)"
    return None


def recupera(vec):
    e = vec["eip712"]
    ds = hash_struct("EIP712Domain", {"EIP712Domain": campi_dominio(e["domain"])}, e["domain"])
    digest = keccak256(b"\x19\x01" + ds + hash_struct(e["primaryType"], e["types"], e["message"]))
    raw = bytes.fromhex(vec["signature"][2:])
    pub = S.recover_public_key(digest, int.from_bytes(raw[:32], "big"),
                               int.from_bytes(raw[32:64], "big"), raw[64] - 27)
    return S.public_key_to_address(pub, keccak256)


def verdetto(vec):
    """accept sse la firma supera i controlli di forma E recupera al firmatario dichiarato."""
    try:
        problema = controlli_firma(vec.get("signature"))
    except Exception:                                        # noqa: BLE001 — nessun input deve passare oltre
        return "reject", None, "firma non interpretabile"
    if problema:
        # Il verdetto e' reject, ma se il recupero e' comunque definito (caso tipico: firma
        # malleabile high-s, matematicamente valida) l'indirizzo si RIPORTA: serve a chi sta
        # debuggando, e distingue "rifiutata da una regola" da "non recuperabile".
        try:
            return "reject", recupera(vec), problema
        except Exception:                                    # noqa: BLE001
            return "reject", None, problema
    try:
        rec = recupera(vec)
    except Exception:                                        # noqa: BLE001
        return "reject", None, "recupero non definito"
    # Il firmatario e' DICHIARATO nel vettore: dedurlo dal nome del campo ("from", "owner"…) funziona
    # solo finche' le struct si chiamano come ci si aspetta, e i vettori strutturali non lo fanno.
    firmatario = vec.get("signer")
    if not firmatario:
        return "reject", rec, "vettore senza `signer` dichiarato"
    ok = rec.lower() == str(firmatario).lower()
    return ("accept" if ok else "reject"), rec, (None if ok else "recupera a un indirizzo diverso")


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
        v, rec, perche = verdetto(vec)
        atteso = vec["expected"]["verdict"]
        ok = v == atteso
        att_addr = vec["expected"]["recovered_address"]
        ok_addr = (rec is None and att_addr is None) or (
            rec is not None and att_addr is not None and rec.lower() == str(att_addr).lower())
        if not (ok and ok_addr):
            falliti += 1
        righe.append((vec["id"], vec["origin"], atteso, v,
                      "OK" if (ok and ok_addr) else "FALLITO", perche or ""))

    print(f"{'vettore':32s} {'origine':10s} {'atteso':8s} {'ottenuto':9s} {'esito':8s} motivo del reject")
    for r in righe:
        print(f"{r[0]:32s} {r[1]:10s} {r[2]:8s} {r[3]:9s} {r[4]:8s} {r[5][:44]}")
    print(f"\n{len(righe)} vettori · {len(righe)-falliti} conformi · {falliti} falliti")
    return 0 if falliti == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
