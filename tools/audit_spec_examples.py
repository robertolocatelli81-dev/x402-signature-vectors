#!/usr/bin/env python3
"""Audit crittografico delle firme presenti negli ESEMPI delle specifiche x402.

Domanda a cui risponde, per ogni firma trovata nei documenti normativi: recupera davvero
all'indirizzo che l'esempio dichiara? Un esempio che non verifica non e' una svista estetica —
chi lo usa come riferimento costruisce il proprio verificatore contro un dato falso.

Nessuna dipendenza esterna: Keccak-256, EIP-712 e secp256k1 sono in lib/, in Python stdlib.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from eip712 import keccak256, hash_struct          # noqa: E402
import secp256k1 as S                              # noqa: E402

FIRMA = ("0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377"
         "d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c")
FROM = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
CAMPI_DOMINIO = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                 {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]


def _rsv(sig):
    raw = bytes.fromhex(sig[2:])
    return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64] - 27


def recupera_eip712(dominio, tipi, primary, messaggio, sig=FIRMA):
    r, s, rec = _rsv(sig)
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, dominio)
    digest = keccak256(b"\x19\x01" + ds + hash_struct(primary, tipi, messaggio))
    try:
        return S.public_key_to_address(S.recover_public_key(digest, r, s, rec), keccak256)
    except Exception as e:                                     # noqa: BLE001
        return f"errore: {type(e).__name__}"


def recupera_eip191(testo, sig=FIRMA):
    """personal_sign / EIP-191: keccak256("\\x19Ethereum Signed Message:\\n" + len + messaggio)."""
    r, s, rec = _rsv(sig)
    msg = testo.encode()
    digest = keccak256(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)
    try:
        return S.public_key_to_address(S.recover_public_key(digest, r, s, rec), keccak256)
    except Exception as e:                                     # noqa: BLE001
        return f"errore: {type(e).__name__}"


def casi():
    dom_usdc = {"name": "USDC", "version": "2", "chainId": 84532, "verifyingContract": ASSET}
    fuori = []

    # 1 — EIP-3009 TransferWithAuthorization (specs/schemes/exact/scheme_exact_evm.md, esempio §Phase 1)
    fuori.append({
        "id": "exact_evm_eip3009",
        "documento": "specs/schemes/exact/scheme_exact_evm.md",
        "standard": "EIP-3009 TransferWithAuthorization (EIP-712)",
        "atteso": FROM,
        "recuperato": recupera_eip712(
            dom_usdc,
            {"TransferWithAuthorization": [
                {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]},
            "TransferWithAuthorization",
            {"from": FROM, "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "value": 10000,
             "validAfter": 1740672089, "validBefore": 1740672154,
             "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"}),
        "nota": "domain dedotto: extra.name / extra.version / CAIP-2 chain reference / accepted.asset",
    })

    # 2 — EIP-2612 Permit (specs/extensions/eip2612_gas_sponsoring.md, extensions.eip2612GasSponsoring)
    fuori.append({
        "id": "eip2612_permit",
        "documento": "specs/extensions/eip2612_gas_sponsoring.md",
        "standard": "EIP-2612 Permit (EIP-712)",
        "atteso": FROM,
        "recuperato": recupera_eip712(
            dom_usdc,
            {"Permit": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
                        {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"},
                        {"name": "deadline", "type": "uint256"}]},
            "Permit",
            {"owner": FROM, "spender": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
             "value": 115792089237316195423570985008687907853269984665640564039457584007913129639935,
             "nonce": 0, "deadline": 1740672154}),
        "nota": "stessi campi dell'esempio; spender = Canonical Permit2, value = uint256 max",
    })

    # 3 — ERC-20 approval gas sponsoring: stessa forma Permit, stesso payload dichiarato
    fuori.append({
        "id": "erc20_gas_sponsoring_permit",
        "documento": "specs/extensions/erc20_gas_sponsoring.md",
        "standard": "EIP-2612 Permit (EIP-712)",
        "atteso": FROM,
        "recuperato": recupera_eip712(
            dom_usdc,
            {"Permit": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
                        {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"},
                        {"name": "deadline", "type": "uint256"}]},
            "Permit",
            {"owner": FROM, "spender": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
             "value": 115792089237316195423570985008687907853269984665640564039457584007913129639935,
             "nonce": 0, "deadline": 1740672154}),
        "nota": "identico al precedente nel payload dichiarato",
    })

    # 4 — SIWE (specs/extensions/sign-in-with-x.md): personal_sign su messaggio ERC-4361
    messaggio_siwe = ("api.example.com wants you to sign in with your Ethereum account:\n"
                      "0x857b06519E91e3A54538791bDbb0E22373e36b66\n\n"
                      "Sign in to access premium data\n\n"
                      "URI: https://api.example.com\nVersion: 1\nChain ID: 8453\n"
                      "Nonce: a1b2c3d4e5f67890a1b2c3d4e5f67890")
    fuori.append({
        "id": "sign_in_with_x",
        "documento": "specs/extensions/sign-in-with-x.md",
        "standard": "ERC-4361 / EIP-191 personal_sign",
        "atteso": FROM,
        "recuperato": recupera_eip191(messaggio_siwe),
        "nota": ("il messaggio ERC-4361 e' ricostruito dai campi dell'esempio: la spec non pubblica "
                 "la stringa firmata, quindi questo caso resta INDICATIVO"),
        "indicativo": True,
    })
    return fuori


def main():
    ris = casi()
    print(f"AUDIT — firma {FIRMA[:20]}…{FIRMA[-8:]}  (la stessa in 7 punti di 5 documenti)\n")
    print(f"{'caso':30s} {'standard':38s} {'recuperato':44s} esito")
    conteggio = {"VALIDA": 0, "PLACEHOLDER": 0, "INDICATIVO": 0}
    for r in ris:
        ok = isinstance(r["recuperato"], str) and r["recuperato"].lower() == r["atteso"].lower()
        if r.get("indicativo") and not ok:
            esito = "non verifica (indicativo)"
            conteggio["INDICATIVO"] += 1
        elif ok:
            esito = "VALIDA"
            conteggio["VALIDA"] += 1
        else:
            esito = "PLACEHOLDER (non verifica)"
            conteggio["PLACEHOLDER"] += 1
        r["esito"] = esito
        print(f"{r['id']:30s} {r['standard']:38s} {str(r['recuperato']):44s} {esito}")
    print(f"\n{conteggio}")
    json.dump({"firma": FIRMA, "atteso": FROM, "casi": ris, "conteggio": conteggio},
              open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit",
                                "spec_examples_audit.json"), "w"), indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
