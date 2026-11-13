#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Audit of the signature examples in the x402 specifications, at a pinned upstream commit.

    python3 tools/audit_spec_examples.py                 # recompute every case; exit 1 if any result differs
                                                         # from audit/spec_examples_audit.json (CI gate)
    python3 tools/audit_spec_examples.py --scrivi        # rewrite audit/spec_examples_audit.json
    python3 tools/audit_spec_examples.py --specs DIR     # provenance: DIR = specs/ of x402-foundation/x402 at
                                                         # PINNED; every case must sit at its document and line

The question, for every occurrence of the reused 65-byte signature under specs/: does it recover to the address the
example itself declares as the signer? Each case is modelled from the JSON or text the document publishes at PINNED;
the domain is the one the example implies (extra.name, extra.version, the CAIP-2 chain, the asset; the canonical
Permit2 domain for Permit2 payloads).

Why a reconstruction cannot rescue a non-matching case: with r, s and the recovery id fixed, the recovered key is
Q = r^-1 (sR - zG), so two digests that differ modulo the group order give two different keys. The bytes verify for
the EIP-3009 digest of scheme_exact_evm.md; any example whose message has a different digest recovers to some other
key, whatever domain or string one assumes (barring a 160-bit address collision between the two keys).

No dependency: Keccak-256, EIP-712 and secp256k1 come from lib/, in the Python standard library.
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))

from eip712 import keccak256, hash_struct          # noqa: E402
import secp256k1 as S                              # noqa: E402

PINNED = "2178d4b77aff61395c375bbdf30757876393b85d"      # x402-foundation/x402, 2026-11-13T08:22:04Z
FIRMA = ("0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377"
         "d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c")
FROM = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
NONCE_3009 = "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
OUT = os.path.join(BASE, "audit", "spec_examples_audit.json")

D4 = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]
D3 = [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}]
TWA = {"TransferWithAuthorization": [
    {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]}
PERMIT = {"Permit": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
                     {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"},
                     {"name": "deadline", "type": "uint256"}]}
# scheme_exact_evm.md: WITNESS_TYPE_STRING = "Witness witness)TokenPermissions(address token,uint256 amount)
# Witness(address to,uint256 validAfter)"
P2W = {"PermitWitnessTransferFrom": [
    {"name": "permitted", "type": "TokenPermissions"}, {"name": "spender", "type": "address"},
    {"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"},
    {"name": "witness", "type": "Witness"}],
    "TokenPermissions": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}],
    "Witness": [{"name": "to", "type": "address"}, {"name": "validAfter", "type": "uint256"}]}
UINT_MAX = 2 ** 256 - 1

# sign-in-with-x.md, section "Message Format" > "EVM (SIWE/EIP-4361)", the published string, verbatim.
SIWE = ("api.example.com wants you to sign in with your Ethereum account:\n"
        "0x857b06519E91e3A54538791bDbb0E22373e36b66\n\n"
        "Sign in to access premium data\n\n"
        "URI: https://api.example.com/premium-data\n"
        "Version: 1\n"
        "Chain ID: 8453\n"
        "Nonce: a1b2c3d4e5f67890a1b2c3d4e5f67890\n"
        "Issued At: 2024-01-15T10:30:00.000Z\n"
        "Expiration Time: 2024-01-15T10:35:00.000Z\n"
        "Resources:\n"
        "- https://api.example.com/premium-data")


def _rsv(sig):
    raw = bytes.fromhex(sig[2:])
    return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64] - 27


def _recover(digest):
    r, s, rec = _rsv(FIRMA)
    try:
        return S.public_key_to_address(S.recover_public_key(digest, r, s, rec), keccak256)
    except Exception as e:                                     # noqa: BLE001
        return f"errore: {type(e).__name__}"


def digest_eip712(domain_fields, domain, types, primary, message):
    ds = hash_struct("EIP712Domain", {"EIP712Domain": domain_fields}, domain)
    return keccak256(b"\x19\x01" + ds + hash_struct(primary, types, message))


def digest_eip191(text):
    msg = text.encode()
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)


def twa(chain_id, value=10000, to=TO):
    return (D4, {"name": "USDC", "version": "2", "chainId": chain_id, "verifyingContract": USDC_BASE_SEPOLIA},
            TWA, "TransferWithAuthorization",
            {"from": FROM, "to": to, "value": value, "validAfter": 1740672089, "validBefore": 1740672154,
             "nonce": NONCE_3009})


def permit2_exact():
    return (D3, {"name": "Permit2", "chainId": 84532, "verifyingContract": PERMIT2}, P2W,
            "PermitWitnessTransferFrom",
            {"permitted": {"token": USDC_BASE_SEPOLIA, "amount": 10000},
             "spender": "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
             "nonce": 33247007178036348590600198031289925668252061821958005840077069883511451257277,
             "deadline": 1740672154, "witness": {"to": TO, "validAfter": 1740672089}})


# Every occurrence of FIRMA (as hex) under specs/ at PINNED: (document, line, kind, model).
# model: ("eip712", args) | ("eip191", text) | ("non_codificabile", reason)
_DOM_V1 = "the v1 block names network base-sepolia, not the asset: domain of the v2 example (USDC on Base Sepolia)"
CASI = [
    ("schemes/exact/scheme_exact_evm.md", 56, "EIP-3009 TransferWithAuthorization", ("eip712", twa(84532)), None),
    ("x402-specification-v2.md", 179, "EIP-3009 TransferWithAuthorization", ("eip712", twa(84532)), None),
    ("transports-v2/http.md", 98, "EIP-3009 TransferWithAuthorization", ("eip712", twa(84532)), None),
    ("transports-v2/mcp.md", 121, "EIP-3009 TransferWithAuthorization", ("eip712", twa(84532)), None),
    ("x402-specification-v1.md", 138, "EIP-3009 TransferWithAuthorization (v1)", ("eip712", twa(84532)), _DOM_V1),
    ("transports-v1/http.md", 72, "EIP-3009 TransferWithAuthorization (v1)", ("eip712", twa(84532)), _DOM_V1),
    ("transports-v1/mcp.md", 104, "EIP-3009 TransferWithAuthorization (v1)", ("eip712", twa(84532)), _DOM_V1),
    ("transports-v1/a2a.md", 93, "EIP-3009 TransferWithAuthorization (v1)",
     ("non_codificabile", "authorization.to is \"0xServerWalletAddressHere\", not an address"), None),
    ("transports-v2/a2a.md", 109, "EIP-3009 TransferWithAuthorization",
     ("non_codificabile", "authorization.to is \"0xServerWalletAddressHere\", not an address"), None),
    ("schemes/exact/scheme_exact_evm.md", 149, "Permit2 PermitWitnessTransferFrom", ("eip712", permit2_exact()),
     "canonical Permit2 domain (no version), chain 84532; witness types from WITNESS_TYPE_STRING"),
    ("extensions/eip2612_gas_sponsoring.md", 124, "Permit2 PermitWitnessTransferFrom", ("eip712", permit2_exact()),
     "the payload block is the one of scheme_exact_evm.md:149"),
    ("extensions/erc20_gas_sponsoring.md", 150, "Permit2 PermitWitnessTransferFrom", ("eip712", permit2_exact()),
     "the signature sits in payload.permit2Authorization only; the extension's info carries a signedTransaction, "
     "not this signature"),
    ("extensions/eip2612_gas_sponsoring.md", 149, "EIP-2612 Permit",
     ("eip712", (D4, {"name": "USDC", "version": "2", "chainId": 84532, "verifyingContract": USDC_BASE_SEPOLIA},
                 PERMIT, "Permit", {"owner": FROM, "spender": PERMIT2, "value": UINT_MAX, "nonce": 0,
                                    "deadline": 1740672154})),
     "token domain from extra (name USDC, version 2); info.version \"1\" is the schema version"),
    ("schemes/upto/scheme_upto_evm.md", 120, "Permit2 PermitWitnessTransferFrom (upto)",
     ("non_codificabile", "witness.facilitator is \"0xFacilitatorAddress1234567890123456789012\", not an address; "
                          "nonce is a bytes32 hex string where Permit2 declares uint256"), None),
    ("extensions/sign-in-with-x.md", 150, "ERC-4361 / EIP-191 personal_sign", ("eip191", SIWE),
     "the EVM string published in the section \"Message Format\" of the same document"),
]


def casi():
    fuori = []
    d_valido = digest_eip712(*twa(84532))
    for doc, riga, standard, (tipo, arg), nota in CASI:
        c = {"documento": f"specs/{doc}", "riga": riga, "standard": standard, "atteso": FROM}
        if tipo == "eip712":
            d = digest_eip712(*arg)
        elif tipo == "eip191":
            d = digest_eip191(arg)
        else:
            d = None
        if d is None:
            c.update(recuperato=None, digest=None, esito="NON CODIFICABILE", nota=arg)
        else:
            rec = _recover(d)
            ok = rec.lower() == FROM.lower()
            c.update(recuperato=rec, digest="0x" + d.hex(), stesso_digest_del_valido=(d == d_valido),
                     esito="VALIDA" if ok else "NON VERIFICA", nota=nota)
        fuori.append(c)
    return fuori


def provenienza(specs):
    """Every case at its document and line, and no occurrence outside the cases."""
    problemi, hexa = [], FIRMA[2:]
    tutte = []
    for radice, _, files in os.walk(specs):
        for f in sorted(files):
            p = os.path.join(radice, f)
            with open(p, encoding="utf-8", errors="replace") as fh:
                for i, linea in enumerate(fh, 1):
                    if hexa in linea:
                        tutte.append((os.path.relpath(p, specs), i))
    attese = sorted((d, r) for d, r, *_ in CASI)
    if sorted(tutte) != attese:
        problemi.append(f"occorrenze nel testo {sorted(tutte)} != casi {attese}")
    siwx = open(os.path.join(specs, "extensions", "sign-in-with-x.md"), encoding="utf-8").read()
    if "```\n" + SIWE + "\n```" not in siwx:
        problemi.append("la stringa SIWE del caso non e' quella pubblicata in sign-in-with-x.md")
    return problemi, len(tutte), len({d for d, _ in tutte})


def main(argv):
    if argv[:1] == ["--specs"]:
        problemi, n, docs = provenienza(argv[1])
        if problemi:
            print("PROVENIENZA NON CONFERMATA:")
            [print("  " + p) for p in problemi]
            return 1
        print(f"provenienza: {n} occorrenze in {docs} documenti, ognuna al suo caso; stringa SIWE identica")
        return 0
    ris = casi()
    conteggio = {}
    print(f"AUDIT @ x402-foundation/x402 {PINNED[:12]} — firma {FIRMA[:12]}…{FIRMA[-8:]}, "
          f"{len(ris)} occorrenze in {len({r['documento'] for r in ris})} documenti\n")
    for r in ris:
        conteggio[r["esito"]] = conteggio.get(r["esito"], 0) + 1
        print(f"{r['documento'] + ':' + str(r['riga']):44s} {r['standard'][:40]:40s} "
              f"{str(r['recuperato']):44s} {r['esito']}")
    print(f"\n{conteggio}")
    dati = {"upstream": "x402-foundation/x402", "commit": PINNED, "firma": FIRMA, "atteso": FROM,
            "casi": ris, "conteggio": conteggio}
    if argv[:1] == ["--scrivi"]:
        with open(OUT, "w", encoding="utf-8") as fh:
            json.dump(dati, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print("scritto", os.path.relpath(OUT, BASE))
        return 0
    # Gate: il risultato ricalcolato deve essere quello pubblicato in audit/ (prima lo riscriveva sempre ed usciva 0).
    pubblicato = json.load(open(OUT, encoding="utf-8"))
    if pubblicato != json.loads(json.dumps(dati, ensure_ascii=False)):
        print("AUDIT DIVERSO DA audit/spec_examples_audit.json: ricalcolo e file pubblicato non coincidono")
        return 1
    print("audit/spec_examples_audit.json coincide con il ricalcolo")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
