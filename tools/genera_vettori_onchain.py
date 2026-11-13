#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Vectors from real x402 payments (SPEC.md §6, origin `onchain`).

    python3 tools/genera_vettori_onchain.py                         # offline: write the vectors from
                                                                    # audit/onchain_sources.json
    python3 tools/genera_vettori_onchain.py --confronta              # offline gate: the committed vectors are
                                                                    # byte-identical to the rebuild
    python3 tools/genera_vettori_onchain.py --verifica RPC          # re-read every source from a public node and
                                                                    # compare it with audit/onchain_sources.json
    python3 tools/genera_vettori_onchain.py --raccogli RPC TX...    # write audit/onchain_sources.json from the chain

A source is a transaction on Base Sepolia (chain 84532) sent by the EVM signer that the x402 SDKs' default
facilitator publishes (https://x402.org/facilitator, `GET /supported` -> signers["eip155:*"]) to the USDC contract,
calling transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s) (selector 0xe3ee160e),
with a successful receipt. The vector is derived from the calldata alone: the message is the six decoded arguments,
the signature is r ‖ s ‖ v, the domain is USDC's (name and version read from the contract, and the domain separator
it computes is compared with the contract's DOMAIN_SEPARATOR()). The token contract checked this signature when the
transaction succeeded; the vector says the same bytes verify off chain.
"""
import json
import os
import sys
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))
sys.path.insert(0, os.path.join(BASE, "tools"))

from eip712 import keccak256, hash_struct                                   # noqa: E402
import secp256k1 as S                                                       # noqa: E402
from genera_vettori import CAMPI_DOMINIO, TIPI_3009                         # noqa: E402
from genera_vettori_50 import costruisci                                    # noqa: E402
from reject_reasons import annota                                           # noqa: E402

SOURCES = os.path.join(BASE, "audit", "onchain_sources.json")
CHAIN_ID = 84532
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
FACILITATOR = "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf"
SEL_TWA_VRS = "0xe3ee160e"
FIRST_ID = 82
STD = "EIP-3009 TransferWithAuthorization — real x402 payment"


def _rpc(url, method, params):
    req = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                                                       "params": params}).encode(),
                                 headers={"content-type": "application/json",
                                          "user-agent": "x402-signature-vectors"})
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def _call_str(url, selector_sig):
    data = _rpc(url, "eth_call", [{"to": USDC, "data": "0x" + keccak256(selector_sig.encode())[:4].hex()},
                                  "latest"])
    raw = bytes.fromhex(data[2:])
    n = int.from_bytes(raw[32:64], "big")
    return raw[64:64 + n].decode("utf-8")


def from_chain(url, hashes):
    """Everything the vector needs, read from a public node; nothing inferred."""
    dom = {"name": _call_str(url, "name()"), "version": _call_str(url, "version()"), "chainId": CHAIN_ID,
           "verifyingContract": USDC}
    sep = _rpc(url, "eth_call", [{"to": USDC, "data": "0x" + keccak256(b"DOMAIN_SEPARATOR()")[:4].hex()}, "latest"])
    chain = int(_rpc(url, "eth_chainId", []), 16)
    txs = []
    for h in hashes:
        tx = _rpc(url, "eth_getTransactionByHash", [h])
        rc = _rpc(url, "eth_getTransactionReceipt", [h])
        txs.append({"hash": h, "block": int(tx["blockNumber"], 16), "from": tx["from"], "to": tx["to"],
                    "input": tx["input"], "status": int(rc["status"], 16)})
    return {"chain_id": chain, "domain": dom, "domain_separator_onchain": sep,
            "facilitator": FACILITATOR, "transactions": txs}


def decode(inp):
    raw = bytes.fromhex(inp[2:])
    assert inp[:10] == SEL_TWA_VRS and len(raw) == 4 + 9 * 32, "not transferWithAuthorization(…, v, r, s)"
    w = [raw[4 + 32 * i: 36 + 32 * i] for i in range(9)]
    addr = lambda b: "0x" + b[12:].hex()                                  # noqa: E731
    msg = {"from": addr(w[0]), "to": addr(w[1]), "value": int.from_bytes(w[2], "big"),
           "validAfter": int.from_bytes(w[3], "big"), "validBefore": int.from_bytes(w[4], "big"),
           "nonce": "0x" + w[5].hex()}
    v = int.from_bytes(w[6], "big")
    assert v in (27, 28), f"v = {v}"
    sig = "0x" + w[7].hex() + w[8].hex() + bytes([v]).hex()
    return msg, sig


def check_sources(src):
    """The offline facts a vector rests on; any failure stops the generation."""
    assert src["chain_id"] == CHAIN_ID
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, src["domain"])
    assert "0x" + ds.hex() == src["domain_separator_onchain"].lower(), "domain separator differs from the contract's"
    for t in src["transactions"]:
        assert t["status"] == 1, f"{t['hash']}: receipt status {t['status']}"
        assert t["from"].lower() == FACILITATOR.lower(), f"{t['hash']}: sender is not the facilitator"
        assert t["to"].lower() == USDC.lower(), f"{t['hash']}: not sent to USDC"


def vectors(src):
    check_sources(src)
    out = []
    for i, t in enumerate(src["transactions"]):
        msg, sig = decode(t["input"])
        raw = bytes.fromhex(sig[2:])
        d = keccak256(b"\x19\x01" + hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, src["domain"])
                      + hash_struct("TransferWithAuthorization", TIPI_3009, msg))
        rec = S.public_key_to_address(S.recover_public_key(d, int.from_bytes(raw[:32], "big"),
                                                           int.from_bytes(raw[32:64], "big"), raw[64] - 27),
                                      keccak256)
        assert rec == msg["from"], f"{t['hash']}: recovers to {rec}, from = {msg['from']}"
        vid = f"{FIRST_ID + i:03d}-onchain-x402-base-sepolia-{t['hash'][2:10]}"
        out.append(costruisci(
            vid, "onchain", STD, dict(src["domain"]), TIPI_3009, "TransferWithAuthorization", msg, sig,
            "accept", rec,
            [f"Real x402 payment on Base Sepolia (chain {CHAIN_ID}): transaction {t['hash']}, block {t['block']}, "
             f"receipt status 1.",
             f"Sent by {FACILITATOR}, the EVM signer published by https://x402.org/facilitator (GET /supported), "
             f"the default facilitator of the x402 SDKs, to USDC {USDC}: transferWithAuthorization(…, v, r, s).",
             "Derived from the calldata only: message = the six decoded arguments, signature = r ‖ s ‖ v; domain = "
             "name() and version() of the contract, chain 84532; the domain separator equals the contract's "
             "DOMAIN_SEPARATOR(). Rebuild: tools/genera_vettori_onchain.py; re-read from a node: --verifica <rpc>."],
            signer=msg["from"]))
    return out


def main(argv):
    if argv[:1] == ["--raccogli"]:
        src = from_chain(argv[1], argv[2:])
        check_sources(src)
        with open(SOURCES, "w", encoding="utf-8") as fh:
            json.dump(src, fh, indent=2)
            fh.write("\n")
        print(f"scritto {os.path.relpath(SOURCES, BASE)}: {len(src['transactions'])} transazioni")
        return 0
    src = json.load(open(SOURCES, encoding="utf-8"))
    if argv[:1] == ["--verifica"]:
        live = from_chain(argv[1], [t["hash"] for t in src["transactions"]])
        if live != src:
            print("LE FONTI NON COINCIDONO CON LA CATENA")
            return 1
        print(f"fonti confermate dal nodo: {len(src['transactions'])} transazioni, dominio e DOMAIN_SEPARATOR()")
        return 0
    vdir = os.path.join(BASE, "vectors")
    if argv[:1] == ["--confronta"]:
        # offline, without git: the committed vectors must be the bytes this tool writes from the sources
        diversi = [v["id"] for v in vectors(src)
                   if open(os.path.join(vdir, v["id"] + ".json"), encoding="utf-8").read()
                   != json.dumps(annota(v), indent=2, ensure_ascii=False)]
        if diversi:
            print(f"VETTORI ONCHAIN DIVERSI DALLE FONTI: {diversi}")
            return 1
        print(f"vettori onchain identici alla ricostruzione dalle fonti: {len(src['transactions'])}")
        return 0
    for vec in vectors(src):
        with open(os.path.join(vdir, vec["id"] + ".json"), "w", encoding="utf-8") as fh:
            json.dump(annota(vec), fh, indent=2, ensure_ascii=False)
        print(f"  {vec['id']:52s} {vec['expected']['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
