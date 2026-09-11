#!/usr/bin/env python3
"""Genera i vettori di conformita' firmati della suite.

Due categorie, tenute distinte perche' hanno statuto diverso:
  - `spec`      : payload e firma presi TALI E QUALI dalle specifiche x402 ufficiali. Il verdetto
                  atteso e' il risultato dell'audit (accept se la firma verifica, reject se no).
  - `generated` : firmati qui con una chiave di test PUBBLICA e dichiarata, cosi' che esista un
                  vettore valido anche dove la spec non ne offre uno utilizzabile.

La chiave di test e' pubblicata in chiaro di proposito: un vettore di conformita' non deve
custodire segreti, deve essere rifattibile da chiunque.
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))

from eip712 import keccak256, hash_struct           # noqa: E402
import secp256k1 as S                               # noqa: E402

CHIAVE_TEST = 0x4646464646464646464646464646464646464646464646464646464646464646
K_DETERMINISTICO = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
CAMPI_DOMINIO = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                 {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]
ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
DOM_USDC = {"name": "USDC", "version": "2", "chainId": 84532, "verifyingContract": ASSET}

TIPI_3009 = {"TransferWithAuthorization": [
    {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]}
TIPI_2612 = {"Permit": [
    {"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
    {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"},
    {"name": "deadline", "type": "uint256"}]}


def indirizzo_test():
    from secp256k1 import _mul, GX, GY
    return S.public_key_to_address(_mul(CHIAVE_TEST, (GX, GY)), keccak256)


def digest(dominio, tipi, primary, messaggio):
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, dominio)
    return keccak256(b"\x19\x01" + ds + hash_struct(primary, tipi, messaggio))


def firma(d):
    r, s, rec = S.sign(d, CHIAVE_TEST, K_DETERMINISTICO)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([rec + 27]).hex()


def vettore(vid, origine, standard, dominio, tipi, primary, messaggio, sig, verdetto, atteso, note):
    return {"id": vid, "origin": origine, "standard": standard,
            "eip712": {"domain": dominio, "types": tipi, "primaryType": primary, "message": messaggio},
            "signature": sig,
            "expected": {"verdict": verdetto, "recovered_address": atteso},
            "notes": note}


def costruisci():
    addr = indirizzo_test()
    FROM_SPEC = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
    SIG_SPEC = ("0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377"
                "d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c")
    v = []

    msg_3009 = {"from": FROM_SPEC, "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "value": 10000,
                "validAfter": 1740672089, "validBefore": 1740672154,
                "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"}
    v.append(vettore(
        "001-eip3009-spec-example", "spec", "EIP-3009 TransferWithAuthorization",
        DOM_USDC, TIPI_3009, "TransferWithAuthorization", msg_3009, SIG_SPEC, "accept", FROM_SPEC,
        ["Payload e firma da specs/schemes/exact/scheme_exact_evm.md (Phase 1 example).",
         "Verifica: la firma recupera all'authorization.from dichiarato.",
         "Il domain non e' scritto in nessun .md normativo: qui e' esplicitato ed e' quello che rende "
         "valida la firma gia' pubblicata (vedi coinbase/x402#324)."]))

    msg_2612 = {"owner": FROM_SPEC, "spender": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                "value": 115792089237316195423570985008687907853269984665640564039457584007913129639935,
                "nonce": 0, "deadline": 1740672154}
    v.append(vettore(
        "002-eip2612-spec-example", "spec", "EIP-2612 Permit",
        DOM_USDC, TIPI_2612, "Permit", msg_2612, SIG_SPEC, "reject",
        "0xd259c1962ac82d9033ea21cf55d59c1a5d97acbb",
        ["Payload da specs/extensions/eip2612_gas_sponsoring.md.",
         "La firma e' BYTE-IDENTICA a quella del vettore 001, ma il messaggio e' diverso: una firma "
         "ECDSA vale per un solo messaggio, quindi qui NON puo' verificare.",
         "Recupera a un indirizzo che non ha relazione con l'owner dichiarato: e' un placeholder.",
         "Un verificatore corretto DEVE rifiutarlo."]))

    d3 = digest(DOM_USDC, TIPI_3009, "TransferWithAuthorization", dict(msg_3009, **{"from": addr}))
    v.append(vettore(
        "003-eip3009-generated-valid", "generated", "EIP-3009 TransferWithAuthorization",
        DOM_USDC, TIPI_3009, "TransferWithAuthorization", dict(msg_3009, **{"from": addr}),
        firma(d3), "accept", addr,
        ["Firmato qui con la chiave di test pubblica dichiarata nel README.",
         "Serve come controllo positivo indipendente dagli esempi della spec."]))

    msg_2612_v = dict(msg_2612, owner=addr)
    d4 = digest(DOM_USDC, TIPI_2612, "Permit", msg_2612_v)
    v.append(vettore(
        "004-eip2612-generated-valid", "generated", "EIP-2612 Permit",
        DOM_USDC, TIPI_2612, "Permit", msg_2612_v, firma(d4), "accept", addr,
        ["Il vettore valido per EIP-2612 che la spec non offre (il suo esempio e' il 002).",
         "Chi implementa il gas sponsoring puo' finalmente testare contro un caso che passa."]))

    # mutazioni avversariali sul 003: ognuna DEVE essere rifiutata
    mutazioni = [
        ("005-mutated-value", {"value": 10001}, "importo alterato di 1 unita'"),
        ("006-mutated-to", {"to": "0x0000000000000000000000000000000000000001"}, "destinatario sostituito"),
        ("007-mutated-validBefore", {"validBefore": 1740672155}, "finestra di validita' spostata di 1 secondo"),
    ]
    for mid, patch, perche in mutazioni:
        msg_m = dict(msg_3009, **{"from": addr}, **patch)
        rec = S.public_key_to_address(
            S.recover_public_key(digest(DOM_USDC, TIPI_3009, "TransferWithAuthorization", msg_m),
                                 int(firma(d3)[2:66], 16), int(firma(d3)[66:130], 16),
                                 int(firma(d3)[130:132], 16) - 27), keccak256)
        v.append(vettore(
            mid, "generated", "EIP-3009 TransferWithAuthorization",
            DOM_USDC, TIPI_3009, "TransferWithAuthorization", msg_m, firma(d3), "reject", rec,
            [f"Mutazione del vettore 003: {perche}.",
             "La firma resta quella del 003: un verificatore che accetta questo vettore non sta "
             "legando la firma al messaggio."]))

    # dominio sbagliato: stesso messaggio e firma del 003, ma chainId di un'altra rete
    dom_sbagliato = dict(DOM_USDC, chainId=8453)
    rec_dom = S.public_key_to_address(
        S.recover_public_key(digest(dom_sbagliato, TIPI_3009, "TransferWithAuthorization",
                                    dict(msg_3009, **{"from": addr})),
                             int(firma(d3)[2:66], 16), int(firma(d3)[66:130], 16),
                             int(firma(d3)[130:132], 16) - 27), keccak256)
    v.append(vettore(
        "008-wrong-domain-chainid", "generated", "EIP-3009 TransferWithAuthorization",
        dom_sbagliato, TIPI_3009, "TransferWithAuthorization", dict(msg_3009, **{"from": addr}),
        firma(d3), "reject", rec_dom,
        ["Stesso messaggio e stessa firma del 003, ma chainId di un'altra rete (8453 invece di 84532).",
         "E' il caso che il mapping mancante del domain rende facile sbagliare: il verificatore non "
         "vede un errore tipizzato, vede solo una firma che recupera all'indirizzo sbagliato."]))
    return v


def main():
    vdir = os.path.join(BASE, "vectors")
    os.makedirs(vdir, exist_ok=True)
    vettori = costruisci()
    for vec in vettori:
        with open(os.path.join(vdir, vec["id"] + ".json"), "w") as f:
            json.dump(vec, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(f"indirizzo della chiave di test: {indirizzo_test()}")
    print(f"vettori scritti: {len(vettori)}")
    for vec in vettori:
        print(f"  {vec['id']:32s} {vec['origin']:10s} {vec['expected']['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
