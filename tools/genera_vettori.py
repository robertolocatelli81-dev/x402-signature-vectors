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
    """I digest intermedi sono parte dell'atteso, non un di piu'.

    Senza, un'implementazione che fallisce sa solo "non verifica" e non se ha sbagliato l'ENCODING
    (typeHash/hashStruct/domainSeparator) o il RECUPERO ECDSA. Con questi campi i due strati si
    testano separatamente, che e' la differenza fra una suite diagnosticabile e un semaforo."""
    from eip712 import type_hash
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, dominio)
    hs = hash_struct(primary, tipi, messaggio)
    firmatario = (messaggio.get("from") or messaggio.get("owner") or messaggio.get("acquirente")
                  or messaggio.get("chi") or (messaggio.get("da", {}) or {}).get("conto", {}).get("indirizzo")
                  or indirizzo_test())
    return {"id": vid, "origin": origine, "standard": standard,
            "signer": firmatario,
            "eip712": {"domain": dominio, "types": tipi, "primaryType": primary, "message": messaggio},
            "signature": sig,
            "expected": {"verdict": verdetto, "recovered_address": atteso,
                         "type_hash": "0x" + type_hash(primary, tipi).hex(),
                         "domain_separator": "0x" + ds.hex(),
                         "hash_struct": "0x" + hs.hex(),
                         "signing_digest": "0x" + keccak256(b"\x19\x01" + ds + hs).hex()},
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
        ("007-mutated-valid-before", {"validBefore": 1740672155}, "finestra di validita' spostata di 1 secondo"),
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


def costruisci_strutturali():
    """Casi dove le implementazioni EIP-712 divergono per davvero: array, struct annidate,
    stringhe con byte nulli, ordinamento dei tipi in encodeType.

    Non sono payload x402: sono le regole di encoding che x402 eredita da EIP-712 e su cui un SDK
    sbaglia prima di arrivare al pagamento.
    """
    addr = indirizzo_test()
    out = []

    # array dinamico di struct: EIP-712 hasha la concatenazione degli hashStruct degli elementi
    tipi_arr = {"Ordine": [{"name": "acquirente", "type": "address"}, {"name": "voci", "type": "Voce[]"}],
                "Voce": [{"name": "sku", "type": "string"}, {"name": "quantita", "type": "uint256"}]}
    msg_arr = {"acquirente": addr, "voci": [{"sku": "A-1", "quantita": 2}, {"sku": "B-2", "quantita": 1}]}
    d = digest_generico(DOM_USDC, tipi_arr, "Ordine", msg_arr)
    out.append(vettore("019-eip712-array-of-structs", "generated", "EIP-712 encoding (array di struct)",
        DOM_USDC, tipi_arr, "Ordine", msg_arr, firma(d), "accept", addr,
        ["Array dinamico di struct: l'hash di un array e' keccak256 della CONCATENAZIONE degli "
         "hashStruct dei suoi elementi, non del JSON dell'array.",
         "encodeType deve produrre Ordine(address acquirente,Voce[] voci)Voce(string sku,uint256 quantita): "
         "i tipi referenziati seguono in ordine alfabetico.",
         "Un'implementazione che serializza l'array come stringa fallisce qui e in nessun altro vettore."]))

    # struct annidata a due livelli
    tipi_nest = {"Busta": [{"name": "da", "type": "Parte"}, {"name": "a", "type": "Parte"},
                           {"name": "nota", "type": "string"}],
                 "Parte": [{"name": "nome", "type": "string"}, {"name": "conto", "type": "Conto"}],
                 "Conto": [{"name": "indirizzo", "type": "address"}, {"name": "catena", "type": "uint256"}]}
    msg_nest = {"da": {"nome": "Alice", "conto": {"indirizzo": addr, "catena": 84532}},
                "a": {"nome": "Bob", "conto": {"indirizzo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                                               "catena": 8453}},
                "nota": "due livelli"}
    d = digest_generico(DOM_USDC, tipi_nest, "Busta", msg_nest)
    out.append(vettore("020-eip712-nested-structs", "generated", "EIP-712 encoding (annidamento)",
        DOM_USDC, tipi_nest, "Busta", msg_nest, firma(d), "accept", addr,
        ["Struct annidate su due livelli: ogni struct contribuisce con il proprio hashStruct.",
         "encodeType raccoglie i tipi referenziati RICORSIVAMENTE e li ordina alfabeticamente: "
         "Busta(...)Conto(...)Parte(...). Sbagliare l'ordine cambia il typeHash e quindi tutto."]))

    # stringa con byte nullo a meta': tronca o hasha per intero?
    tipi_s = {"Messaggio": [{"name": "chi", "type": "address"}, {"name": "testo", "type": "string"}]}
    msg_s = {"chi": addr, "testo": "prima\u0000dopo"}
    d = digest_generico(DOM_USDC, tipi_s, "Messaggio", msg_s)
    out.append(vettore("021-eip712-string-null-byte", "generated", "EIP-712 encoding (stringhe)",
        DOM_USDC, tipi_s, "Messaggio", msg_s, firma(d), "accept", addr,
        ["La stringa contiene un byte NULLO a meta'. EIP-712 hasha i byte UTF-8 per intero: una "
         "implementazione che tratta le stringhe alla maniera del C tronca a 'prima' e ottiene un "
         "hashStruct diverso.",
         "E' il caso che separa chi lavora sui byte da chi lavora su stringhe C."]))

    # ordinamento dei tipi in encodeType: B prima di A nel dizionario, ma A prima di B nell'encoding
    tipi_ord = {"Radice": [{"name": "b", "type": "Zeta"}, {"name": "a", "type": "Alfa"}],
                "Zeta": [{"name": "v", "type": "uint256"}],
                "Alfa": [{"name": "v", "type": "uint256"}]}
    msg_ord = {"b": {"v": 2}, "a": {"v": 1}}
    d = digest_generico(DOM_USDC, tipi_ord, "Radice", msg_ord)
    out.append(vettore("022-eip712-type-ordering", "generated", "EIP-712 encoding (ordinamento tipi)",
        DOM_USDC, tipi_ord, "Radice", msg_ord, firma(d), "accept", addr,
        ["I tipi referenziati compaiono in encodeType in ordine ALFABETICO (Alfa prima di Zeta), "
         "indipendentemente dall'ordine in cui appaiono nella struct o nel JSON.",
         "L'atteso `type_hash` in questo vettore e' la verifica diretta di quella regola: "
         "un'implementazione che conserva l'ordine di dichiarazione produce un typeHash diverso."]))
    return out


def digest_generico(dominio, tipi, primary, messaggio):
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, dominio)
    return keccak256(b"\x19\x01" + ds + hash_struct(primary, tipi, messaggio))


def main():
    vdir = os.path.join(BASE, "vectors")
    os.makedirs(vdir, exist_ok=True)
    vettori = costruisci() + costruisci_edge() + costruisci_strutturali()
    for vec in vettori:
        with open(os.path.join(vdir, vec["id"] + ".json"), "w") as f:
            json.dump(vec, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(f"indirizzo della chiave di test: {indirizzo_test()}")
    print(f"vettori scritti: {len(vettori)}")
    for vec in vettori:
        print(f"  {vec['id']:32s} {vec['origin']:10s} {vec['expected']['verdict']}")
    return 0




# ─────────────────────────── edge case crittografici (v0.2) ───────────────────────────
def costruisci_edge():
    """Casi che un verificatore sbaglia davvero: malleabilita', bordi degli interi, firme malformate.

    Non sono vettori "didattici": ognuno corrisponde a un modo documentato di rompere una verifica
    EIP-712/ECDSA. Dove il recupero non e' definito, l'atteso e' `null` e il verdetto e' reject.
    """
    from secp256k1 import N as ORDINE
    addr = indirizzo_test()
    base_msg = {"from": addr, "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "value": 10000,
                "validAfter": 1740672089, "validBefore": 1740672154,
                "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"}
    d = digest(DOM_USDC, TIPI_3009, "TransferWithAuthorization", base_msg)
    sig_valida = firma(d)
    r = int(sig_valida[2:66], 16)
    s = int(sig_valida[66:130], 16)
    v = int(sig_valida[130:132], 16)
    out = []

    def rec_o_none(sig, messaggio=base_msg, dominio=DOM_USDC):
        try:
            raw = bytes.fromhex(sig[2:])
            dd = digest(dominio, TIPI_3009, "TransferWithAuthorization", messaggio)
            pub = S.recover_public_key(dd, int.from_bytes(raw[:32], "big"),
                                       int.from_bytes(raw[32:64], "big"), raw[64] - 27)
            return S.public_key_to_address(pub, keccak256)
        except Exception:                                      # noqa: BLE001
            return None

    # malleabilita' ECDSA: (r, N-s) e' una firma matematicamente valida sullo stesso messaggio.
    # EIP-2 impone low-s: un verificatore conforme DEVE rifiutarla.
    s_alto = ORDINE - s
    v_flip = 28 if v == 27 else 27
    sig_mall = "0x" + r.to_bytes(32, "big").hex() + s_alto.to_bytes(32, "big").hex() + bytes([v_flip]).hex()
    out.append(vettore(
        "009-ecdsa-malleability-high-s", "generated", "EIP-3009 TransferWithAuthorization",
        DOM_USDC, TIPI_3009, "TransferWithAuthorization", base_msg, sig_mall, "reject",
        rec_o_none(sig_mall),
        ["Firma (r, N-s) con v invertito: matematicamente valida sullo STESSO messaggio e recupera "
         "allo STESSO indirizzo del vettore 003 — per questo `recovered_address` NON e' null: il "
         "recupero e' definito, e' la regola low-s a imporre il reject.",
         "EIP-2 impone s <= N/2 (low-s): un verificatore conforme deve RIFIUTARLA, altrimenti la "
         "stessa autorizzazione esiste in due forme con hash diversi — la porta d'ingresso del replay.",
         "E' il vettore che separa un verificatore corretto da uno che si limita a fare ecrecover."]))

    # bordi di uint256
    for vid, patch, perche in [
        ("010-value-zero", {"value": 0}, "importo nullo"),
        ("011-value-max-uint256", {"value": 2**256 - 1}, "importo al massimo rappresentabile"),
        ("012-window-inverted", {"validAfter": 1740672154, "validBefore": 1740672089},
         "finestra di validita' invertita (after > before)"),
    ]:
        m = dict(base_msg, **patch)
        dd = digest(DOM_USDC, TIPI_3009, "TransferWithAuthorization", m)
        sg = firma(dd)
        out.append(vettore(
            vid, "generated", "EIP-3009 TransferWithAuthorization",
            DOM_USDC, TIPI_3009, "TransferWithAuthorization", m, sg, "accept", addr,
            [f"Bordo: {perche}. La FIRMA e' valida e deve verificare.",
             "MARCATORE DI CONFINE, non un test crittografico: serve a dimostrare che il livello "
             "firma NON deve applicare regole di business. Chi lo rifiuta sta mischiando i livelli.",
             "Il verdetto crittografico e' accept: rifiutarlo per ragioni di policy (importo nullo, "
             "finestra invertita) e' compito del livello sopra, e va tenuto distinto dalla firma."]))

    # firme malformate: il recupero non e' definito
    for vid, sig, perche in [
        ("013-signature-r-zero", "0x" + "00" * 32 + s.to_bytes(32, "big").hex() + bytes([v]).hex(),
         "r = 0, fuori dal range [1, N-1]"),
        ("014-signature-s-zero", "0x" + r.to_bytes(32, "big").hex() + "00" * 32 + bytes([v]).hex(),
         "s = 0, fuori dal range [1, N-1]"),
        ("015-signature-v-out-of-range", sig_valida[:-2] + "1f",
         "v = 31, fuori dai valori ammessi (27/28)"),
        ("016-signature-r-equals-n", "0x" + ORDINE.to_bytes(32, "big").hex()
         + s.to_bytes(32, "big").hex() + bytes([v]).hex(),
         "r = N (ordine del gruppo): non e' una coordinata valida"),
    ]:
        out.append(vettore(
            vid, "generated", "EIP-3009 TransferWithAuthorization",
            DOM_USDC, TIPI_3009, "TransferWithAuthorization", base_msg, sig, "reject", rec_o_none(sig),
            [f"Firma malformata: {perche}.",
             "Il recupero non e' definito: il verificatore deve rifiutare senza sollevare eccezioni "
             "non gestite. Una libreria che qui lancia invece di rifiutare e' un denial of service."]))

    # unicode nel domain name: l'encoding della stringa entra nel typeHash
    dom_uni = dict(DOM_USDC, name="USD€")
    d_uni = digest(dom_uni, TIPI_3009, "TransferWithAuthorization", base_msg)
    out.append(vettore(
        "017-domain-name-non-ascii", "generated", "EIP-3009 TransferWithAuthorization",
        dom_uni, TIPI_3009, "TransferWithAuthorization", base_msg, firma(d_uni), "accept", addr,
        ["Il `name` del dominio contiene un carattere non ASCII (USD€).",
         "In EIP-712 una stringa e' hashata come keccak256 dei suoi byte UTF-8: un'implementazione "
         "che normalizza, tronca o ri-codifica produce un domainSeparator diverso e fallisce qui."]))

    # indirizzo zero come destinatario: firma valida, destinatario che brucia i fondi
    m_zero = dict(base_msg, to="0x0000000000000000000000000000000000000000")
    out.append(vettore(
        "018-recipient-zero-address", "generated", "EIP-3009 TransferWithAuthorization",
        DOM_USDC, TIPI_3009, "TransferWithAuthorization", m_zero,
        firma(digest(DOM_USDC, TIPI_3009, "TransferWithAuthorization", m_zero)), "accept", addr,
        ["Destinatario = indirizzo zero. La firma e' valida: il verdetto crittografico e' accept.",
         "Serve a distinguere il livello: chi rifiuta questo vettore sta applicando policy, non "
         "verifica di firma, e deve dirlo con un errore diverso."]))
    return out


if __name__ == "__main__":
    sys.exit(main())
