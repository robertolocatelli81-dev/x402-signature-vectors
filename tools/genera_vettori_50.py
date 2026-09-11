#!/usr/bin/env python3
"""Vettori 023-050: confini ECDSA, dominio, encoding EIP-712, i due metodi x402 non ancora coperti,
robustezza. Portano la suite a 50.

Ogni caso qui corrisponde a un modo documentato in cui una implementazione sbaglia — non a
riempimento per arrivare a un numero.
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))
sys.path.insert(0, os.path.join(BASE, "tools"))

from eip712 import keccak256, hash_struct, type_hash          # noqa: E402
import secp256k1 as S
from reject_reasons import annota  # noqa: E402
from genera_vettori import (CHIAVE_TEST, K_DETERMINISTICO, CAMPI_DOMINIO, ASSET, DOM_USDC,  # noqa: E402
                            TIPI_3009, indirizzo_test, firma, digest)

ADDR = indirizzo_test()
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
# Firma sintatticamente ineccepibile (65 byte, v=27, r/s nel range, low-s): serve ai vettori in cui
# il rifiuto DEVE venire dall'encoding e non dalla forma della firma. Senza, il test passerebbe per
# il motivo sbagliato — e un test che passa per il motivo sbagliato non e' un test.
FIRMA_BEN_FORMATA = "0x" + "11" * 32 + "22" * 32 + "1b"
MSG3009 = {"from": ADDR, "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "value": 10000,
           "validAfter": 1740672089, "validBefore": 1740672154,
           "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"}


def costruisci(vid, origine, standard, dominio, tipi, primary, messaggio, sig, verdetto, atteso,
               note, signer=None, campi_dom=None):
    cd = campi_dom or CAMPI_DOMINIO
    try:
        ds = hash_struct("EIP712Domain", {"EIP712Domain": cd}, dominio)
        hs = hash_struct(primary, tipi, messaggio)
        th = "0x" + type_hash(primary, tipi).hex()
        exp = {"verdict": verdetto, "recovered_address": atteso, "type_hash": th,
               "domain_separator": "0x" + ds.hex(), "hash_struct": "0x" + hs.hex(),
               "signing_digest": "0x" + keccak256(b"\x19\x01" + ds + hs).hex()}
    except Exception:                                          # noqa: BLE001
        # Encoding non calcolabile (messaggio incompleto, tipo assente): e' il verdetto stesso.
        exp = {"verdict": verdetto, "recovered_address": None, "type_hash": None,
               "domain_separator": None, "hash_struct": None, "signing_digest": None}
    return {"id": vid, "origin": origine, "standard": standard, "signer": signer or ADDR,
            "eip712": {"domain": dominio, "types": tipi, "primaryType": primary, "message": messaggio},
            "signature": sig, "expected": exp, "notes": note}


def rec_o_none(sig, dominio, tipi, primary, messaggio, campi_dom=None):
    try:
        cd = campi_dom or CAMPI_DOMINIO
        ds = hash_struct("EIP712Domain", {"EIP712Domain": cd}, dominio)
        d = keccak256(b"\x19\x01" + ds + hash_struct(primary, tipi, messaggio))
        raw = bytes.fromhex(sig[2:])
        if len(raw) != 65:
            return None
        pub = S.recover_public_key(d, int.from_bytes(raw[:32], "big"),
                                   int.from_bytes(raw[32:64], "big"), raw[64] - 27)
        return S.public_key_to_address(pub, keccak256)
    except Exception:                                          # noqa: BLE001
        return None


def firma_su(dominio, tipi, primary, messaggio, campi_dom=None):
    cd = campi_dom or CAMPI_DOMINIO
    ds = hash_struct("EIP712Domain", {"EIP712Domain": cd}, dominio)
    return firma(keccak256(b"\x19\x01" + ds + hash_struct(primary, tipi, messaggio)))


def tutti():
    v = []
    d3 = digest(DOM_USDC, TIPI_3009, "TransferWithAuthorization", MSG3009)
    sig_ok = firma(d3)
    r_ok = int(sig_ok[2:66], 16)
    s_ok = int(sig_ok[66:130], 16)
    v_ok = int(sig_ok[130:132], 16)
    T3 = ("EIP-3009 TransferWithAuthorization", DOM_USDC, TIPI_3009, "TransferWithAuthorization")

    # ── A. confini esatti di secp256k1 ────────────────────────────────────────────────
    meta = S.N // 2
    for vid, s_val, verdetto, perche in [
        ("023-s-exactly-half-n", meta, "reject",
         "s = N/2 esatto: e' il confine della regola low-s. EIP-2 ammette s <= N/2, ma questa firma "
         "non e' quella del messaggio: serve a fissare DOVE cade il confine, non a passarlo"),
        ("024-s-just-above-half-n", meta + 1, "reject",
         "s = N/2 + 1: il primo valore che EIP-2 rifiuta. Un'implementazione che usa '<' invece di "
         "'<=' (o viceversa) sbaglia esattamente qui e in nessun altro punto"),
        ("025-s-equals-one", 1, "reject", "s = 1: valore minimo del range, firma non del messaggio"),
        ("026-r-equals-one", None, "reject", "r = 1: valore minimo del range"),
        ("027-r-equals-n-minus-one", None, "reject",
         "r = N-1: il massimo valore ammesso dal range. Il recupero e' definito ma il punto non "
         "corrisponde al firmatario"),
    ]:
        if vid == "026-r-equals-one":
            sig = "0x" + (1).to_bytes(32, "big").hex() + s_ok.to_bytes(32, "big").hex() + bytes([v_ok]).hex()
        elif vid == "027-r-equals-n-minus-one":
            sig = "0x" + (S.N - 1).to_bytes(32, "big").hex() + s_ok.to_bytes(32, "big").hex() + bytes([v_ok]).hex()
        else:
            sig = "0x" + r_ok.to_bytes(32, "big").hex() + s_val.to_bytes(32, "big").hex() + bytes([v_ok]).hex()
        v.append(costruisci(vid, "generated", T3[0], T3[1], T3[2], T3[3], MSG3009, sig, verdetto,
                            rec_o_none(sig, T3[1], T3[2], T3[3], MSG3009), [perche + ".",
                            "Confine esatto: i bug di range vivono qui, non nei valori centrali."]))

    for vid, vbyte, perche in [
        ("028-v-raw-zero", "00", "v = 0 (recovery id grezzo, non 27): formato di libsecp256k1"),
        ("029-v-raw-one", "01", "v = 1 (recovery id grezzo, non 28)"),
    ]:
        sig = sig_ok[:-2] + vbyte
        v.append(costruisci(vid, "generated", T3[0], T3[1], T3[2], T3[3], MSG3009, sig, "reject",
                            rec_o_none(sig, T3[1], T3[2], T3[3], MSG3009),
                            [perche + ".",
                             "Ethereum trasmette v come 27/28. Accettare anche 0/1 senza dirlo rende "
                             "la stessa autorizzazione valida in due forme: da decidere esplicitamente, "
                             "non per caso."]))

    # ── B. dominio ───────────────────────────────────────────────────────────────────
    for vid, dom, perche in [
        ("030-domain-chainid-zero", dict(DOM_USDC, chainId=0), "chainId = 0"),
        ("031-domain-chainid-max", dict(DOM_USDC, chainId=2**256 - 1), "chainId al massimo di uint256"),
        ("032-domain-verifying-contract-zero",
         dict(DOM_USDC, verifyingContract="0x0000000000000000000000000000000000000000"),
         "verifyingContract = indirizzo zero"),
        ("033-domain-empty-name", dict(DOM_USDC, name=""), "name vuoto"),
        ("034-domain-empty-version", dict(DOM_USDC, version=""), "version vuota"),
    ]:
        sg = firma_su(dom, TIPI_3009, "TransferWithAuthorization", MSG3009)
        v.append(costruisci(vid, "generated", T3[0], dom, TIPI_3009, "TransferWithAuthorization",
                            MSG3009, sg, "accept", ADDR,
                            [f"Dominio ai confini: {perche}.",
                             "La firma e' valida: il domainSeparator cambia ma resta ben definito. "
                             "Un'implementazione che tratta il valore come assente invece che come "
                             "valore produce un separator diverso e fallisce."]))

    # dominio a 3 campi, senza version: e' il dominio reale del contratto Permit2
    campi3 = [c for c in CAMPI_DOMINIO if c["name"] != "version"]
    dom_p2 = {"name": "Permit2", "chainId": 84532, "verifyingContract": PERMIT2}
    sg = firma_su(dom_p2, TIPI_3009, "TransferWithAuthorization", MSG3009, campi3)
    v.append(costruisci("035-domain-without-version", "generated", T3[0], dom_p2, TIPI_3009,
                        "TransferWithAuthorization", MSG3009, sg, "accept", ADDR,
                        ["Dominio SENZA `version`: e' il dominio reale del contratto Permit2, che x402 "
                         "usa come spender canonico.",
                         "EIP-712 dichiara i campi del dominio opzionali e il typeHash si calcola su "
                         "quelli presenti: chi assume quattro campi fissi calcola un separator diverso.",
                         "Questo vettore ha costretto ad ammorbidire anche il nostro JSON Schema, che "
                         "rendeva `version` obbligatoria."], campi_dom=campi3))
    return v, campi3


def parte_due(v, campi3):
    T3 = ("EIP-3009 TransferWithAuthorization", DOM_USDC, TIPI_3009, "TransferWithAuthorization")

    # ── C. encoding EIP-712 ──────────────────────────────────────────────────────────
    tipi_arr = {"Lista": [{"name": "chi", "type": "address"}, {"name": "voci", "type": "Voce[]"}],
                "Voce": [{"name": "sku", "type": "string"}, {"name": "quantita", "type": "uint256"}]}
    for vid, voci, perche in [
        ("036-array-empty", [], "array VUOTO: keccak256 della stringa vuota, non un errore"),
        ("037-array-single", [{"sku": "solo", "quantita": 1}], "array con un solo elemento"),
    ]:
        m = {"chi": ADDR, "voci": voci}
        sg = firma_su(DOM_USDC, tipi_arr, "Lista", m)
        v.append(costruisci(vid, "generated", "EIP-712 encoding (array)", DOM_USDC, tipi_arr, "Lista",
                            m, sg, "accept", ADDR,
                            [f"{perche}.",
                             "Un array vuoto produce keccak256(b''): le implementazioni che sollevano "
                             "o saltano il campo calcolano un hashStruct diverso."]))

    tipi_misti = {"Misto": [{"name": "chi", "type": "address"}, {"name": "attivo", "type": "bool"},
                            {"name": "piccolo", "type": "uint8"}, {"name": "segno", "type": "int256"},
                            {"name": "parola", "type": "bytes32"}]}
    for vid, m, perche in [
        ("038-types-bool-true", {"chi": ADDR, "attivo": True, "piccolo": 255, "segno": 1,
                                 "parola": "0x" + "ff" * 32}, "bool true, uint8 max, bytes32 tutto FF"),
        ("039-types-bool-false", {"chi": ADDR, "attivo": False, "piccolo": 0, "segno": 0,
                                  "parola": "0x" + "00" * 32}, "bool false, uint8 zero, bytes32 zero"),
    ]:
        sg = firma_su(DOM_USDC, tipi_misti, "Misto", m)
        v.append(costruisci(vid, "generated", "EIP-712 encoding (tipi atomici)", DOM_USDC, tipi_misti,
                            "Misto", m, sg, "accept", ADDR,
                            [f"Tipi atomici ai valori limite: {perche}.",
                             "Ogni valore atomico occupa 32 byte con padding a SINISTRA: un bool false "
                             "e' 32 byte di zeri, non un campo assente."]))

    # address con checksum misto: l'encoding non deve dipendere dal case
    m_low = dict(MSG3009, to="0x209693bc6afc0c5328ba36faf03c514ef312287c")
    sg = firma_su(DOM_USDC, TIPI_3009, "TransferWithAuthorization", m_low)
    v.append(costruisci("040-address-lowercase-vs-checksum", "generated", T3[0], DOM_USDC, TIPI_3009,
                        "TransferWithAuthorization", m_low, sg, "accept", ADDR,
                        ["Stesso indirizzo del vettore 003 ma tutto minuscolo (senza checksum EIP-55).",
                         "L'encoding di un address usa i 20 byte: il case e' una convenzione di "
                         "visualizzazione. Chi hasha la STRINGA invece dei byte ottiene un hashStruct "
                         "diverso fra questo vettore e il 003 — ed e' un errore che passa inosservato "
                         "finche' qualcuno non manda l'indirizzo in minuscolo."]))

    # ── D. i metodi x402 non ancora coperti ──────────────────────────────────────────
    tipi_p2 = {"PermitWitnessTransferFrom": [
                   {"name": "permitted", "type": "TokenPermissions"},
                   {"name": "spender", "type": "address"}, {"name": "nonce", "type": "uint256"},
                   {"name": "deadline", "type": "uint256"}, {"name": "witness", "type": "Witness"}],
               "TokenPermissions": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}],
               "Witness": [{"name": "to", "type": "address"}, {"name": "validAfter", "type": "uint256"}]}
    dom_p2 = {"name": "Permit2", "chainId": 84532, "verifyingContract": PERMIT2}
    m_p2 = {"permitted": {"token": ASSET, "amount": 10000},
            "spender": "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
            "nonce": 33247007178036348590600198031289925668252061821958005840077069883511451257277,
            "deadline": 1740672154,
            "witness": {"to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "validAfter": 1740672089}}
    sg = firma_su(dom_p2, tipi_p2, "PermitWitnessTransferFrom", m_p2, campi3)
    v.append(costruisci("041-permit2-witness-transfer", "generated",
                        "Permit2 PermitWitnessTransferFrom (x402 assetTransferMethod=permit2)",
                        dom_p2, tipi_p2, "PermitWitnessTransferFrom", m_p2, sg, "accept", ADDR,
                        ["Il secondo metodo di trasferimento di x402, finora scoperto dalla suite.",
                         "I tipi sono quelli della spec: WITNESS_TYPE_STRING dichiara "
                         "Witness(address to,uint256 validAfter) e TokenPermissions(address token,uint256 amount).",
                         "Il dominio e' quello del contratto Permit2 canonico e NON ha version: "
                         "chi riusa il dominio del token qui calcola un separator sbagliato."],
                        campi_dom=campi3))

    # witness alterato: la firma non deve piu' valere
    m_p2_alt = json.loads(json.dumps(m_p2))
    m_p2_alt["witness"]["to"] = "0x0000000000000000000000000000000000000001"
    v.append(costruisci("042-permit2-witness-tampered", "generated",
                        "Permit2 PermitWitnessTransferFrom", dom_p2, tipi_p2,
                        "PermitWitnessTransferFrom", m_p2_alt, sg, "reject",
                        rec_o_none(sg, dom_p2, tipi_p2, "PermitWitnessTransferFrom", m_p2_alt, campi3),
                        ["Stessa firma del 041 con il destinatario del witness sostituito.",
                         "E' l'attacco che il pattern witness esiste per impedire: se un verificatore "
                         "accetta questo vettore, il facilitatore puo' dirottare il pagamento."],
                        campi_dom=campi3))

    for vid, nonce, perche in [
        ("043-nonce-all-zero", "0x" + "00" * 32, "nonce tutto a zero"),
        ("044-nonce-all-ff", "0x" + "ff" * 32, "nonce tutto a FF"),
    ]:
        m = dict(MSG3009, nonce=nonce)
        sg2 = firma_su(DOM_USDC, TIPI_3009, "TransferWithAuthorization", m)
        v.append(costruisci(vid, "generated", T3[0], DOM_USDC, TIPI_3009, "TransferWithAuthorization",
                            m, sg2, "accept", ADDR,
                            [f"Confine del nonce EIP-3009: {perche}.",
                             "Il nonce e' un bytes32 opaco: nessun valore e' speciale per la firma. "
                             "Rifiutarlo e' policy anti-replay, non verifica."]))

    m_eq = dict(MSG3009, validAfter=1740672154, validBefore=1740672154)
    sg3 = firma_su(DOM_USDC, TIPI_3009, "TransferWithAuthorization", m_eq)
    v.append(costruisci("045-validity-window-degenerate", "generated", T3[0], DOM_USDC, TIPI_3009,
                        "TransferWithAuthorization", m_eq, sg3, "accept", ADDR,
                        ["validAfter == validBefore: finestra di validita' istantanea.",
                         "Firma valida. Come il 012, marca il confine fra crittografia e policy."]))

    # ── E. robustezza: input malformati non devono far esplodere il verificatore ─────
    for vid, sig, perche in [
        ("046-signature-too-short", "0x" + "ab" * 64, "64 byte invece di 65"),
        ("047-signature-too-long", "0x" + "ab" * 66, "66 byte invece di 65"),
        ("048-signature-empty", "0x", "firma vuota"),
    ]:
        v.append(costruisci(vid, "generated", T3[0], DOM_USDC, TIPI_3009, "TransferWithAuthorization",
                            MSG3009, sig, "reject", None,
                            [f"Firma malformata: {perche}.",
                             "Il verificatore deve rifiutare in modo pulito. Una libreria che qui "
                             "solleva un'eccezione non gestita e' un denial of service: l'input arriva "
                             "da rete e non e' fidato."]))

    tipi_mancante = {"TransferWithAuthorization": TIPI_3009["TransferWithAuthorization"]}
    m_incompleto = {k: val for k, val in MSG3009.items() if k != "nonce"}
    v.append(costruisci("049-message-missing-field", "generated", T3[0], DOM_USDC, tipi_mancante,
                        "TransferWithAuthorization", m_incompleto, FIRMA_BEN_FORMATA, "reject", None,
                        ["Al messaggio manca un campo dichiarato nel tipo (`nonce`).",
                         "La member list EIP-712 e' FISSA: un campo assente non e' un'omissione, e' un "
                         "messaggio che non si puo' codificare. L'encoding deve fallire prima della "
                         "firma, e i digest attesi sono null."]))

    v.append(costruisci("050-primary-type-not-in-types", "generated", T3[0], DOM_USDC, TIPI_3009,
                        "Inesistente", MSG3009, FIRMA_BEN_FORMATA, "reject", None,
                        ["`primaryType` non presente in `types`.",
                         "Caso degenere che un consumatore di vettori puo' ricevere da un peer "
                         "malevolo: il fallimento deve essere un rifiuto, non un KeyError."]))

    # ── F. recupero al punto all'infinito ────────────────────────────────────────────
    # Q = r^-1 (sR - eG). Se sR == eG allora Q = ∞, che NON e' una chiave pubblica. Si costruisce a
    # tavolino senza conoscere alcuna chiave privata: R = kG, r = R.x, s = e * k^-1 (mod N), con k
    # cercato dal basso finche' s e' low-s, cosi' la firma supera OGNI controllo di forma e il rifiuto
    # puo' venire SOLO dal recupero. libsecp256k1 fallisce ("failed to recover ECDSA public key").
    # Il `signer` dichiarato e' l'indirizzo che un'implementazione DIFETTOSA produrrebbe dal punto ∞:
    # se il verificatore lo confronta e trova uguale, ACCETTA una firma senza firmatario.
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, DOM_USDC)
    digest_inf = keccak256(b"\x19\x01" + ds + hash_struct("TransferWithAuthorization", TIPI_3009, MSG3009))
    e_inf = int.from_bytes(digest_inf, "big") % S.N
    k = 1
    while True:
        R = S._mul(k, (S.GX, S.GY))
        r_inf = R[0] % S.N
        if R[0] < S.N and r_inf:
            s_inf = e_inf * S._inv(k, S.N) % S.N
            if 1 <= s_inf <= S.N // 2:
                break
        k += 1
    sig_inf = ("0x" + r_inf.to_bytes(32, "big").hex() + s_inf.to_bytes(32, "big").hex()
               + bytes([(R[1] & 1) + 27]).hex())
    assert S._mul(s_inf, R) == S._mul(e_inf, (S.GX, S.GY)), "costruzione sbagliata: sR != eG"
    for vid, signer, perche in [
        ("051-recovery-point-at-infinity-address-zero",
         "0x0000000000000000000000000000000000000000",
         "`address(0)`: e' cio' che `ecrecover` restituisce in Solidity quando il recupero fallisce. "
         "Un verificatore off-chain che copia quel comportamento e poi confronta con il firmatario "
         "atteso accetta qualunque firma degenere purche' il firmatario dichiarato sia zero"),
        ("052-recovery-point-at-infinity-zero-point-address",
         "0x" + keccak256(b"\x00" * 64).hex()[-40:],
         "keccak256 di 64 byte zero: l'indirizzo che si ottiene se il codice rappresenta l'identita' "
         "con la tupla (0, 0) e la serializza come 64 byte. Attenzione: (0, 0) NON e' un punto della "
         "curva (0 != 7 mod p) e il punto all'infinito non ha coordinate affini — e' una convenzione "
         "software per l'elemento neutro, non una serializzazione matematica"),
    ]:
        v.append(costruisci(vid, "generated", T3[0], DOM_USDC, TIPI_3009, "TransferWithAuthorization",
                            MSG3009, sig_inf, "reject", None,
                            [f"Firma ben formata (65 byte, r e s nel range, low-s) costruita con "
                             f"R = {k}·G e s = e·k⁻¹, cosi' che s·R = e·G e il recupero dia il punto "
                             f"all'infinito. Nessuna chiave privata coinvolta.",
                             "Il punto all'infinito NON e' una chiave pubblica: il recupero deve "
                             "FALLIRE (libsecp256k1: 'failed to recover ECDSA public key'). "
                             "`recovered_address` e' null.",
                             f"Il `signer` dichiarato e' {perche}. Confrontare un indirizzo fabbricato "
                             "dal punto ∞ con il firmatario atteso e' il modo in cui questa firma senza "
                             "firmatario viene accettata."],
                            signer=signer))
    return v


def main():
    v, campi3 = tutti()
    v = parte_due(v, campi3)
    vdir = os.path.join(BASE, "vectors")
    for vec in v:
        with open(os.path.join(vdir, vec["id"] + ".json"), "w") as f:
            json.dump(annota(vec), f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(f"vettori 023-052 scritti: {len(v)}")
    for vec in v:
        print(f"  {vec['id']:38s} {vec['expected']['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
