#!/usr/bin/env python3
"""Vettori 056-076: codifica STRETTA dei valori JSON (regola in lib/eip712.py, 25/09/2026).

Perche' esistono: un fuzz di input malformati (25/09/2026) ha misurato `accept` su messaggi il cui JSON
MOSTRATO non e' il messaggio FIRMATO. La libreria normalizzava: int(10000.9) = 10000, int("١٠٠٠٠") =
10000, bytes.fromhex saltava gli spazi, "XX"+hex passava per un indirizzo, bool("false") = true, la
stringa "123" dichiarata uint256[] diventava l'array [1, 2, 3].

Costruzione di ogni reject 056-075: la firma e' quella VERA della chiave di test sul messaggio che un
parser permissivo ricava dal JSON (argomento `msg_firmato` di `rej`). Quindi un verificatore che normalizza
recupera il firmatario dichiarato e ACCETTA; uno che applica la codifica stretta rifiuta con
`encoding_error`. Il 076 e' il controllo nell'altro senso: la stringa decimale canonica e' ammessa, e
un verificatore troppo stretto la rifiuterebbe.
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))
sys.path.insert(0, os.path.join(BASE, "tools"))

from eip712 import keccak256, hash_struct, type_hash, encode_value          # noqa: E402
from reject_reasons import annota                                           # noqa: E402
from genera_vettori import CAMPI_DOMINIO, DOM_USDC, TIPI_3009, firma        # noqa: E402
from genera_vettori_50 import ADDR, MSG3009, costruisci, firma_su           # noqa: E402

T3 = "TransferWithAuthorization"
STD = "EIP-712 encoding — strict JSON value forms"
NOTA_COSTRUZIONE = ("Firma VERA della chiave di test sul messaggio che un parser permissivo ricava da "
                    "questo JSON: un verificatore che normalizza il valore recupera il firmatario "
                    "dichiarato e ACCETTA. Il JSON mostrato non e' il messaggio firmato: e' un "
                    "differenziale di parsing, e la sola risposta sicura e' encoding_error.")


def digest_manuale(tipi, primary, parti_codificate):
    """hashStruct scritto a mano per i casi che la lib stretta si rifiuta di codificare."""
    ds = hash_struct("EIP712Domain", {"EIP712Domain": CAMPI_DOMINIO}, DOM_USDC)
    hs = keccak256(type_hash(primary, tipi) + b"".join(parti_codificate))
    return keccak256(b"\x19\x01" + ds + hs)


def tutti():
    v = []

    def rej(vid, perche, dom_mostrato, dom_firmato, tipi, primary, msg_mostrato, msg_firmato, sig=None):
        sg = sig or firma_su(dom_firmato, tipi, primary, msg_firmato)
        v.append(costruisci(vid, "generated", STD, dom_mostrato, tipi, primary, msg_mostrato, sg,
                            "reject", None, [perche, NOTA_COSTRUZIONE]))

    def msg(**kw):
        return dict(MSG3009, **kw)

    f, to, nonce = MSG3009["from"], MSG3009["to"], MSG3009["nonce"]
    D = DOM_USDC

    # ── uintN: solo intero JSON o stringa decimale ASCII canonica ─────────────────────
    rej("056-uint-float-fraction",
        "`value` = 10000.9 (numero JSON con parte frazionaria) per un uint256; int() lo tronca a 10000.",
        D, D, TIPI_3009, T3, msg(value=10000.9), MSG3009)
    rej("057-uint-float-timestamp",
        "`validAfter` = 1740672089.99 per un uint256: troncato, la finestra firmata non e' quella mostrata.",
        D, D, TIPI_3009, T3, msg(validAfter=1740672089.99), MSG3009)
    rej("058-domain-chainid-float",
        "`domain.chainId` = 84532.5: troncato a 84532, il dominio mostrato non e' una catena.",
        dict(D, chainId=84532.5), D, TIPI_3009, T3, MSG3009, MSG3009)
    rej("059-uint-string-unicode-digits",
        "`value` = \"١٠٠٠٠\" (cifre arabo-indiche U+0660..U+0669): Python int() le legge come 10000.",
        D, D, TIPI_3009, T3, msg(value="١٠٠٠٠"), MSG3009)
    rej("060-uint-string-whitespace",
        "`value` = \" 10000\\n\": int() scarta gli spazi; la forma canonica non ne ha.",
        D, D, TIPI_3009, T3, msg(value=" 10000\n"), MSG3009)
    rej("061-uint-string-underscore",
        "`value` = \"10_000\": int() accetta il separatore di Python; un altro parser no.",
        D, D, TIPI_3009, T3, msg(value="10_000"), MSG3009)
    rej("062-uint-string-plus-sign",
        "`value` = \"+10000\": il segno esplicito non fa parte della forma canonica di un uint.",
        D, D, TIPI_3009, T3, msg(value="+10000"), MSG3009)
    rej("063-uint-string-leading-zero",
        "`value` = \"010000\": con zeri iniziali; strtol(s, NULL, 0) in C lo legge in ottale (0o10000 = 4096).",
        D, D, TIPI_3009, T3, msg(value="010000"), MSG3009)
    rej("064-uint-bool",
        "`value` = true per un uint256: in Python bool e' un int, int(True) = 1. Firmato: value = 1.",
        D, D, TIPI_3009, T3, msg(value=True), msg(value=1))

    # ── address / bytes32 / bytes: regex esatte, niente spazi ───────────────────────────
    rej("065-address-bad-prefix",
        "`from` = \"XX\" + 40 hex: il prefisso non veniva controllato (str(v)[2:]).",
        D, D, TIPI_3009, T3, msg(**{"from": "XX" + f[2:]}), MSG3009)
    rej("066-address-trailing-whitespace",
        "`to` con \" \\n\" in coda: bytes.fromhex salta gli spazi ASCII.",
        D, D, TIPI_3009, T3, msg(to=to + " \n"), MSG3009)
    vc = D["verifyingContract"]
    rej("067-domain-verifying-contract-bad-prefix",
        "`domain.verifyingContract` = \"XX\" + 40 hex.",
        dict(D, verifyingContract="XX" + vc[2:]), D, TIPI_3009, T3, MSG3009, MSG3009)
    rej("068-bytes32-internal-whitespace",
        "`nonce` (bytes32) con spazi fra i gruppi di cifre: bytes.fromhex li salta.",
        D, D, TIPI_3009, T3,
        msg(nonce="0x" + " ".join(nonce[2 + i:10 + i] for i in range(0, 64, 8))), MSG3009)
    rej("069-bytes32-bad-prefix",
        "`nonce` = \"::\" + 64 hex: il prefisso 0x non veniva controllato.",
        D, D, TIPI_3009, T3, msg(nonce="::" + nonce[2:]), MSG3009)
    tipi_nota = {"Nota": [{"name": "memo", "type": "bytes"}]}
    rej("070-bytes-internal-whitespace",
        "`memo` (bytes dinamico) = \"0xdead beef\": bytes.fromhex salta lo spazio.",
        D, D, tipi_nota, "Nota", {"memo": "0xdead beef"}, {"memo": "0xdeadbeef"})

    # ── string / bool: il tipo JSON deve essere quello ─────────────────────────────────
    rej("071-domain-version-integer",
        "`domain.version` = 2 (intero JSON) dove il tipo e' string: str(2) = \"2\".",
        dict(D, version=2), D, TIPI_3009, T3, MSG3009, MSG3009)
    tipi_flag = {"Flag": [{"name": "attivo", "type": "bool"}]}
    rej("072-bool-as-string-false",
        "`attivo` = \"false\" (stringa) per un bool: bool(\"false\") = true. Mostra false, firma true.",
        D, D, tipi_flag, "Flag", {"attivo": "false"}, {"attivo": True})

    # ── array: deve essere un array JSON, della lunghezza dichiarata ───────────────────
    tipi_lotto = {"Lotto": [{"name": "quantita", "type": "uint256[]"}]}
    rej("073-array-given-as-string",
        "`quantita` (uint256[]) = \"123\": iterare una stringa da' i caratteri, firmato [1, 2, 3].",
        D, D, tipi_lotto, "Lotto", {"quantita": "123"}, {"quantita": [1, 2, 3]})
    tipi_coppia = {"Coppia": [{"name": "v", "type": "uint256[2]"}]}
    d74 = digest_manuale(tipi_coppia, "Coppia", [encode_value("uint256[]", [1, 2, 3])])
    rej("074-array-fixed-length-mismatch",
        "`v` dichiarato uint256[2] con 3 elementi: la lunghezza del tipo non veniva controllata.",
        D, D, tipi_coppia, "Coppia", {"v": [1, 2, 3]}, None, sig=firma(d74))

    # ── larghezze intere fuori da EIP-712 ──────────────────────────────────────────────
    tipi_u7 = {"Piccolo": [{"name": "x", "type": "uint7"}]}
    d75 = digest_manuale(tipi_u7, "Piccolo", [(5).to_bytes(32, "big")])
    rej("075-uint-width-not-multiple-of-8",
        "Tipo `uint7`: EIP-712 ammette uint8..uint256 a passi di 8. Il nome veniva tagliato con "
        "int(tipo[4:]) e codificato comunque.",
        D, D, tipi_u7, "Piccolo", {"x": 5}, None, sig=firma(d75))

    # ── controllo nell'altro senso: la forma decimale canonica in stringa e' AMMESSA ──
    m_str = msg(value="10000")
    sg = firma_su(D, TIPI_3009, T3, MSG3009)
    v.append(costruisci("076-uint-decimal-string-accepted", "generated", STD, D, TIPI_3009, T3, m_str,
                        sg, "accept", ADDR,
                        ["`value` = \"10000\": stringa decimale ASCII canonica, la forma in cui il "
                         "payload x402 trasporta gli importi. E' AMMESSA e vale 10000: firma e digest "
                         "coincidono con il 003.",
                         "Controllo nell'altro senso per 056-075: un verificatore troppo stretto, che "
                         "accetta solo interi JSON, rifiuta qui una firma valida."]))
    return v


def main():
    v = tutti()
    vdir = os.path.join(BASE, "vectors")
    for vec in v:
        with open(os.path.join(vdir, vec["id"] + ".json"), "w") as fh:
            json.dump(annota(vec), fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    print(f"vettori 056-076 scritti: {len(v)}")
    for vec in v:
        print(f"  {vec['id']:42s} {vec['expected']['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
