#!/usr/bin/env python3
"""Vettori 077-081: una sola lettura del testo, del dominio e dei nomi dei tipi (25/09/2026).

Trovati dalla revisione a 4 menti (round 2) dopo la codifica stretta dei valori (056-076): il JSON mostrato
poteva ancora non essere il messaggio firmato. Ogni reject porta la firma VERA della chiave di test sul
messaggio che il runner PRECEDENTE ricavava da quel JSON, quindi il runner precedente ACCETTA:
  077 membro ripetuto `"value": 99999999999, "value": 10000` (json tiene l'ultimo, un altro lettore il primo);
  078 membro estraneo nel dominio (`chainID`), ignorato;
  079 `types.EIP712Domain` dichiarato senza `version` mentre il dominio lo porta: la dichiarazione era ignorata;
  080 `types.EIP712Domain` con `chainId` dichiarato `string`, codificato uint256;
  081 una struct chiamata `address` che oscura il tipo atomico.
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "lib"))
sys.path.insert(0, os.path.join(BASE, "tools"))

from reject_reasons import annota                                           # noqa: E402
from genera_vettori import CAMPI_DOMINIO, DOM_USDC, TIPI_3009               # noqa: E402
from genera_vettori_50 import MSG3009, costruisci, firma_su                 # noqa: E402

T3 = "TransferWithAuthorization"
STD = "EIP-712 encoding — one reading of the text, the domain and the type names"
NOTA = ("Firma VERA della chiave di test sul messaggio che il runner precedente ricavava da questo JSON: "
        "quel runner ACCETTA. Il JSON mostrato ammette un'altra lettura: la sola risposta sicura e' il rifiuto.")


def tutti():
    v = []
    D = DOM_USDC
    sg = firma_su(D, TIPI_3009, T3, MSG3009)
    # 077: il duplicato si scrive a mano nel testo (json.dump non puo' produrlo): qui il vettore porta il valore firmato
    v.append(costruisci("077-json-duplicate-member", "generated", STD, D, TIPI_3009, T3, dict(MSG3009), sg, "reject", None,
                        ["Il file ripete il membro `value`: 99999999999 e poi 10000. Il `json` di Python tiene l'ultimo "
                         "(10000, firmato), un lettore che tiene il primo vede 99999999999 sotto la stessa firma. RFC 8259 "
                         "§4: con nomi ripetuti il comportamento dei lettori e' imprevedibile.", NOTA,
                         "eth-account riceve un dict gia' letto: non vede il duplicato e accetterebbe."]))
    D78 = dict(D, chainID=1)
    v.append(costruisci("078-domain-unknown-member", "generated", STD, D78, TIPI_3009, T3, MSG3009, sg, "reject", None,
                        ["Il dominio porta `chainID` (maiuscola diversa) oltre a `chainId`: il membro estraneo veniva ignorato.",
                         NOTA, "eth-account 0.14.0 solleva `Invalid domain key`."]))
    t79 = dict(TIPI_3009, EIP712Domain=[c for c in CAMPI_DOMINIO if c["name"] != "version"])
    v.append(costruisci("079-domain-types-inconsistent", "generated", STD, D, t79, T3, MSG3009, sg, "reject", None,
                        ["`types.EIP712Domain` dichiara il dominio senza `version`, il dominio lo porta: la dichiarazione "
                         "veniva ignorata e il separatore calcolato sui campi presenti.", NOTA,
                         "eth-account 0.14.0 solleva ValidationError."]))
    t80 = dict(TIPI_3009, EIP712Domain=[dict(c, type="string") if c["name"] == "chainId" else c for c in CAMPI_DOMINIO])
    v.append(costruisci("080-domain-chainid-declared-string", "generated", STD, D, t80, T3, MSG3009, sg, "reject", None,
                        ["`types.EIP712Domain` dichiara `chainId` di tipo `string`; veniva codificato uint256 comunque.", NOTA]))
    t81 = {"Pay": [{"name": "to", "type": "address"}], "address": [{"name": "a", "type": "uint256"}]}
    m81 = {"to": {"a": 5}}
    v.append(costruisci("081-struct-named-like-atomic-type", "generated", STD, D, t81, "Pay", m81,
                        firma_su(D, t81, "Pay", m81), "reject", None,
                        ["Una struct si chiama `address`: il campo `to`, dichiarato address, veniva codificato come "
                         "quella struct. eth-account calcola un digest diverso.", NOTA]))
    return v


def main():
    vdir = os.path.join(BASE, "vectors")
    for vec in tutti():
        # Nessuna codifica UNICA esiste per questi messaggi (e' il motivo del rifiuto): i campi di encoding sono
        # null, come per 056-075, e le cross-validazioni li contano fra i non codificabili per costruzione.
        for k in ("type_hash", "domain_separator", "hash_struct", "signing_digest"):
            vec["expected"][k] = None
        testo = json.dumps(annota(vec), indent=2, ensure_ascii=False) + "\n"
        if vec["id"] == "077-json-duplicate-member":
            vecchio = '      "value": 10000,'
            assert testo.count(vecchio) == 1, "077: il membro value non si trova una sola volta"
            testo = testo.replace(vecchio, '      "value": 99999999999,\n      "value": 10000,')
        with open(os.path.join(vdir, vec["id"] + ".json"), "w") as fh:
            fh.write(testo)
        print(f"  {vec['id']:42s} {vec['expected']['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
