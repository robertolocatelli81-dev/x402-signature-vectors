"""TEST 3 — anti-panic: input malevoli non devono far esplodere il verificatore.

L'input di un verificatore x402 arriva dalla rete. Una libreria che solleva un'eccezione non gestita
invece di rifiutare e' un denial of service: basta un payload storto per fermare il facilitatore.
"""
import json, os, random, string, sys, traceback
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "lib"))
import verify as V

base = json.load(open(os.path.join(BASE, "vectors", "003-eip3009-generated-valid.json")))
random.seed(20260911)

def storpia(v, n):
    v = json.loads(json.dumps(v))
    e = v["eip712"]
    scelta = n % 12
    if scelta == 0:   v["signature"] = "0x" + "".join(random.choice("0123456789abcdef") for _ in range(random.randint(0, 200)))
    elif scelta == 1: v["signature"] = "non-esadecimale"
    elif scelta == 2: e["message"] = {}
    elif scelta == 3: e["types"] = {}
    elif scelta == 4: e["domain"] = {}
    elif scelta == 5: e["primaryType"] = "".join(random.choice(string.ascii_letters) for _ in range(8))
    elif scelta == 6: e["message"]["value"] = "non-un-numero"
    elif scelta == 7: e["message"]["from"] = "0xNONVALIDO"
    elif scelta == 8: e["types"]["TransferWithAuthorization"] = [{"name": "x", "type": "tipo_inesistente"}]
    elif scelta == 9: e["message"]["value"] = 10**100
    elif scelta == 10: e["domain"]["chainId"] = "stringa-invece-di-intero"
    else:             e["types"]["TransferWithAuthorization"] = [{"name": "a", "type": "A"}]; e["types"]["A"] = [{"name": "b", "type": "A"}]  # ricorsione
    return v

panici, rifiuti, accettati = [], 0, 0
for i in range(600):
    v = storpia(base, i)
    try:
        esito, _, _, _ = V.verdetto(v)
        if esito == "reject": rifiuti += 1
        else: accettati += 1
    except RecursionError:
        panici.append((i, "RecursionError"))
    except Exception as ex:
        panici.append((i, f"{type(ex).__name__}: {str(ex)[:60]}"))

print(f"  600 input malevoli -> {rifiuti} rifiutati, {accettati} accettati, {len(panici)} ECCEZIONI NON GESTITE")
for i, p in panici[:6]:
    print(f"      caso {i}: {p}")

# ── Input radice che NON e' un oggetto JSON (fuzz 25/09/2026): prima vec.get() sollevava
# AttributeError, finiva nel ramo della firma e il rifiuto usciva come `signature_malformed`.
# Verdetto giusto, ragione sbagliata: qui si pretende la classe giusta.
radici_ko = []
for radice in [None, [], [base], "x", "", 5, 0, 1.5, True, False]:
    try:
        esito = V.verdetto(radice)
    except Exception as ex:                                  # noqa: BLE001
        esito = ("RAISE", None, type(ex).__name__, None)
    if esito[0] != "reject" or esito[2] != "input_not_object":
        radici_ko.append(f"{radice!r:.30}: {esito[0]} / {esito[2]}")
print(f"  10 radici non-oggetto -> {10 - len(radici_ko)} con reject/input_not_object, {len(radici_ko)} sbagliate")
for r in radici_ko:
    print(f"      {r}")

# ── Forme STRETTE dei valori (lib/eip712.py). Tabella nei DUE sensi: le forme ammesse devono
# codificare, le altre sollevare. Copre anche forme che nessun vettore porta ("-0", "0x2710").
from eip712 import encode_value                                  # noqa: E402
AMMESSI = [("uint256", 0), ("uint256", "0"), ("uint256", "10000"), ("uint256", 2**256 - 1),
           ("uint256", str(2**256 - 1)), ("uint8", 255), ("int256", -1), ("int256", "-1"),
           ("int256", "0"), ("int256", -(2**255)), ("address", "0x" + "aB" * 20),
           ("bytes32", "0x" + "00" * 32), ("bytes", "0x"), ("bytes", "0xdeadbeef"), ("string", ""),
           ("string", "١٠"), ("bool", True), ("bool", False), ("uint256[]", []), ("uint256[2]", [1, 2])]
RIFIUTATI = [("uint256", 10000.0), ("uint256", 10000.9), ("uint256", True), ("uint256", None),
             ("uint256", "0x2710"), ("uint256", "010000"), ("uint256", "+1"), ("uint256", "-1"),
             ("uint256", " 1"), ("uint256", "1\n"), ("uint256", "1_0"), ("uint256", "١"), ("uint256", ""),
             ("uint256", "1e4"), ("uint256", "9" * 79), ("uint256", 2**256), ("int256", "-0"),
             ("int256", "--1"), ("uint8", 256), ("uint7", 1), ("uint08", 1), ("uint264", 1),
             ("uint", 1), ("address", "0x" + "ab" * 19), ("address", "0x" + "ab" * 20 + "\n"),
             ("address", "0X" + "ab" * 20), ("address", "0x" + "gg" * 20), ("address", 1),
             ("bytes32", "0x" + "00" * 31), ("bytes32", "0x" + "00" * 33), ("bytes32", "0x" + "0" * 63),
             ("bytes", "0xabc"), ("bytes", "0xab cd"), ("bytes", "abcd"), ("bytes", None),
             ("string", 2), ("string", None), ("bool", "false"), ("bool", 1), ("bool", None),
             ("uint256[]", "123"), ("uint256[]", {"0": 1}), ("uint256[2]", [1, 2, 3]),
             ("uint256[02]", [1, 2])]
forme_ko = []
for tipo, val in AMMESSI:
    try:
        encode_value(tipo, val, {})
    except Exception as ex:                                  # noqa: BLE001
        forme_ko.append(f"AMMESSO rifiutato: {tipo} {val!r:.40} ({type(ex).__name__})")
for tipo, val in RIFIUTATI:
    try:
        encode_value(tipo, val, {})
        forme_ko.append(f"NON AMMESSO codificato: {tipo} {val!r:.40}")
    except Exception:                                        # noqa: BLE001
        pass
print(f"  forme strette: {len(AMMESSI)} ammesse + {len(RIFIUTATI)} non ammesse -> {len(forme_ko)} sbagliate")
for r in forme_ko:
    print(f"      {r}")

# ── Letture e nomi (13/11/2026, nessun gate li esercitava): le costanti non JSON di SPEC.md §3.1 sono
# json_ambiguous ovunque nel testo, anche in un membro che EIP-712 ignora; una struct chiamata come uno dei tipi
# atomici e' encoding_error per ogni nome atomico, non solo per `address` (vettore 081).
_v3 = json.load(open(os.path.join(BASE, "vectors", "003-eip3009-generated-valid.json"), encoding="utf-8"))
letture_ko = []
for costante in ("NaN", "Infinity", "-Infinity"):
    for testo in (json.dumps(_v3).replace('"value": 10000', '"value": ' + costante, 1),
                  json.dumps(_v3).replace('"validAfter": ', '"x_ignorato": ' + costante + ', "validAfter": ', 1)):
        assert costante in testo
        esito = V.verdetto_da_testo(testo)
        if esito[0] != "reject" or esito[2] != "json_ambiguous":
            letture_ko.append(f"{costante}: {esito[0]}/{esito[2]}")
ATOMICI = ("address", "bool", "string", "bytes", "bytes32", "bytes1", "uint256", "uint8", "int256", "int8")
for nome in ATOMICI:
    v = json.loads(json.dumps(_v3))
    v["eip712"]["types"][nome] = [{"name": "a", "type": "uint256"}]
    esito = V.verdetto_da_testo(json.dumps(v))
    if esito[0] != "reject" or esito[2] != "encoding_error":
        letture_ko.append(f"struct {nome!r}: {esito[0]}/{esito[2]}")
print(f"  letture e nomi: {6 + len(ATOMICI)} casi (NaN/Infinity/-Infinity in due posti, {len(ATOMICI)} struct dal nome "
      f"atomico) -> {len(letture_ko)} sbagliati")
for r in letture_ko:
    print(f"      {r}")

# ── Annidamento profondo (20/11/2026): fino alla 1.5.0 verdetto_da_testo("[" * 1000 + "]" * 1000) sollevava
# RecursionError invece di rifiutare, e verdetto() su un oggetto gia' letto con un `signer` annidato in profondita'
# pure (str()). Un valore annidato al posto di OGNI nodo del vettore 003, radice compresa, letto come testo e come
# oggetto: nessuna eccezione, e il testo che il lettore di QUESTO interprete non segue (json.loads solleva
# RecursionError: da 1000 livelli su 3.9/3.11, da 20000 su 3.12/3.13, da 100000 su 3.14, misurato 20/11/2026) e'
# reject/input_not_object (SPEC.md §3.1).
def _percorsi(o, p=()):
    yield p
    for k, v in (o.items() if isinstance(o, dict) else enumerate(o) if isinstance(o, list) else ()):
        yield from _percorsi(v, p + (k,))


def _metti(radice, p, valore):
    if not p:
        return valore
    o = radice
    for k in p[:-1]:
        o = o[k]
    o[p[-1]] = valore
    return radice


def _leggibile(testo):
    try:
        json.loads(testo)
        return True
    except RecursionError:
        return False


annidati_ko, annidati_n, illeggibili = [], 0, 0
_SEGNA = "__ANNIDATO__"
for p in list(_percorsi(_v3)):
    for n in (50, 5000, 200000):
        for forma in ("lista", "oggetto"):
            testo_prof = ("[" * n + "]" * n) if forma == "lista" else ('{"a":' * n + "1" + "}" * n)
            obj_prof = 1
            for _ in range(n):
                obj_prof = [obj_prof] if forma == "lista" else {"a": obj_prof}
            testo = json.dumps(_metti(json.loads(json.dumps(_v3)), p, _SEGNA)).replace(json.dumps(_SEGNA), testo_prof, 1)
            illeggibili += not _leggibile(testo)
            for modo in ("testo", "oggetto"):
                annidati_n += 1
                try:
                    if modo == "testo":
                        esito = V.verdetto_da_testo(testo)
                    else:
                        esito = V.verdetto(_metti(json.loads(json.dumps(_v3)), p, obj_prof))
                except BaseException as ex:                  # noqa: BLE001
                    annidati_ko.append(f"/{'/'.join(map(str, p))} {n} {forma} {modo}: {type(ex).__name__}")
                    continue
                if esito[0] not in ("accept", "reject"):
                    annidati_ko.append(f"/{'/'.join(map(str, p))} {n} {forma} {modo}: {esito[0]!r}")
                elif p == ("signer",) and esito[0] != "reject":     # SPEC.md §1 /signer: a string; a list is no signer
                    annidati_ko.append(f"/signer {n} {forma} {modo}: {esito[0]}")
                elif modo == "testo" and not _leggibile(testo) and esito[:3:2] != ("reject", "input_not_object"):
                    annidati_ko.append(f"/{'/'.join(map(str, p))} {n} {forma} testo: {esito[0]}/{esito[2]} (atteso reject/input_not_object)")
print(f"  annidamento: {annidati_n} casi ({len(list(_percorsi(_v3)))} nodi x 3 profondita' x 2 forme x testo/oggetto) "
      f"({illeggibili} testi oltre il limite del lettore di questo interprete) -> {len(annidati_ko)} sbagliati")
if not illeggibili:
    annidati_ko.append("nessun testo oltre il limite del lettore: il caso RecursionError non e' stato esercitato")
for r in annidati_ko[:8]:
    print(f"      {r}")

falliti = bool(panici or radici_ko or forme_ko or letture_ko or annidati_ko)
print("  ESITO:", "nessun panic, classi e forme corrette" if not falliti else "DA CORREGGERE")
sys.exit(0 if not falliti else 1)
