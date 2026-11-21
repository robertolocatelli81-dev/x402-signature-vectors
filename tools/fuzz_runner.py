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
    # la stessa struct RAGGIUNGIBILE da primaryType e firmata sulla lettura «struct» (come 081): sola regola dei nomi
    # (una struct non raggiungibile e' encoding_error anche per SPEC.md 1.3, e da sola non proverebbe questa regola)
    sys.path.insert(0, os.path.join(BASE, "tools"))
    from genera_vettori import DOM_USDC as _D, digest as _dg, firma as _fm, indirizzo_test as _it   # noqa: E402
    ti, vi = ("bool", True) if nome == "string" else ("string", "x")      # il membro interno non e' la struct stessa
    tp = {"Pay": [{"name": "to", "type": nome}], nome: [{"name": "a", "type": ti}]}
    vp = {"signer": _it(), "signature": _fm(_dg(_D, tp, "Pay", {"to": {"a": vi}})),
          "eip712": {"domain": _D, "types": tp, "primaryType": "Pay", "message": {"to": {"a": vi}}}}
    esito = V.verdetto_da_testo(json.dumps(vp))
    if esito[0] != "reject" or esito[2] != "encoding_error":
        letture_ko.append(f"struct {nome!r} raggiungibile: {esito[0]}/{esito[2]}")
print(f"  letture e nomi: {6 + 2 * len(ATOMICI)} casi (NaN/Infinity/-Infinity in due posti, {len(ATOMICI)} struct dal nome "
      f"atomico, non raggiungibili e raggiungibili firmate) -> {len(letture_ko)} sbagliati")
for r in letture_ko:
    print(f"      {r}")

# ── Annidamento profondo (20/11/2026): fino alla 1.5.0 verdetto_da_testo("[" * 1000 + "]" * 1000) sollevava
# RecursionError invece di rifiutare, e verdetto() su un oggetto gia' letto con un `signer` annidato in profondita'
# pure (str()). Un valore annidato al posto di OGNI nodo del vettore 003, radice compresa, letto come testo e come
# oggetto: nessuna eccezione, e il testo annidato oltre 64 livelli (SPEC.md §3.1, verify.PROFONDITA_MAX) e'
# reject/input_not_object su OGNI interprete: il limite del lettore cambia (json.loads solleva RecursionError: prima
# profondita' di liste rifiutata 993 su 3.9.25 e 3.11.2, 9998 su 3.12.15, 9999 su 3.13.15, 65197 su 3.14.8, misurato
# 20/11/2026), quello della suite no. Qui "oltre" e' noto per costruzione: 5000 e 200000 livelli lo sono, 50 no
# (i nodi del vettore stanno entro 5 livelli).
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
            oltre = n > 64
            illeggibili += oltre
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
                elif modo == "testo" and oltre and esito[:3:2] != ("reject", "input_not_object"):
                    annidati_ko.append(f"/{'/'.join(map(str, p))} {n} {forma} testo: {esito[0]}/{esito[2]} (atteso reject/input_not_object)")
print(f"  annidamento: {annidati_n} casi ({len(list(_percorsi(_v3)))} nodi x 3 profondita' x 2 forme x testo/oggetto) "
      f"({illeggibili} testi oltre 64 livelli) -> {len(annidati_ko)} sbagliati")
if not illeggibili:
    annidati_ko.append("nessun testo oltre 64 livelli: il caso non e' stato esercitato")
# Il confine, sul primo vettore con un membro in piu' che il verdetto ignora: 64 livelli in tutto si leggono (accept),
# 65 no; parentesi dentro una stringa (anche dopo \" e \\) non sono livelli; lo stesso testo in bytes; e la rete di
# sicurezza: un lettore che solleva RecursionError e' reject/input_not_object.
_t1 = open(os.path.join(BASE, "vectors", sorted(os.listdir(os.path.join(BASE, "vectors")))[0]), encoding="utf-8").read().rstrip()
_con = lambda valore: _t1[:-1] + ', "x_annidato": ' + valore + "}"                    # noqa: E731
_lista = lambda n: "[" * n + "]" * n                                                  # noqa: E731
_ogg = lambda n: '{"a":' * n + "1" + "}" * n                                          # noqa: E731
confine = [("controllo", _t1, "accept", None), ("lista 63 (64 in tutto)", _con(_lista(63)), "accept", None),
           ("lista 64 (65 in tutto)", _con(_lista(64)), "reject", "input_not_object"),
           ("oggetto 63", _con(_ogg(63)), "accept", None), ("oggetto 64", _con(_ogg(64)), "reject", "input_not_object"),
           ("misto 64", _con("[{\"a\":" * 32 + "1" + "}]" * 32), "reject", "input_not_object"),
           ("misto 62", _con("[{\"a\":" * 31 + "1" + "}]" * 31), "accept", None),
           ("parentesi in una stringa", _con(json.dumps("[" * 500 + "{" * 500)), "accept", None),
           ("stringa con \\\" e parentesi", _con(json.dumps('a"' + "[" * 500 + "\\" + '"' + "{" * 500)), "accept", None),
           ("chiave con parentesi", _t1[:-1] + ', ' + json.dumps("[" * 500) + ': 1}', "accept", None),
           ("200 fratelli, 2 livelli", _con("[" + ",".join(["[]", "{}"] * 100) + "]"), "accept", None),
           ("signer numero", json.dumps({**json.loads(_t1), "signer": 5}), "reject", "signer_mismatch"),
           ("signer lista", json.dumps({**json.loads(_t1), "signer": [json.loads(_t1)["signer"]]}), "reject", "signer_mismatch"),
           ("signer con spazio in coda", json.dumps({**json.loads(_t1), "signer": json.loads(_t1)["signer"] + " "}), "reject", "signer_mismatch"),
           ("65 livelli di sole aperte", "[" * 65, "reject", "input_not_object"),
           ("bytes, lista 64", _con(_lista(64)).encode("utf-8"), "reject", "input_not_object"),
           ("bytes utf-16, lista 64", _con(_lista(64)).encode("utf-16"), "reject", "input_not_object"),
           ("bytes, lista 63", _con(_lista(63)).encode("utf-8"), "accept", None)]
confine_ko = []
for nome, testo, v_att, c_att in confine:
    try:
        esito = V.verdetto_da_testo(testo)
    except BaseException as ex:                              # noqa: BLE001
        confine_ko.append(f"{nome}: {type(ex).__name__}"); continue
    if (esito[0], esito[2]) != (v_att, c_att):
        confine_ko.append(f"{nome}: {esito[0]}/{esito[2]} (atteso {v_att}/{c_att})")
    elif nome.startswith("signer ") and (esito[1] or "").lower() != json.loads(_t1)["signer"].lower():
        confine_ko.append(f"{nome}: indirizzo recuperato {esito[1]!r} (SPEC.md §1: un rifiuto per regola riporta l'indirizzo)")
_vero = V.leggi_json_stretto
def _solleva(testo):
    raise RecursionError("lettore finto")
V.leggi_json_stretto = _solleva
try:
    esito = V.verdetto_da_testo(_t1)
    if (esito[0], esito[2]) != ("reject", "input_not_object"):
        confine_ko.append(f"lettore che solleva RecursionError: {esito[0]}/{esito[2]}")
except BaseException as ex:                                  # noqa: BLE001
    confine_ko.append(f"lettore che solleva RecursionError: {type(ex).__name__}")
finally:
    V.leggi_json_stretto = _vero
print(f"  confine dei 64 livelli e `signer` non stringa: {len(confine) + 1} casi -> {len(confine_ko)} sbagliati")
for r in confine_ko:
    print(f"      {r}")
annidati_ko += confine_ko
for r in annidati_ko[:8]:
    print(f"      {r}")

# ── Struct non raggiungibili da primaryType (21/11/2026, SPEC.md 1.3 §1 /eip712/types): fino alla 1.5.0 una struct in
# piu' in `types` era accept (encodeType non la include, la firma non la copre). Generativo, nei due sensi: grafi di
# struct casuali (membri atomici, struct, T[] e T[k], cicli attraverso T[] vuoti, EIP712Domain dichiarato o no, ordine
# delle chiavi mescolato), messaggio costruito sui tipi e FIRMATO con la chiave di test. Tutte raggiungibili -> accept
# col firmatario; con struct in piu' (isolate, vuote, che contengono la primaria, in catena, ricorsive, con tipi ignoti,
# non liste, membri non oggetti) -> reject/encoding_error. L'oracolo e' un punto fisso sugli archi scritto qui, non
# lib/eip712.strutture_raggiungibili.
sys.path.insert(0, os.path.join(BASE, "tools"))
from genera_vettori import CAMPI_DOMINIO, DOM_USDC, digest as _digest, firma as _firma, indirizzo_test  # noqa: E402
from eip712 import ValoreNonConforme, signing_digest                    # noqa: E402
_rng = random.Random(20261121)
_FIRMATARIO = indirizzo_test()
_ATOMI = {"uint256": lambda: _rng.randrange(2 ** 256), "uint8": lambda: _rng.randrange(256),
          "int256": lambda: _rng.randrange(-2 ** 255, 2 ** 255), "address": lambda: "0x" + _rng.randbytes(20).hex(),
          "bool": lambda: _rng.random() < 0.5, "string": lambda: "s" * _rng.randrange(4),
          "bytes32": lambda: "0x" + _rng.randbytes(32).hex(), "bytes": lambda: "0x" + _rng.randbytes(_rng.randrange(4)).hex()}


def _oracolo_fuori(primary, types):
    """Struct diverse da EIP712Domain non raggiungibili da primary: punto fisso R = {primary} U basi dei tipi di R."""
    R = {primary}
    while True:
        basi = {c["type"].split("[")[0] for n in R if isinstance(types.get(n), list) for c in types[n]
                if isinstance(c, dict) and isinstance(c.get("type"), str)}
        nuovo = R | (basi & set(types))
        if nuovo == R:
            return sorted(n for n in types if n != "EIP712Domain" and n not in R)
        R = nuovo


def _grafo():
    k = _rng.randint(1, 5)
    nomi = [f"S{i}" for i in range(k)]
    types = {n: [] for n in nomi}
    for j in range(1, k):                                   # ogni S_j ha un genitore prima di lei: raggiungibile
        types[nomi[_rng.randrange(j)]].append({"name": f"r{j}", "type": nomi[j] + _rng.choice(["", "[]", "[2]"])})
    for i, n in enumerate(nomi):
        for m in range(_rng.randint(0 if types[n] else 1, 3)):
            types[n].append({"name": f"a{m}", "type": _rng.choice(list(_ATOMI)) + _rng.choice(["", "", "[]", "[1]"])})
        if _rng.random() < 0.3:                             # ciclo: verso una struct gia' vista, come T[] vuoto
            types[n].append({"name": "ciclo", "type": nomi[_rng.randrange(i + 1)] + "[]"})
        _rng.shuffle(types[n])
    return nomi, types


def _valore(tipo, types):
    if tipo.endswith("[]"):
        return [_valore(tipo[:-2], types) for _ in range(_rng.randrange(3))]
    if tipo.endswith("]"):
        base, n = tipo[:-1].split("[")
        return [_valore(base, types) for _ in range(int(n))]
    if tipo in types:
        return {c["name"]: ([] if c["name"] == "ciclo" else _valore(c["type"], types)) for c in types[tipo]}
    return _ATOMI[tipo]()


def _in_piu(nomi, s):
    p, X, Y = nomi[0], "X" + s, "Y" + s
    return _rng.choice([
        {X: [{"name": "x", "type": "uint256"}]}, {X: []}, {X: [{"name": "x", "type": p}]},
        {X: [{"name": "x", "type": p + "[]"}]}, {X: [{"name": "x", "type": _rng.choice(nomi) + "[3]"}]},
        {X: [{"name": "y", "type": Y}], Y: [{"name": "z", "type": "uint8"}]}, {X: [{"name": "x", "type": X + "[]"}]},
        {X: [{"name": "x", "type": "foo"}]}, {X: [{"name": "x", "type": "Nessuna"}]}, {X: 5}, {X: {"a": 1}},
        {X: None}, {X: p}, {X: [5]}, {X: ["uint256 x"]}, {Y: [{"name": "x", "type": X}], X: [{"name": "y", "type": Y}]}])


struct_ko, struct_n, struct_rej = [], 0, 0
for i in range(240):
    nomi, types = _grafo()
    msg = _valore(nomi[0], types)
    sig = _firma(_digest(DOM_USDC, types, nomi[0], msg))
    tipi = dict(types)
    if i % 2:
        for q in range(_rng.randint(1, 3)):
            tipi.update(_in_piu(nomi, f"{i}_{q}"))
    if _rng.random() < 0.5:
        tipi["EIP712Domain"] = CAMPI_DOMINIO
    chiavi = list(tipi)
    _rng.shuffle(chiavi)
    tipi = {k: tipi[k] for k in chiavi}
    fuori = _oracolo_fuori(nomi[0], tipi)
    atteso = ("reject", "encoding_error") if fuori else ("accept", None)
    struct_rej += bool(fuori)
    vec = {"signer": _FIRMATARIO, "signature": sig,
           "eip712": {"domain": DOM_USDC, "types": tipi, "primaryType": nomi[0], "message": msg}}
    for modo in ("testo", "oggetto"):
        struct_n += 1
        try:
            esito = V.verdetto_da_testo(json.dumps(vec)) if modo == "testo" else V.verdetto(vec)
        except BaseException as ex:                          # noqa: BLE001
            struct_ko.append(f"grafo {i} {modo}: {type(ex).__name__}"); continue
        if (esito[0], esito[2]) != atteso or (atteso[0] == "accept" and (esito[1] or "").lower() != _FIRMATARIO.lower()):
            struct_ko.append(f"grafo {i} {modo} (fuori {fuori[:3]}): {esito[0]}/{esito[2]} (atteso {atteso[0]}/{atteso[1]})")
    # lib/eip712.signing_digest applica la stessa regola, con la primaria data (non dedotta dai nomi)
    struct_n += 1
    try:
        d_lib = signing_digest(DOM_USDC, nomi[0], tipi, msg, CAMPI_DOMINIO)
        if fuori or d_lib != _digest(DOM_USDC, types, nomi[0], msg):
            struct_ko.append(f"grafo {i} signing_digest: digest calcolato (fuori {fuori[:3]})")
    except ValoreNonConforme:
        if not fuori:
            struct_ko.append(f"grafo {i} signing_digest: rifiuta un grafo tutto raggiungibile")
    except BaseException as ex:                              # noqa: BLE001
        struct_ko.append(f"grafo {i} signing_digest: {type(ex).__name__}")
    # verify.strati (i quattro valori intermedi di SPEC.md §1): None se una struct non e' raggiungibile, altrimenti il
    # digest firmato. Il runner non la chiama su un encoding_error: senza questo caso la regola in strati() non era provata.
    struct_n += 1
    try:
        st = V.strati(vec)
        if (st is None) != bool(fuori) or (st is not None and st["signing_digest"] != _digest(DOM_USDC, types, nomi[0], msg)):
            struct_ko.append(f"grafo {i} strati: {'None' if st is None else 'calcolati'} (fuori {fuori[:3]})")
    except BaseException as ex:                              # noqa: BLE001
        struct_ko.append(f"grafo {i} strati: {type(ex).__name__}")
for pt in (5, None, ["TransferWithAuthorization"], {"a": 1}, "", "EIP712Domain", "Nessuna"):
    v = json.loads(json.dumps(_v3)); v["eip712"]["primaryType"] = pt
    struct_n += 1
    try:
        esito = V.verdetto(v)
    except BaseException as ex:                              # noqa: BLE001
        struct_ko.append(f"primaryType {pt!r}: {type(ex).__name__}"); continue
    if (esito[0], esito[2]) != ("reject", "encoding_error"):
        struct_ko.append(f"primaryType {pt!r}: {esito[0]}/{esito[2]} (atteso reject/encoding_error)")
# La libreria (lib/eip712.valida_struttura) rifiuta con la SUA classe e il suo motivo, mai con un'eccezione qualunque:
# forme ostili delle struct raggiungibili (non liste, membri non oggetti, `type` non stringa) e primaryType non validi.
from eip712 import ValoreNonConforme, strutture_raggiungibili, valida_struttura   # noqa: E402
_T = "TransferWithAuthorization"
_ostili = [({_T: v}, _T) for v in (5, None, "S0", {"a": 1}, [5], [None], ["uint256 x"], [{"name": "x"}],
                                   [{"name": "x", "type": 7}], [{"name": "x", "type": None}], [{"name": "x", "type": ["X"]}])]
_ostili += [({_T: _v3["eip712"]["types"][_T]}, pt) for pt in (5, None, [_T], {"a": 1}, "", "EIP712Domain", "Nessuna")]
_ostili += [({_T: [{"name": "x", "type": "X[]"}], "X": v}, _T) for v in (5, None, "S0", {"a": 1}, [5], [{"name": "x"}],
                                                                          [{"name": "x", "type": 7}])]
# Forme che nessun controllo nomina (solo da chi chiama la libreria con un oggetto, non da un testo JSON): un intero di
# 5000 cifre come primaryType, come nome di struct, come nome o tipo di un membro (str() e repr() di un intero cosi'
# sollevano ValueError), nomi non stringa nel dominio, domain / types che non sono oggetti. Anche a queste la libreria
# risponde con la SUA eccezione.
_G = 10 ** 5000
_ostili_dom = [(DOM_USDC, {_T: _v3["eip712"]["types"][_T]}, _G), (DOM_USDC, {_T: _v3["eip712"]["types"][_T], _G: []}, _T),
               (DOM_USDC, {_T: [{"name": _G, "type": "uint256"}]}, _T), (DOM_USDC, {_T: [{"name": "x", "type": _G}]}, _T),
               ({**DOM_USDC, 5: 1, "zz": 1}, {_T: _v3["eip712"]["types"][_T]}, _T),
               ({**DOM_USDC, _G: 1}, {_T: _v3["eip712"]["types"][_T]}, _T), (None, {_T: []}, _T), ([], {_T: []}, _T),
               (DOM_USDC, None, _T), (DOM_USDC, [[_T, []]], _T),
               (DOM_USDC, {"EIP712Domain": CAMPI_DOMINIO}, "Nessuna"), (DOM_USDC, {}, _T)]   # primaryType assente, nessuna struct fuori
for dom, tipi, pt in [(DOM_USDC, t, p) for t, p in _ostili] + _ostili_dom:
    for nome_f, f in (("valida_struttura", lambda: valida_struttura(dom, tipi, pt)),
                      ("signing_digest", lambda: signing_digest(dom, pt, tipi, _v3["eip712"]["message"], CAMPI_DOMINIO))):
        struct_n += 1
        try:
            strutture_raggiungibili(pt, tipi) if isinstance(pt, str) and isinstance(tipi, dict) else None
            f()
            struct_ko.append(f"lib {nome_f}, types {str(type(tipi))} primaryType {type(pt).__name__}: nessuna eccezione su una forma ostile")
        except ValoreNonConforme:
            pass
        except BaseException as ex:                          # noqa: BLE001
            struct_ko.append(f"lib {nome_f}, primaryType {type(pt).__name__}: {type(ex).__name__} invece di ValoreNonConforme")
# Un primaryType che non e' una stringa e' rifiutato con QUEL motivo (non con quello generico delle forme non nominate)
for pt in (5, None, [_T], {"a": 1}, _G):
    struct_n += 1
    try:
        valida_struttura(DOM_USDC, {_T: _v3["eip712"]["types"][_T]}, pt)
        struct_ko.append(f"lib, primaryType {type(pt).__name__}: nessuna eccezione")
    except ValoreNonConforme as ex:
        if not str(ex).startswith("primaryType non e' una stringa"):
            struct_ko.append(f"lib, primaryType {type(pt).__name__}: motivo {str(ex)[:50]!r}")
    except BaseException as ex:                              # noqa: BLE001
        struct_ko.append(f"lib, primaryType {type(pt).__name__}: {type(ex).__name__} invece di ValoreNonConforme")
# Una catena di struct tutte raggiungibili, ognuna membro `T[]` vuoto della precedente (il testo ha 2 livelli): encodeType
# le include tutte, la firma le copre, il verdetto e' accept a ogni lunghezza e da ogni profondita' della pila. Fino al
# 21/11/2026 encode_type era ricorsiva: da ~990 struct RecursionError -> encoding_error, e a 980 l'esito cambiava con
# la profondita' di chi chiama.
def _da_profondita(k, f):
    return f() if k == 0 else _da_profondita(k - 1, f)


for n_catena in (980, 3000):
    tc = {f"C{i}": [{"name": "a", "type": f"C{i + 1}[]"}] for i in range(n_catena - 1)}
    tc[f"C{n_catena - 1}"] = [{"name": "x", "type": "uint256"}]
    try:
        vc = {"signer": _FIRMATARIO, "signature": _firma(_digest(DOM_USDC, tc, "C0", {"a": []})),
              "eip712": {"domain": DOM_USDC, "types": tc, "primaryType": "C0", "message": {"a": []}}}
        tx = json.dumps(vc)
        esiti = [("testo", V.verdetto_da_testo(tx)), ("oggetto", V.verdetto(vc)),
                 ("testo da 200 chiamate", _da_profondita(200, lambda: V.verdetto_da_testo(tx)))]
    except BaseException as ex:                              # noqa: BLE001
        esiti = [(m, (type(ex).__name__, None, None)) for m in ("testo", "oggetto", "testo da 200 chiamate")]
    for modo, esito in esiti:
        struct_n += 1
        if esito[0] != "accept" or (esito[1] or "").lower() != _FIRMATARIO.lower():
            struct_ko.append(f"catena di {n_catena} struct raggiungibili, {modo}: {esito[0]}/{esito[2]} (atteso accept)")
if not (0 < struct_rej < 240):
    struct_ko.append(f"grafi con struct non raggiungibili: {struct_rej} su 240, il caso non e' esercitato nei due sensi")
print(f"  struct non raggiungibili da primaryType: {struct_n} casi (240 grafi firmati, {struct_rej} con struct in piu', "
      f"x testo/oggetto + lib signing_digest + verify.strati; 7 primaryType non validi; {len(_ostili)} + {len(_ostili_dom)} forme ostili alla libreria "
      f"x valida_struttura/signing_digest; 5 primaryType non stringa col loro motivo; catene di 980 e 3000 struct x 3 modi) -> {len(struct_ko)} sbagliati")
for r in struct_ko[:8]:
    print(f"      {r}")

falliti = bool(panici or radici_ko or forme_ko or letture_ko or annidati_ko or struct_ko)
print("  ESITO:", "nessun panic, classi e forme corrette" if not falliti else "DA CORREGGERE")
sys.exit(0 if not falliti else 1)
