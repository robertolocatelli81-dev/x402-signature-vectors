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

falliti = bool(panici or radici_ko or forme_ko)
print("  ESITO:", "nessun panic, classi e forme corrette" if not falliti else "DA CORREGGERE")
sys.exit(0 if not falliti else 1)
