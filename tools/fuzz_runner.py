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
print("  ESITO:", "nessun panic — il verificatore rifiuta e basta" if not panici else "PANIC: da correggere")
sys.exit(0 if not panici else 1)
