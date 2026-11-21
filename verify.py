#!/usr/bin/env python3
"""Runner di conformita': ricalcola ogni vettore e confronta col verdetto dichiarato.

    python3 verify.py            # exit 0 = conforme, 1 = non conforme, 2 = banco non affidabile

Il banco si valida PRIMA di emettere qualunque verdetto (Keccak-256 contro valori pubblici, EIP-712
contro i digest pubblicati nella EIP-712 stessa, secp256k1 contro un controllo di firma non
circolare). Un banco che non dimostra di funzionare non ha titolo per dire se altri sono conformi.
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "lib"))

from eip712 import keccak256, hash_struct, type_hash, valida_struttura, self_test as banco_eip712    # noqa: E402
import secp256k1 as S                                                    # noqa: E402

# Ordine canonico dei campi di EIP712Domain. I campi sono OPZIONALI: il typeHash si calcola su
# quelli effettivamente presenti. Una lista fissa a quattro campi sbaglia su ogni dominio parziale —
# per esempio quello del contratto Permit2, che non ha `version` (vettore 035).
_ORDINE_DOMINIO = [("name", "string"), ("version", "string"), ("chainId", "uint256"),
                   ("verifyingContract", "address"), ("salt", "bytes32")]


def campi_dominio(dominio):
    return [{"name": n, "type": t} for n, t in _ORDINE_DOMINIO if n in dominio]


def controlli_firma(sig_hex):
    """Regole che una firma deve rispettare PRIMA del recupero (EIP-2 e range di secp256k1).

    Un verificatore che si limita a ecrecover accetta anche la firma malleabile (r, N-s), cioe' la
    stessa autorizzazione in due forme con hash diversi: e' la porta d'ingresso del replay.
    """
    # L'input arriva dalla rete: ogni assunzione va verificata PRIMA di usarla. Un fromhex() su una
    # stringa arbitraria solleva ValueError, e un verificatore che solleva invece di rifiutare e' un
    # denial of service. (Misurato: 79 eccezioni non gestite su 600 input malevoli, prima di questo.)
    if not isinstance(sig_hex, str) or not sig_hex.startswith("0x"):
        return "signature_malformed", "firma non e' una stringa 0x"
    corpo = sig_hex[2:]
    if len(corpo) % 2 or any(c not in "0123456789abcdefABCDEF" for c in corpo):
        return "signature_malformed", "firma non esadecimale"
    raw = bytes.fromhex(corpo)
    if len(raw) != 65:
        return "signature_malformed", "lunghezza != 65 byte"
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64]
    if v not in (27, 28):
        return "signature_malformed", f"v = {v} fuori dai valori ammessi (27/28)"
    if not (1 <= r < S.N):
        return "signature_out_of_range", "r fuori dal range [1, N-1]"
    if not (1 <= s < S.N):
        return "signature_out_of_range", "s fuori dal range [1, N-1]"
    if s > S.N // 2:
        return "signature_high_s", "s alto: viola la regola low-s di EIP-2 (firma malleabile)"
    return None


class EncodingError(Exception):
    """Il messaggio EIP-712 non si puo' codificare: e' un fallimento DIVERSO dal recupero."""


class JsonAmbiguo(ValueError):
    """Il testo JSON ammette due letture: un membro ripetuto (RFC 8259 §4: i nomi SHOULD essere unici e il
    comportamento con duplicati e' imprevedibile) o NaN/Infinity."""


def _no_duplicati(coppie):
    visti = {}
    for k, v in coppie:
        if k in visti:
            raise JsonAmbiguo(f"membro JSON ripetuto: {k!r}")
        visti[k] = v
    return visti


def _no_costanti(nome):
    raise JsonAmbiguo(f"{nome} non e' JSON")


PROFONDITA_MAX = 64     # SPEC.md §3.1: i livelli di array e oggetti annidati che un testo puo' avere


class TroppoAnnidato(ValueError):
    """Il testo annida array e oggetti oltre PROFONDITA_MAX: non viene letto (SPEC.md §3.1)."""


def annidato_oltre(testo, limite=PROFONDITA_MAX):
    """True se nel testo array e oggetti sono annidati piu' di `limite` livelli, contati FUORI dalle stringhe e PRIMA
    della lettura. Il limite del lettore `json` cambia con l'interprete (prima profondita' di liste rifiutata, misurata
    il 20/11/2026: 993 su 3.9.25 e 3.11.2, 9998 su 3.12.15, 9999 su 3.13.15, 65197 su 3.14.8): con quel solo limite
    il primo vettore con un membro in piu', ignorato dal verdetto e annidato 1500 livelli, era reject su 3.9 e 3.11 e
    accept su 3.12, 3.13 e 3.14. Un numero della suite da' la stessa risposta ovunque."""
    if isinstance(testo, (bytes, bytearray)):               # json.loads li accetta: stessa decodifica
        testo = bytes(testo).decode(json.detect_encoding(bytes(testo)), "surrogatepass")
    livello, in_stringa, salta = 0, False, False
    for c in testo:
        if in_stringa:
            if salta:
                salta = False
            elif c == "\\":
                salta = True
            elif c == '"':
                in_stringa = False
        elif c == '"':
            in_stringa = True
        elif c == "[" or c == "{":
            livello += 1
            if livello > limite:
                return True
        elif c == "]" or c == "}":
            livello -= 1
    return False


CIFRE_MAX = 4300        # SPEC.md §3.1: le cifre che un numero JSON puo' avere (parte intera, frazione ed esponente insieme)


class TroppeCifre(ValueError):
    """Un numero JSON ha piu' di CIFRE_MAX cifre: il testo non viene letto (SPEC.md §3.1)."""


class NumeroNonFinito(ValueError):
    """Un numero JSON con frazione o esponente vale infinito per float(): il testo non viene letto (SPEC.md §3.1)."""


def numero_oltre(testo, limite=CIFRE_MAX):
    """True se nel testo un numero JSON ha piu' di `limite` cifre (parte intera, frazione ed esponente contate insieme),
    contate FUORI dalle stringhe e PRIMA della lettura. Il `json` di CPython converte gli interi con int(), che oltre 4300
    cifre solleva ValueError, ma il limite lo sposta una variabile d'ambiente (PYTHONINTMAXSTRDIGITS=0 lo toglie):
    misurato il 21/11/2026, il vettore 003 con un membro ignorato di 4301 cifre era input_not_object e, con quella
    variabile, accept (anche in 1.5.0). I numeri con frazione o esponente passavano da float() senza limite: 5000 cifre
    seguite da `.5` erano accept in un membro ignorato. Un numero della suite da' la stessa risposta ovunque."""
    if isinstance(testo, (bytes, bytearray)):               # json.loads li accetta: stessa decodifica
        testo = bytes(testo).decode(json.detect_encoding(bytes(testo)), "surrogatepass")
    in_stringa = salta = in_numero = False
    cifre = 0
    for c in testo + " ":                                    # lo spazio finale chiude un numero in coda al testo
        if in_stringa:
            if salta:
                salta = False
            elif c == "\\":
                salta = True
            elif c == '"':
                in_stringa = False
        elif "0" <= c <= "9":
            if not in_numero:
                in_numero, cifre = True, 0
            cifre += 1
        elif in_numero and c in ".eE+-":
            pass                                             # frazione, esponente e suo segno: lo stesso numero
        else:
            if in_numero and cifre > limite:
                return True
            in_numero = False
            if c == '"':
                in_stringa = True
    return False


def _float_json(s):
    """parse_float del lettore: float() di un numero con frazione o esponente; infinito (1e400, -1e400) non e' un valore
    che il testo mostra, quindi NumeroNonFinito (SPEC.md §3.1). Prima: accept in un membro ignorato. (Un numero JSON non
    da' mai NaN a float(): NaN arriva solo come costante, che `_no_costanti` rifiuta.)"""
    v = float(s)
    if v in (float("inf"), float("-inf")):
        raise NumeroNonFinito(f"numero non finito: {s[:24]}")
    return v


def _intero_json(s):
    """parse_int del lettore: int() su pezzi di 600 cifre (sotto il minimo di PYTHONINTMAXSTRDIGITS, 640), cosi' la
    lettura di un intero entro CIFRE_MAX non dipende dalla variabile d'ambiente."""
    segno, s = (-1, s[1:]) if s.startswith("-") else (1, s)
    v = 0
    for i in range(0, len(s), 600):
        pezzo = s[i:i + 600]
        v = v * 10 ** len(pezzo) + int(pezzo)
    return segno * v


def leggi_json_stretto(testo):
    """Il lettore che un verificatore deve usare: il `json` della libreria standard tiene l'ULTIMO di due membri
    con lo stesso nome, un altro lettore il primo, e i due vedono importi diversi sotto la stessa firma
    (25/09/2026: `"value": 99999999999, "value": 10000` era `accept`). `verdetto(dict)` riceve un oggetto gia'
    letto e non puo' piu' vedere i duplicati: chi integra deve leggere con questa funzione, o usare
    `verdetto_da_testo`."""
    if annidato_oltre(testo):
        raise TroppoAnnidato(f"annidato oltre {PROFONDITA_MAX} livelli")
    if numero_oltre(testo):
        raise TroppeCifre(f"un numero con piu' di {CIFRE_MAX} cifre")
    return json.loads(testo, object_pairs_hook=_no_duplicati, parse_constant=_no_costanti, parse_int=_intero_json,
                      parse_float=_float_json)


def verdetto_da_testo(testo):
    try:
        vec = leggi_json_stretto(testo)
    except JsonAmbiguo as ex:
        return "reject", None, "json_ambiguous", str(ex)
    except ValueError as ex:
        return "reject", None, "input_not_object", f"testo non leggibile come JSON: {ex}"
    except RecursionError:
        # Rete di sicurezza: oltre PROFONDITA_MAX il testo non arriva al lettore (TroppoAnnidato, sopra); resta per un
        # interprete con un limite di ricorsione piu' basso di quello. Un testo annidato oltre la profondita' che il
        # lettore segue (RFC 8259 §9: un'implementazione puo' porre un limite alla profondita') non e' leggibile qui. Fino alla 1.5.0 RecursionError usciva dalla funzione: con
        # "[" * 1000 + "]" * 1000 il verificatore sollevava invece di rifiutare (Python 3.11; su 3.12 e 3.13 con 20000
        # livelli, su 3.14 con 100000; 20/11/2026).
        return "reject", None, "input_not_object", "testo non leggibile come JSON: annidato oltre il limite del lettore"
    return verdetto(vec)


def digest_di(vec):
    try:
        e = vec["eip712"]       # dentro il try: un vettore SENZA il blocco sollevava KeyError (fuzz 25/09, root={})
        valida_struttura(e["domain"], e["types"], e["primaryType"])     # SPEC.md §1 /eip712/types: struct raggiungibili
        ds = hash_struct("EIP712Domain", {"EIP712Domain": campi_dominio(e["domain"])}, e["domain"])
        return keccak256(b"\x19\x01" + ds + hash_struct(e["primaryType"], e["types"], e["message"]))
    except Exception as ex:                                  # noqa: BLE001 — l'input non e' fidato
        raise EncodingError(str(ex)) from ex


def recupera(vec, digest):
    raw = bytes.fromhex(vec["signature"][2:])
    pub = S.recover_public_key(digest, int.from_bytes(raw[:32], "big"),
                               int.from_bytes(raw[32:64], "big"), raw[64] - 27)
    return S.public_key_to_address(pub, keccak256)


def verdetto(vec):
    """accept sse la firma supera i controlli di forma E recupera al firmatario dichiarato.

    Ritorna (verdict, recovered_address, classe_di_ragione, testo). Il verificatore rifiuta TUTTO cio'
    che non capisce (l'input arriva dalla rete: sollevare e' un denial of service), ma dice PERCHE':
    senza la classe, un vettore rotto che solleva un'eccezione diventa un "reject" e passa per il
    motivo sbagliato. Le classi sono in tools/reject_reasons.py.

    La codifica dei valori del messaggio e' STRETTA (lib/eip712.py): un valore che non ha la forma
    ammessa per il suo tipo EIP-712 (10000.9 per un uint256, "XX"+hex per un address, "false" per un
    bool…) e' `encoding_error`, non viene normalizzato — altrimenti il JSON mostrato non e' il
    messaggio firmato.
    """
    # Un input che non e' un oggetto JSON (null, array, stringa, numero, bool) non ha campi da
    # leggere: prima vec.get() sollevava AttributeError, l'eccezione finiva nel ramo della firma e il
    # rifiuto usciva come `signature_malformed` — verdetto giusto, ragione sbagliata (fuzz 25/09).
    if not isinstance(vec, dict):
        return "reject", None, "input_not_object", f"l'input e' {type(vec).__name__}, non un oggetto JSON"
    try:
        problema = controlli_firma(vec.get("signature"))
    except Exception:                                        # noqa: BLE001 — nessun input deve passare oltre
        return "reject", None, "signature_malformed", "firma non interpretabile"
    # L'encoding si calcola PRIMA e SEPARATAMENTE dal recupero: un messaggio non codificabile e' un
    # fallimento dello strato EIP-712, non della firma, e la classe deve dirlo.
    try:
        digest = digest_di(vec)
    except EncodingError:
        return "reject", None, "encoding_error", "messaggio EIP-712 non codificabile"
    if problema:
        classe, testo = problema
        # SPEC.md §1 (/expected/recovered_address): firma malformata o fuori range -> indirizzo null, anche quando
        # il recupero sarebbe definito (v = 29/30 con r < p - N da' recovery id 2/3: prima l'indirizzo usciva).
        if classe != "signature_high_s":
            return "reject", None, classe, testo
        # Il verdetto e' reject, ma se il recupero e' comunque definito (caso tipico: firma
        # malleabile high-s, matematicamente valida) l'indirizzo si RIPORTA: serve a chi sta
        # debuggando, e distingue "rifiutata da una regola" da "non recuperabile".
        try:
            return "reject", recupera(vec, digest), classe, testo
        except Exception:                                    # noqa: BLE001
            return "reject", None, classe, testo
    try:
        rec = recupera(vec, digest)
    except Exception as ex:                                  # noqa: BLE001
        return "reject", None, "recovery_undefined", f"recupero non definito: {ex}"
    # Il firmatario e' DICHIARATO nel vettore: dedurlo dal nome del campo ("from", "owner"…) funziona
    # solo finche' le struct si chiamano come ci si aspetta, e i vettori strutturali non lo fanno.
    firmatario = vec.get("signer")
    if not firmatario:
        return "reject", rec, "signer_mismatch", "vettore senza `signer` dichiarato"
    if not isinstance(firmatario, str):
        # SPEC.md §1 /signer: una stringa. Prima str(firmatario): mai uguale a un indirizzo, ma su un oggetto gia' letto
        # annidato in profondita' str() sollevava RecursionError invece di rifiutare (20/11/2026)
        return "reject", rec, "signer_mismatch", "`signer` non e' una stringa"
    ok = rec.lower() == firmatario.lower()
    if ok:
        return "accept", rec, None, None
    return "reject", rec, "signer_mismatch", "recupera a un indirizzo diverso"


STRATI = ("type_hash", "domain_separator", "hash_struct", "signing_digest")


def strati(vec):
    """I quattro valori intermedi di SPEC.md §1, o None se il messaggio non e' codificabile."""
    try:
        e = vec["eip712"]
        valida_struttura(e["domain"], e["types"], e["primaryType"])
        th = type_hash(e["primaryType"], e["types"])
        ds = hash_struct("EIP712Domain", {"EIP712Domain": campi_dominio(e["domain"])}, e["domain"])
        hs = hash_struct(e["primaryType"], e["types"], e["message"])
    except Exception:                                        # noqa: BLE001 — l'input non e' fidato
        return None
    return {"type_hash": th, "domain_separator": ds, "hash_struct": hs,
            "signing_digest": keccak256(b"\x19\x01" + ds + hs)}


class _ConRipetuti(dict):
    """Un oggetto che nel testo aveva un membro ripetuto (qui vince l'ultimo, come in json.loads)."""


def _segna_ripetuti(coppie):
    d = dict(coppie)
    return _ConRipetuti(d) if len(d) != len(coppie) else d


def ripetuto_fuori_da_eip712(o, percorso=()):
    """Il percorso del primo oggetto con un membro ripetuto FUORI da /eip712, o None. Dentro /eip712 un membro
    ripetuto e' un caso di prova (077, json_ambiguous); fuori, le attese stesse del vettore avrebbero due letture."""
    if isinstance(o, _ConRipetuti) and percorso[:1] != ("eip712",):
        return "/" + "/".join(map(str, percorso))
    figli = o.items() if isinstance(o, dict) else enumerate(o) if isinstance(o, list) else ()
    for k, v in figli:
        p = ripetuto_fuori_da_eip712(v, percorso + (k,))
        if p is not None:
            return p
    return None


def main():
    banco = banco_eip712()
    if not banco.get("ok"):
        print("BANCO NON AFFIDABILE — nessun verdetto emesso:", banco.get("checks"))
        return 2
    prova = S.self_test(keccak256)
    if not prova.get("ok"):
        print("BANCO NON AFFIDABILE — secp256k1:", prova)
        return 2
    print(f"banco: Keccak-256 ok · EIP-712 ok (esempio canonico riprodotto) · secp256k1 ok "
          f"({prova['indirizzo_recuperato'][:10]}…)\n")

    vdir = os.path.join(BASE, "vectors")
    file = sorted(f for f in os.listdir(vdir) if f.endswith(".json"))
    # Schema chiuso (10/10/2026): un vettore con un campo che lo schema non prevede NON e' un vettore della suite. Prima il
    # runner lo leggeva e giudicava la firma ignorando il campo (misurato: `x_unknown_2026` al primo livello, in `eip712`
    # e in `expected` → «conforme», nessuna traccia); lo schema lo rifiutava solo in CI, in un passo separato.
    sys.path.insert(0, os.path.join(BASE, "tools"))
    from check_schema import valida as _valida_schema          # noqa: E402
    schema = json.load(open(os.path.join(BASE, "schema", "vector.schema.json"), encoding="utf-8"))
    righe, falliti = [], 0
    for nome in file:
        testo = open(os.path.join(vdir, nome), encoding="utf-8").read()
        # Un file che il lettore di §3.1 non legge (oltre 64 livelli, un intero di piu' di 4300 cifre, non JSON) non e' un
        # vettore: FALLITO col motivo, stesso esito con ogni interprete e PYTHONINTMAXSTRDIGITS. Prima: 998 con il testo
        # tronco faceva uscire il runner con JSONDecodeError, e un intero di 5000 cifre lo stesso o no secondo la variabile.
        try:
            if annidato_oltre(testo) or numero_oltre(testo):
                raise ValueError(f"oltre i limiti di SPEC.md §3.1 ({PROFONDITA_MAX} livelli, {CIFRE_MAX} cifre)")
            vec = json.loads(testo, object_pairs_hook=_segna_ripetuti, parse_int=_intero_json, parse_float=_float_json)   # SOLO per leggere expected/id e per lo schema: il verdetto passa dal lettore stretto
        except (ValueError, RecursionError) as ex:
            falliti += 1; righe.append((nome, "?", "?", "?", "FALLITO", f"schema: testo non leggibile: {str(ex)[:80]}")); continue
        # (un vettore con un membro ripetuto, come 077, e' un vettore della suite che DEVE dare reject/json_ambiguous)
        errori_schema = _valida_schema(vec, schema, "") if isinstance(vec, dict) else ["non e' un oggetto"]   # percorso senza il nome del file: il campo resta leggibile
        if not errori_schema and ripetuto_fuori_da_eip712(vec) is not None:
            errori_schema = [f"{ripetuto_fuori_da_eip712(vec)}: membro ripetuto fuori da /eip712"]
        if errori_schema:
            falliti += 1; righe.append((str(vec.get("id", nome)) if isinstance(vec, dict) else nome, str(vec.get("origin", "?")) if isinstance(vec, dict) else "?",
                                        "?", "?", "FALLITO", f"schema: {errori_schema[0]}")); continue   # intero: il campo non previsto e' NOMINATO
        v, rec, classe, perche = verdetto_da_testo(testo)
        atteso = vec["expected"]["verdict"]
        ok = v == atteso
        att_addr = vec["expected"]["recovered_address"]
        ok_addr = (rec is None and att_addr is None) or (
            rec is not None and att_addr is not None and rec.lower() == str(att_addr).lower())
        # Un reject e' conforme solo se rifiuta PER LA RAGIONE DICHIARATA. FAIL-CLOSED: un vettore
        # reject senza classe dichiarata non e' un test, e' un semaforo.
        ok_ragione = True
        if atteso == "reject":
            att_classe = vec["expected"].get("reject_reason")
            ok_ragione = att_classe is not None and classe == att_classe
            if not ok_ragione:
                perche = f"ragione {classe} != dichiarata {att_classe}"
        # I quattro valori intermedi (SPEC.md §1, livello "layer"): null se il messaggio non si codifica, altrimenti
        # quelli che il runner calcola. Prima nessun gate leggeva type_hash e domain_separator.
        calc = None if classe in ("json_ambiguous", "encoding_error") else strati(vec)
        ok_strati = all((calc is None and vec["expected"][k] is None) or (
            calc is not None and isinstance(vec["expected"][k], str)
            and vec["expected"][k].lower() == "0x" + calc[k].hex()) for k in STRATI)
        if not ok_strati and ok and ok_addr and ok_ragione:
            perche = "valori intermedi diversi da expected"
            classe = classe or "strati"
        if not (ok and ok_addr and ok_ragione and ok_strati):
            falliti += 1
        righe.append((vec["id"], vec["origin"], atteso, v,
                      "OK" if (ok and ok_addr and ok_ragione and ok_strati) else "FALLITO",
                      f"{classe}: {perche}" if classe else ""))

    print(f"{'vettore':32s} {'origine':10s} {'atteso':8s} {'ottenuto':9s} {'esito':8s} ragione del reject")
    for r in righe:
        print(f"{r[0]:32s} {r[1]:10s} {r[2]:8s} {r[3]:9s} {r[4]:8s} {r[5] if r[5].startswith('schema: ') else r[5][:60]}")
    print(f"\n{len(righe)} vettori · {len(righe)-falliti} conformi · {falliti} falliti")
    return 0 if falliti == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
