"""Keccak-256 + EIP-712 in Python puro (stdlib), per generare e verificare i vettori `offerDigest`.

Nessuna dipendenza esterna: l'ambiente non ha pycryptodome/pysha3/eth-hash, e un vettore di
conformità non deve richiedere un ecosistema per essere controllato. Keccak-256 NON è SHA3-256:
differiscono per il byte di padding (0x01 contro 0x06), quindi hashlib.sha3_256 non è sostituibile.
La correttezza è verificata contro vettori pubblici noti in `self_test()`.
"""
from __future__ import annotations

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl(A[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & _MASK & B[(x + 2) % 5][y])
        A[0][0] ^= _RC[rnd]
    return A


def keccak256(data: bytes) -> bytes:
    """Keccak-256 originale (padding 0x01), quello usato da Ethereum — non SHA3-256 (0x06)."""
    rate = 136
    A = [[0] * 5 for _ in range(5)]
    m = bytearray(data)
    m.append(0x01)                                   # padding Keccak, NON 0x06
    while len(m) % rate != 0:
        m.append(0x00)
    m[-1] |= 0x80
    for off in range(0, len(m), rate):
        blocco = m[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(blocco[i * 8:(i + 1) * 8], "little")
        A = _keccak_f(A)
    out = b""
    while len(out) < 32:
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            out += A[x][y].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            A = _keccak_f(A)
    return bytes(out[:32])


# ----------------------------------------------------------------------------- EIP-712
def encode_type(primary: str, types: dict) -> bytes:
    """encodeType: `Primary(tipo nome,...)` seguito dai tipi referenziati in ordine alfabetico."""
    def deps(nome, visti):
        if nome in visti or nome not in types:
            return visti
        visti = visti | {nome}
        for campo in types[nome]:
            base = campo["type"].split("[")[0]
            if base in types:
                visti = deps(base, visti)
        return visti
    ordinati = [primary] + sorted(deps(primary, set()) - {primary})
    fuori = "".join(f"{t}({','.join(f'{c[chr(116)+chr(121)+chr(112)+chr(101)]} {c[chr(110)+chr(97)+chr(109)+chr(101)]}' for c in types[t])})" for t in ordinati)
    return fuori.encode()


def type_hash(primary: str, types: dict) -> bytes:
    return keccak256(encode_type(primary, types))


def encode_value(tipo: str, valore, types: dict | None = None) -> bytes:
    """encodeData. Profilo x402: solo string e uint256. Le struct annidate sono gestite (hashStruct
    ricorsivo) perche' servono al controllo positivo contro l'esempio canonico della EIP-712."""
    if types and tipo in types:
        return hash_struct(tipo, types, valore)
    if tipo == "string":
        return keccak256(str(valore).encode("utf-8"))
    if tipo == "bytes":
        return keccak256(valore)
    if tipo.startswith("uint") or tipo.startswith("int"):
        return int(valore).to_bytes(32, "big")
    if tipo == "address":
        return bytes(12) + bytes.fromhex(str(valore)[2:])
    if tipo == "bool":
        return (1 if valore else 0).to_bytes(32, "big")
    if tipo == "bytes32":
        b = bytes.fromhex(str(valore)[2:]) if isinstance(valore, str) else valore
        return b.rjust(32, b"\x00")
    raise ValueError(f"tipo non gestito nel profilo x402: {tipo}")


def hash_struct(primary: str, types: dict, dati: dict) -> bytes:
    parti = [type_hash(primary, types)]
    for campo in types[primary]:
        if campo["name"] not in dati:
            raise KeyError(f"campo mancante nella struct {primary}: {campo['name']} "
                           f"(EIP-712 ha una member list FISSA: un campo assente non e' omissione, e' errore)")
        parti.append(encode_value(campo["type"], dati[campo["name"]], types))
    return keccak256(b"".join(parti))


# profilo x402: il dominio ha 3 campi (name, version, chainId) — vedi §3.2 della extension
_DOMINIO_X402 = [{"name": "name", "type": "string"},
                 {"name": "version", "type": "string"},
                 {"name": "chainId", "type": "uint256"}]


def domain_separator(dominio: dict, campi: list | None = None) -> bytes:
    """domainSeparator. `campi` permette il dominio a 4 membri della EIP-712 canonica (con
    verifyingContract), usato SOLO per il controllo positivo esterno contro i digest pubblicati
    nella EIP stessa: un banco che non riproduce quelli non ha titolo per emettere vettori."""
    return hash_struct("EIP712Domain", {"EIP712Domain": campi or _DOMINIO_X402}, dominio)


def signing_digest(dominio: dict, primary: str, types: dict, messaggio: dict,
                   campi_dominio: list | None = None) -> bytes:
    """Il digest EIP-712 firmato: keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))."""
    return keccak256(b"\x19\x01" + domain_separator(dominio, campi_dominio)
                     + hash_struct(primary, types, messaggio))


def self_test() -> dict:
    """Il banco deve dimostrare di funzionare PRIMA di produrre vettori: Keccak contro valori pubblici."""
    noti = {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        b"testing": "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
    }
    ok_keccak = all(keccak256(k).hex() == v for k, v in noti.items())
    import hashlib
    diverso_da_sha3 = keccak256(b"abc").hex() != hashlib.sha3_256(b"abc").hexdigest()
    # encodeType su un caso di riferimento EIP-712 (esempio canonico della EIP)
    tipi_ref = {"Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
                "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"},
                         {"name": "contents", "type": "string"}]}
    et = encode_type("Mail", tipi_ref).decode()
    ok_encode = et == "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    # CONTROLLO POSITIVO ESTERNO: i digest dell'esempio "Mail" sono pubblicati NELLA EIP-712.
    # Riprodurli e' la prova che questo banco calcola EIP-712 e non qualcosa che gli somiglia.
    campi_dom = [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                 {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]
    dom = {"name": "Ether Mail", "version": "1", "chainId": 1,
           "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"}
    msg = {"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
           "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
           "contents": "Hello, Bob!"}
    ds = domain_separator(dom, campi_dom).hex()
    hs = hash_struct("Mail", tipi_ref, msg).hex()
    sd = signing_digest(dom, "Mail", tipi_ref, msg, campi_dom).hex()
    atteso_ds = "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    atteso_hs = "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    atteso_sd = "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    ok_eip = (ds == atteso_ds and hs == atteso_hs and sd == atteso_sd)
    return {"keccak_vettori_pubblici": ok_keccak, "keccak_diverso_da_sha3_256": diverso_da_sha3,
            "encode_type_riferimento_EIP712": ok_encode,
            "eip712_esempio_canonico_riprodotto": ok_eip,
            "domainSeparator": ds, "hashStruct": hs, "signingDigest": sd,
            "ok": ok_keccak and diverso_da_sha3 and ok_encode and ok_eip}


if __name__ == "__main__":
    import json
    print(json.dumps(self_test(), indent=2))
