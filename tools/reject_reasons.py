"""Classe di ragione DICHIARATA per ogni vettore `reject`.

Perche' esiste: un runner che rifiuta tutto cio' che non capisce (giusto: l'input arriva dalla rete)
puo' dare verde a un vettore ROTTO — un JSON con una chiave sbagliata produce un'eccezione, l'eccezione
diventa "reject", e se il vettore si aspettava "reject" il runner dice CONFORME. Passa per il motivo
sbagliato. (Rilievo di Gemini 3.1 Pro, 11/09/2026: prima di questo, 049 e 050 rifiutavano con la
stessa ragione di un recupero fallito, e nessuno lo vedeva.)

La classe e' dichiarata QUI, a mano, per ogni vettore — non dedotta dal runner, altrimenti il
confronto sarebbe circolare. Il runner la ricalcola e la confronta: verdetto giusto + ragione
sbagliata = FALLITO.
"""
CLASSI = {
    "signature_malformed":     "non e' una firma: non 0x, non esadecimale, lunghezza != 65, v non in {27,28}",
    "signature_out_of_range":  "r o s fuori da [1, N-1]",
    "signature_high_s":        "s > N/2: firma malleabile (EIP-2)",
    "encoding_error":          "il messaggio EIP-712 non e' codificabile (campo mancante, primaryType ignoto)",
    "recovery_undefined":      "firma ben formata ma il recupero non produce una chiave (x non sulla curva, punto all'infinito)",
    "signer_mismatch":         "recupera a un indirizzo diverso dal `signer` dichiarato",
}

REJECT_REASON = {
    "002-eip2612-spec-example": "signer_mismatch",
    "005-mutated-value": "signer_mismatch",
    "006-mutated-to": "signer_mismatch",
    "007-mutated-valid-before": "signer_mismatch",
    "008-wrong-domain-chainid": "signer_mismatch",
    "009-ecdsa-malleability-high-s": "signature_high_s",
    "013-signature-r-zero": "signature_out_of_range",
    "014-signature-s-zero": "signature_out_of_range",
    "015-signature-v-out-of-range": "signature_malformed",
    "016-signature-r-equals-n": "signature_out_of_range",
    "023-s-exactly-half-n": "signer_mismatch",
    "024-s-just-above-half-n": "signature_high_s",
    "025-s-equals-one": "signer_mismatch",
    "026-r-equals-one": "signer_mismatch",
    "027-r-equals-n-minus-one": "recovery_undefined",
    "028-v-raw-zero": "signature_malformed",
    "029-v-raw-one": "signature_malformed",
    "042-permit2-witness-tampered": "signer_mismatch",
    "046-signature-too-short": "signature_malformed",
    "047-signature-too-long": "signature_malformed",
    "048-signature-empty": "signature_malformed",
    "049-message-missing-field": "encoding_error",
    "050-primary-type-not-in-types": "encoding_error",
    "051-recovery-point-at-infinity-address-zero": "recovery_undefined",
    "052-recovery-point-at-infinity-zero-point-address": "recovery_undefined",
}


def annota(vec):
    """Aggiunge expected.reject_reason. FAIL-CLOSED: un reject senza classe dichiarata non si scrive."""
    vid, verdetto = vec["id"], vec["expected"]["verdict"]
    if verdetto == "reject":
        if vid not in REJECT_REASON:
            raise KeyError(f"{vid}: vettore reject senza reject_reason dichiarata")
        vec["expected"]["reject_reason"] = REJECT_REASON[vid]
    elif vid in REJECT_REASON:
        raise ValueError(f"{vid}: ha una reject_reason ma il verdetto e' accept")
    return vec
