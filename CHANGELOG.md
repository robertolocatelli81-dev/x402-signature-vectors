# Changelog

Vectors are versioned so that an implementation can state *which* set it passes. Vector `id`s are
stable and never reused: a vector that turns out to be wrong is corrected in place and the change is
recorded here, so a verdict recorded against v0.2.0 stays meaningful.

## 1.4.0 — 2026-09-26

Two review rounds on 25/09/2026: a malformed-input fuzz (vectors 056–076) and a second round on the text of the
payload (077–081). Figures dated 25/09 are from those rounds and were not all re-measured; the 26/09 re-run on the
release commit is at the end of this entry.

### First round (056–076): fixes for two defects measured by the malformed-input fuzz

- **Strict value encoding in `lib/eip712.py`.** The encoder called `int()`, `str()` and
  `bytes.fromhex()` on JSON values, which *normalize*: `10000.9`, `"١٠٠٠٠"` (Arabic-Indic digits),
  `" 10000\n"`, `"10_000"`, `"+10000"` all encoded as 10000; an address or `bytes32` with `XX` or `::`
  instead of `0x`, or with spaces inside, encoded as the clean value; `"false"` encoded as `true`; the
  string `"123"` typed `uint256[]` encoded as `[1, 2, 3]`; a `uint256[2]` with three elements and a
  `uint7` were encoded anyway. The runner therefore returned `accept` on messages whose displayed JSON
  is not the signed message. Now each EIP-712 type admits one reading (table in the README, rule in
  the `lib/eip712.py` source) and anything else is `encoding_error`. Admitted for integers: a JSON
  integer or its canonical ASCII decimal string, both the same number, and no other spelling; hex strings
  (`"0x2710"`) are **not** admitted — one textual form per number is the point.
- **056–076**, 21 new vectors: 20 `reject` / `encoding_error`, each signed by the test key over the
  message a normalizing parser derives, plus 076 `accept` (canonical decimal string `"10000"`, same
  signature as 003). Measured: the runner at `fa91c0f` accepts all 20 rejects (56/76 conformant); with
  the fix 76/76. 31 accept / 45 reject at the end of this round. All 76 vectors regenerated
  byte-identical from `tools/genera_vettori*.py` on 25/09; 001–055 are unchanged.
- **eth-account 0.14.0 differs from this rule on 6 of the 20** (measured with `encode_typed_data` +
  `Account.recover_message`, offline): it recovers the declared signer on 059–063 (decimal strings with
  non-ASCII digits, whitespace, `_`, `+`, leading zeros) and 074 (fixed-array length). The other 14 it
  refuses or recovers to a different address. Its encoding still agrees with `lib/` on every encodable
  vector: 54 compared, 0 divergences (the 22 non-encodable ones are skipped by construction, and the 6
  differences above are all among them).
- **New reject class `input_not_object`.** A payload that is not a JSON object (`null`, array, string,
  number, boolean) raised `AttributeError` on `vec.get`, which landed in the signature branch and came
  out as `signature_malformed`: right verdict, wrong reason. Added to `tools/reject_reasons.py`, the
  schema enum and the README list; `tools/check_docs.py` now fails if those three lists disagree, and
  `tools/fuzz_runner.py` checks 10 non-object roots (0/10 right at `fa91c0f`, 10/10 now) plus a table
  of 20 admitted and 44 non-admitted value forms (31 wrong at `fa91c0f`, 0 after the fix; counts of 25/09).
- **`verify.py digest_di`**: `vec["eip712"]` is read inside the `try`, so a vector without the block is
  `encoding_error` instead of an unhandled `KeyError`.
- **Schema**: the value constraints on `eip712.domain` members were removed (the members stay
  required). A malformed domain value is what 058, 067 and 071 test; rejecting it is the verifier's job,
  as the schema already said for the signature length.
- **`tools/check_manifest.py --genera`** now ends `manifest.json` with a newline.

### Second round (077–081)

- **One reading of the text, the domain and the type names.**
  After the strict value forms, the JSON shown could still differ from the message signed:
  a repeated member (`"value": 99999999999, "value": 10000`: `json` keeps the last) — new class
  `json_ambiguous` and a strict reader `verify.leggi_json_stretto` / `verdetto_da_testo`; a domain member
  outside the five EIP-712 names; a `types.EIP712Domain` that does not match the domain (including `chainId`
  declared `string`); a struct named like an atomic type. Each new vector carries a real signature; this runner
  rejects each for the declared class, and each check, ablated on 25/09, turned exactly its own vectors red.
  Measured 26/09: the 1.3.0 runner (`af02a79`) accepts all five, and all 25 rejects added in 1.4.0 (056–081 without
  076): 56/81 conformant.
- **eth-account 0.14.0 on 077–081** (measured 26/09 with `encode_typed_data` + `Account.recover_message`): it raises
  on 078 (`Invalid domain key`) and 079 (`ValidationError`); it recovers a different address on 081 (its digest
  differs); it recovers the declared signer on 080 (`chainId` declared `string` in `types.EIP712Domain`) — it
  accepts that message; and it cannot see 077, because it receives a dict already parsed (and recovers the declared
  signer from it). These five are among the 27 vectors that `tools/crossvalidate_eip712.py` skips (no digest is
  declared for a non-encodable message), so its "0 divergences" does not cover them; the results above are direct
  calls. `tools/crossvalidate.py` now applies the same two reading rules before the cryptographic check.
- **Declared, not repaired (measured 25/09):** the strict value forms of the first round also turned three
  inputs that the 1.3.0 runner accepted, and that eth-account 0.14.0 encodes with the same digest as the 1.3.0 runner, into
  `encoding_error`: `"-0"` for an `intN`, the width-less type `uint`, and the zero-length array type `uint256[0]`.
  None has a canonical form under the rule in the README: the EIP-712 text states that "there are no aliases `uint` and `int`",
  `-0` is not the canonical decimal of 0, and the EIP-712 text is silent on zero-length arrays.

### Re-run on 26/09/2026 on the release commit

81 vectors, 81 conformant (31 `accept` / 50 `reject`); schema 81/81; manifest 112 files, every sha256 matching; all
81 vectors regenerated from `tools/genera_vettori*.py` into an empty directory, byte-identical; `tools/crossvalidate.py`
(coincurve + eth-hash): 81 re-verified, 0 discordant; `tools/crossvalidate_eip712.py` (eth-account 0.14.0): 54
compared, 27 skipped, 0 divergences; `tools/fuzz_runner.py`: no panic, classes and forms as declared.

## 1.3.0 — 2026-09-11

Second adversarial review (Gemini 3.1 Pro), this time over the complete code. Everything it found was
checked against the code and the curve; everything that held is fixed here. Rule applied: a wrong
statement is not softened, it is replaced by the true one.

- **Two dormant defects in `lib/eip712.py`**, dormant because no vector touched them: `intN` was
  encoded without `signed=True`, so a **negative `int256` — a valid message — raised `OverflowError`**
  (a library that refuses a valid message is worse than one that crashes); and dynamic `bytes` was
  hashed as the JSON string object instead of the decoded content (`TypeError`). Both fixed; values
  outside the declared width now raise (→ `encoding_error` for the runner) instead of silently
  encoding. Cross-validated against `eth-account` 0.14.0.
- **053–055**: signed-integer minimum with `uint8` maximum and empty `bytes`; non-empty dynamic
  `bytes`; and an **undeclared field** — the message of 054 plus a key not in `types`, carrying the
  *same* signature, because `encodeData` concatenates the declared members and nothing else (both
  `eth-account` and this library ignore the field). 30 accept / 25 reject.
- **Two wrong statements removed.** The note of 027 said the recovery at `r = N−1` "is defined": it
  is not — `x = N−1` is not on the curve (`x³+7` is not a quadratic residue mod p), which is exactly
  why the runner classifies it `recovery_undefined`. And the cross-validation count "48 vectors" was
  stale since 1.0.1 (it is 53 now: all vectors whose message is encodable).
- Confirmed by the review, unchanged: `signer_mismatch` is the right class for 023/025/026 — an
  arbitrary `r` or `s` still recovers to *some* key, and `ecrecover` returns that address, so the only
  cryptographic reason to reject is that it is not the declared signer.
- **`tools/check_docs.py`, in CI**: the numbers in the README (vector counts, version, how many
  vectors the `eth-account` cross-validation can compare) are recomputed from the vectors, each
  vector's notes are checked against its own data, and the changelog must carry the manifest
  version. Why: "48 vectors compared" survived three releases because no gate ever read a sentence.
- Still open (missing coverage, not a wrong claim): EIP-191 / `personal_sign` vectors for the
  ERC-4361 sign-in flow. That needs a `format` dimension in the schema and runner; next release.

## 1.2.0 — 2026-09-11

Adversarial review (Gemini 3.1 Pro, same day) of the whole v1.1.0. Three findings survived
verification and are fixed here; the others were checked against the code and rejected (r=0/s=0 are
vectors 013/014; the domain mapping in x402 PR #324 reads `extra` from the *resource server's*
requirements and settlement uses the contract's own domain on-chain).

- **`expected.reject_reason` — a reject must be for the declared reason.** The runner rejects
  everything it does not understand (input arrives from the network; raising is a denial of
  service), which means a *broken* vector — a mistyped key, a wrong type — also becomes a "reject",
  and if the vector expected "reject" it passed. Before this change, 049 and 050 (EIP-712 messages
  that cannot be encoded) were rejected with the **same reason as a failed ECDSA recovery** and
  nobody could tell. Now every reject vector declares one of six classes (`signature_malformed`,
  `signature_out_of_range`, `signature_high_s`, `encoding_error`, `recovery_undefined`,
  `signer_mismatch`; see `tools/reject_reasons.py`), declared **by hand per vector**, not derived
  from the runner; the runner classifies independently and a class mismatch is a FAIL. Fail-closed:
  a reject without a declared class fails the schema gate and the runner. Shown to fail in both
  directions (wrong declared class → FAIL; vector with a renamed `domain` key → `encoding_error`
  ≠ declared → FAIL). Encoding is now computed before and separately from recovery in `verify.py`.
  The 27 accept vectors are byte-identical.
- **`tools/discriminate_infinity.py`** — positive control of 051/052, in CI: simulates the two
  defective recoveries the vectors claim to catch (identity → `address(0)`; identity → keccak of 64
  zero bytes) and requires that both ACCEPT. A reject vector nobody could accept proves nothing.
- **052 note corrected.** `(0, 0)` is not a point of secp256k1 (0 ≠ 7 mod p) and the identity has
  no affine coordinates: the address is what a *software convention* for the neutral element
  produces when serialised as 64 bytes, not a mathematical serialisation of ∞.

## 1.1.0 — 2026-09-11

**52 vectors** (27 accept, 25 reject). Closes the last item left open by the review: recovery at the
point at infinity.

- **051–052 — recovery yields the point at infinity.** `Q = r⁻¹(sR − eG)` is the identity whenever
  `sR = eG`, and that is constructible without any private key: `R = kG`, `r = R.x`, `s = e·k⁻¹`
  (here `k = 2`, chosen so that `s` is low-s). The signature is well-formed in every syntactic
  respect — 65 bytes, `r` and `s` in range, low-s — so the **only** reason to reject is that the
  identity is not a public key. libsecp256k1 fails the recovery (`failed to recover ECDSA public
  key`). The declared `signer` is, in turn, the address a *defective* implementation would derive
  from ∞: `address(0)` (051, the Solidity `ecrecover` failure sentinel) and `keccak256(0x00 × 64)`
  = `0x3f17…5fb5` (052, the identity serialised as `(0, 0)`). Both defective mappings were
  simulated against the vectors and both would ACCEPT; `verify.py` rejects.
- **`lib/secp256k1.py`** now raises on the identity instead of returning `None`. Before this change
  the runner rejected only because of its blanket exception handler, and `public_key_to_address`
  would have raised a `TypeError` — the same class of defect the fuzzer caught in 1.0.1, one layer
  lower.
- `tools/check_manifest.py` ignores the local cross-validation venv (`.xval/`) — and, found while
  doing so, **now covers `.github/workflows/conformance.yml`**: the old exclusion matched `.github`
  as well as `.git`, so the CI definition was outside the integrity gate. 77 files declared.

## 1.0.1 — 2026-09-11

Pre-publication testing, and what it found.

- **EIP-712 encoding cross-validated against `eth-account` 0.14.0**: 48 vectors, 0 divergences. Until
  now the encoding had a single external oracle — the canonical `Mail` example in EIP-712 itself.
  One example is not coverage.
- **Runner hardening**: `tools/fuzz_runner.py` threw 600 malformed vectors at `verify.py` and found
  **79 unhandled `ValueError`s** — `fromhex` on an unvalidated string. A verifier that raises instead
  of rejecting is a denial of service, since the input arrives from the network. Now 600/600 rejected,
  0 exceptions, and the fuzzer runs in CI.
- **Reproducibility**: vectors regenerate byte-identical.
- **Clean-clone test**: a fresh `git clone` passes every gate with no local state.

## 1.0.0 — 2026-09-11

**50 vectors** (27 accept, 23 reject). The additions are not padding: each one is a documented way an
implementation goes wrong.

- **Exact curve boundaries** (023–029): `s = N/2`, `s = N/2+1`, `r = 1`, `r = N−1`, raw recovery ids.
- **Domain boundaries** (030–035): `chainId` 0 and max, zero `verifyingContract`, empty `name`/`version`,
  and **a domain without `version`** — the canonical Permit2 domain.
- **EIP-712 encoding** (036–040): empty array, single-element array, atomic types at their limits,
  lowercase vs checksummed address (the encoding uses the 20 bytes; hashing the *string* diverges
  silently).
- **The other x402 transfer methods** (041–045): Permit2 `PermitWitnessTransferFrom` with the spec's
  own witness types, a **tampered-witness** vector, nonce boundaries, degenerate validity window.
- **Robustness** (046–050): malformed signature lengths, missing message field, unknown `primaryType`.

**Three defects found in our own code by these vectors**, which is what they are for:
1. `lib/secp256k1.py` accepted a recovery id of `−27` (from `v = 0`) and returned a **fabricated**
   address where libsecp256k1 rejects. Found by the differential cross-validation. Fixed.
2. `verify.py` had the EIP-712 domain fields hard-coded to four, so every partial domain — including
   Permit2's — failed. Now derived from the domain actually present.
3. Vectors 049/050 initially passed *for the wrong reason* (rejected on a dummy signature rather than
   on the encoding). They now carry a syntactically valid signature, so the rejection comes from where
   the vector claims.

The JSON Schema was relaxed exactly where the vectors demanded it — optional `version`, unconstrained
signature length, nullable digests — and nowhere else.

## 0.3.0 — 2026-09-11

- **Negative differential fuzzing**: 600 degenerate inputs (`r=0`, `s=0`, `r≥N`, `s≥N`, out-of-range
  recovery id, random non-curve points) checked for *matching rejections* against libsecp256k1. The
  positive test alone only proved the happy path; the real risk is accepting what the reference
  refuses.
- **Layer separation**: every vector now carries `type_hash`, `domain_separator`, `hash_struct` and
  `signing_digest`, so the EIP-712 encoding can be tested independently of ECDSA recovery. A failing
  implementation learns *which* layer broke.
- **Four EIP-712 structural vectors** (019–022): array of structs, two-level nesting, NUL byte inside
  a string, referenced-type ordering in `encodeType`. Vector 019 immediately found a real gap: `lib/`
  did not implement array encoding at all and raised. Now implemented.
- **`signer` is declared, not inferred.** The runner used to guess the signer from field names
  (`from`, `owner`) — which silently breaks on any struct that names it otherwise.
- Vector 012 (inverted validity window) relabelled explicitly as a **boundary marker** between
  cryptography and policy, not a cryptographic test.

## 0.2.0 — 2026-09-11

- **Cross-validation** against independent reference implementations: Keccak-256 vs `eth-hash`
  (2000 cases) and recovery vs `coincurve`/libsecp256k1 (500 real signatures), zero divergences.
  The reference libraries are *not* a dependency of the suite — they are used only to show that
  `lib/` has no blind spot of its own.
- **Ten cryptographic edge cases** added (009–018): ECDSA malleability (high-s, EIP-2), uint256
  boundaries, inverted validity window, malformed signatures (`r=0`, `s=0`, `v` out of range,
  `r=N`), non-ASCII domain `name`, zero-address recipient.
- **Form checks before recovery** in `verify.py`: EIP-2 low-s, `r`/`s` range, `v` ∈ {27,28}. A
  verifier that only calls ecrecover accepts the malleable signature — the replay door.
- **JSON Schema** (`schema/vector.schema.json`) plus a stdlib validator. It immediately caught an
  id-naming inconsistency, which is what a schema is for.
- **CI**: integrity gate, schema, conformance run and audit on every push; cross-validation in a
  separate job; weekly scheduled run.

## 0.1.0 — 2026-09-11

- First 8 vectors (3 accept, 5 reject), fail-closed manifest, self-validating bench,
  audit of the signature examples in the x402 specifications.
