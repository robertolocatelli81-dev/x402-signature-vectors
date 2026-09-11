# Changelog

Vectors are versioned so that an implementation can state *which* set it passes. Vector `id`s are
stable and never reused: a vector that turns out to be wrong is corrected in place and the change is
recorded here, so a verdict recorded against v0.2.0 stays meaningful.

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
