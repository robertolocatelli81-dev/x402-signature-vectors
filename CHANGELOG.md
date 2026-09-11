# Changelog

Vectors are versioned so that an implementation can state *which* set it passes. Vector `id`s are
stable and never reused: a vector that turns out to be wrong is corrected in place and the change is
recorded here, so a verdict recorded against v0.2.0 stays meaningful.

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
