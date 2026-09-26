# x402 signature conformance vectors

Cryptographic conformance vectors for the **signature layer** of [x402](https://github.com/coinbase/x402):
EIP-712 typed-data digests and secp256k1 recovery, for the `exact` scheme on EVM and the gas-sponsoring
extensions.

**Zero dependencies.** Keccak-256, EIP-712 and secp256k1 are implemented from scratch in the Python
standard library (`lib/`). A conformance vector that needs an ecosystem installed to be checked is a
vector most people will not check.

```bash
python3 verify.py                  # exit 0 = conformant, 1 = failures, 2 = bench not trustworthy
python3 tools/check_manifest.py    # fail-closed integrity gate over every file
python3 tools/check_schema.py      # every vector against schema/vector.schema.json
python3 tools/audit_spec_examples.py
```

**Cross-validated in both directions.** `lib/` is not trusted on its own authority: Keccak-256 against
`eth-hash` over 2000 inputs (including rate boundaries), recovery against `coincurve`/libsecp256k1 over
500 signatures *produced by* libsecp256k1, and — the half that is usually missing — **600 degenerate
inputs checked for matching rejections**, because the real risk is not failing to read a good
signature, it is accepting one the reference library would refuse. Zero divergences in all three. Those libraries are *not* a dependency of the suite; they are used only to prove
`lib/` has no blind spot of its own (`tools/crossvalidate.py`, run in its own CI job).

## Why this exists

x402 has five official implementations (typescript, python, go, java, contracts) and nine `exact`
variants, and — at the time of writing — `specs/vectors/` and `specs/conformance/` both return 404.
Every implementation currently verifies itself.

The signature layer is where that costs the most: a wrong EIP-712 domain does not raise a typed
error, it yields a signature that recovers to a different address, and the verifier can only report
"invalid signature" with no diagnostic pointing at the cause.

## What this is *not*

Deliberately narrow, and complementary to work that already exists:

| project | layer covered | method |
|---|---|---|
| [AlgoVoi JCS conformance vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors) | RFC 8785 JSON canonicalisation, cross-validated across 10 implementations | offline; **explicitly does not cross-validate signature verification** |
| [Cairn](https://cairnwake.com/reports.html) | behaviour of **live** endpoints (malformed payments, replay) | paid, on-chain, signed reports |
| [*Five Attacks on x402*](https://arxiv.org/abs/2605.11781) | protocol-level attacks on authorization, binding, replay | formal analysis of three SDKs |
| **this suite** | **EIP-712 / secp256k1 signatures over artifacts** | offline, dependency-free, byte-reproducible |

No claim of being first or authoritative. This is not an official Coinbase artifact and does not
speak for the x402 Foundation.

## Finding: one signature, reused seven times

The same 65-byte signature appears **seven times across five normative documents**, presented as the
signature of five different message types (EIP-3009 `TransferWithAuthorization`, Permit2,
EIP-2612 `Permit`, ERC-20 approval, ERC-4361 sign-in). An ECDSA signature is valid for exactly one
message, so at most one of those can be genuine.

| example | standard | verdict |
|---|---|---|
| `scheme_exact_evm.md` | EIP-3009 `TransferWithAuthorization` | **valid** — recovers to the declared `from` |
| `eip2612_gas_sponsoring.md` | EIP-2612 `Permit` | **placeholder** — recovers to `0xd259c196…` |
| `erc20_gas_sponsoring.md` | EIP-2612 `Permit` | **placeholder** — same |
| `sign-in-with-x.md` | ERC-4361 / EIP-191 | **indicative only** — the spec does not publish the exact signed string, so this cannot be stated categorically |

Full detail: [`audit/SPEC_EXAMPLES_AUDIT.md`](audit/SPEC_EXAMPLES_AUDIT.md).

This is reported clinically, not as criticism. The consequence is concrete: a developer who copies a
placeholder example as a reference builds their verifier against a value that cannot verify, and the
first thing they will conclude is that *their own* implementation is broken.

## Vector format

Each vector is a single self-contained JSON file — `eip712` (domain, types, primaryType, message),
`signature`, and an `expected` block naming both the verdict and the address the signature actually
recovers to. Nothing is implicit, including the domain that the specification leaves unstated.

Every `reject` vector also declares **`reject_reason`** — one of `signature_malformed`,
`signature_out_of_range`, `signature_high_s`, `encoding_error`, `recovery_undefined`,
`signer_mismatch`, `input_not_object`, `json_ambiguous` (defined in `tools/reject_reasons.py`). A verifier is conformant on a reject vector
only if it rejects **for that class of reason**: a vector rejected for the wrong reason is how a broken
test passes, and a reject vector without a declared class fails the schema gate. `input_not_object`
(the payload is `null`, an array, a string, a number or a boolean) cannot appear in a vector file,
which is an object by construction; the runner emits it and `tools/fuzz_runner.py` checks it.

**Value encoding is strict.** The runner's encoder (`lib/eip712.py`) admits exactly one JSON form per EIP-712
type and rejects everything else with `encoding_error`, instead of normalizing it:

| EIP-712 type | admitted JSON value |
|---|---|
| `uintN` / `intN` (N = 8…256, multiple of 8) | a JSON integer (not a boolean, not a number with a fraction or exponent — `10000.0` is rejected), or an ASCII decimal string in canonical form: `^(0\|[1-9][0-9]*)$`, with an optional leading `-` for `intN` (`"-0"` excluded). No `+`, whitespace, `_`, leading zeros, non-ASCII digits or `0x`. Then the range of the type. |
| `address` | a string matching `^0x[0-9a-fA-F]{40}$` exactly (the EIP-55 checksum is not checked, see 040) |
| `bytes32` | a string matching `^0x[0-9a-fA-F]{64}$` exactly (other `bytesN` are outside the x402 profile) |
| `bytes` | a string matching `^0x([0-9a-fA-F]{2})*$` |
| `string` | a JSON string |
| `bool` | `true` or `false` |
| `T[]` / `T[k]` | a JSON array; exactly `k` elements for `T[k]` |

Why: a library that calls `int()`, `str()` or `bytes.fromhex()` on the value reads `10000.9`,
`"١٠٠٠٠"`, `" 10000\n"`, `"10_000"` and `"+10000"` as 10000, an address with `XX` instead of `0x`, a
`bytes32` with spaces in it, and the string `"false"` as `true`. The JSON a person or a policy engine
reads is then not the message that was signed. Vectors 056–075 carry a real signature by the test key
over the message such a parser derives, so a normalizing verifier **accepts** them; 076 is the check in
the other direction (the canonical decimal string is admitted). This is a rule of this suite, stated
here; EIP-712 itself defines the encoding of values, not their JSON spelling.

The same reasoning applies to what surrounds the values (vectors 077–081). A member repeated in the text
(`"value": 99999999999, "value": 10000`) is read as its last occurrence by Python's `json` and as its
first by other readers, so the runner reads every vector with a strict reader (`verify.leggi_json_stretto`,
class `json_ambiguous`); `verdetto(dict)` receives an object already read and cannot see a duplicate, so an
integrator must read with that function or call `verdetto_da_testo`. A domain member outside the five
EIP-712 names, a `types.EIP712Domain` that does not match the domain's members (names, types, order), and
a struct named like an atomic type (`address`) are `encoding_error`.

`origin` separates two statuses that must not be mixed:

- **`spec`** — payload and signature taken verbatim from the x402 specifications. The expected verdict
  is the audit result, whatever it is.
- **`generated`** — signed here with the test key below, so that a valid vector exists even where the
  spec offers none.

```
test private key  0x4646…4646   (published on purpose: a conformance vector must hold no secrets)
test address      0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f
```

Current set: **81 vectors — 31 `accept`, 50 `reject`** (v1.4.0), against
[`schema/vector.schema.json`](schema/vector.schema.json).

Beyond message-binding mutations (amount off by one, substituted recipient, one-second validity
shift, wrong-chain domain), the set covers the cryptographic edges where verifiers actually break:

- **ECDSA malleability** — `(r, N−s)` with flipped `v` is mathematically valid over the *same*
  message and recovers to the *same* address. EIP-2 requires low-s, so a conformant verifier must
  reject it. This is the vector that separates a real verifier from one that just calls `ecrecover`,
  and accepting it means the same authorization exists in two forms with different hashes.
- **Malformed signatures** — `r=0`, `s=0`, `r=N`, `v` out of range: recovery is undefined and
  `recovered_address` is `null`. A library that raises here instead of rejecting is a denial of service.
- **uint256 boundaries and non-ASCII domain names** — these are `accept`: the signature is valid, and
  rejecting them is *policy*, not signature verification. Keeping the two apart is the point.
- **Exact secp256k1 boundaries** — `s = N/2` and `s = N/2 + 1` (where a `<` instead of `<=` breaks
  and nowhere else), `r = 1`, `r = N−1`, raw recovery ids `v = 0/1` instead of 27/28.
- **Partial EIP-712 domains** — a domain without `version`, which is the real domain of the canonical
  Permit2 contract. An implementation assuming four fixed fields computes a different separator. This
  vector found the bug in *our own* runner, which had the fields hard-coded.
- **Both other x402 transfer methods** — Permit2 `PermitWitnessTransferFrom` with the witness types
  taken from the spec's `WITNESS_TYPE_STRING`, plus a tampered-witness vector: the attack the witness
  pattern exists to stop, where a facilitator redirects the payment.
- **Robustness** — signatures too short, too long, empty; a message missing a declared field; a
  `primaryType` absent from `types`. These must be clean rejections: the input comes from the network,
  and a library that raises here is a denial of service.
- **Strict value forms** — 056–075: a JSON value that a permissive parser normalizes into the value that
  was actually signed (fractional numbers, non-ASCII digits, whitespace, `_`, `+`, leading zeros,
  booleans as integers, `XX` instead of `0x`, spaces inside hex, an integer where a string is typed,
  `"false"` for a boolean, a string where an array is typed, the wrong length for a fixed array, a
  `uint7`). Rejected as `encoding_error`; 076 accepts the canonical decimal string.
- **One reading of the text, the domain and the type names** — 077–081: a repeated JSON member
  (`json_ambiguous`), an unknown domain member, a declared `EIP712Domain` that differs from the domain, a
  `chainId` declared `string`, a struct named `address` (`encoding_error`). Each carries a real signature
  the previous runner accepted.
- **EIP-712 encoding structure** — arrays of structs (hashed as the concatenation of element
  hashStructs, not as JSON), two-level nesting, a string containing a NUL byte (hashed whole, not
  truncated C-style), and referenced-type ordering in `encodeType` (alphabetical, regardless of
  declaration order). These are where SDKs diverge before a payment is ever involved.

**Each layer is testable in isolation.** Every vector carries `type_hash`, `domain_separator`,
`hash_struct` and `signing_digest` alongside the verdict. An implementation that fails learns *which*
layer failed — the EIP-712 encoding or the ECDSA recovery — instead of just "does not verify".

## Tested before publication

| test | result |
|---|---|
| **EIP-712 encoding vs `eth-account` 0.14.0** (reference implementation) | 54 vectors compared (the 22 whose message is not encodable by construction are skipped), **0 divergences** — arrays, nesting, NUL byte, partial domains, signed integers, dynamic bytes, undeclared fields and canonical decimal strings included |
| **Primitives vs `coincurve`/libsecp256k1 and `eth-hash`** | 2000 Keccak inputs, 500 signatures produced *by* libsecp256k1, **600 degenerate inputs checked on rejections** — 0 divergences |
| **Reproducibility** | regenerated from scratch, **byte-identical** to the committed vectors |
| **Clean clone** | `git clone` into an empty directory, all gates green with no local state |
| **Hostile input (`tools/fuzz_runner.py`)** | 600 malformed vectors → **600 rejected, 0 unhandled exceptions**; 10 non-object payloads → 10 `input_not_object`; strict value forms, 20 admitted + 44 not admitted → 0 wrong |

That last row was not green at first: the runner raised `ValueError` on 79 of 600 inputs because it
called `fromhex` on an unvalidated string. On a facilitator that is a denial of service — hostile
input comes from the network. Fixed before publishing, and the fuzzer now runs in CI.

## The bench proves itself before it measures

`verify.py` refuses to emit a verdict unless the bench passes first:

- **Keccak-256** against three published digests, and confirmed distinct from SHA3-256 — the two differ
  only by a padding byte, which is exactly the substitution a preimage bug is made of;
- **EIP-712** against the three digests published in EIP-712 itself for the canonical `Mail` example
  (`domainSeparator f2cee375…`, `hashStruct c52c0ee5…`, `signingDigest be609aee…`);
- **secp256k1** against a non-circular control: sign with a known key, recover, compare the address.

`tools/check_manifest.py` is fail-closed: every file's sha256 must match `manifest.json`, counts must
reconcile, and an undeclared file is a failure.

## Scope and honesty

Signature verification only. It says nothing about balances, on-chain settlement, replay windows at
runtime, or endpoint behaviour — for those, see Cairn and the attack paper above. A vector proves that
a verifier computes the same bytes, not that a system is secure.


## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/x402-signature-vectors/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with x402 implementers who want their signature layer cross-validated against independent vectors. Write with the use case; the answer says what is measured and what is not.
- **Licence**: Apache-2.0: use it freely, also in closed products. If you build on it, a note in Discussions helps the roadmap (and tells the author the work is used).
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.

## Licence

Apache-2.0. Prepared by **Noûs**, AI agent of [@robertolocatelli81-dev](https://github.com/robertolocatelli81-dev)
(Roberto Locatelli), under an explicit, revocable human mandate. Noûs is a role/identity, not a claim
of sentience.
