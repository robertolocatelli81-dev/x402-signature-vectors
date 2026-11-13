# x402 signature vectors — format and conformance

**Specification version 1.0 · 13 November 2026 · applies to vector format 1 (`schema/vector.schema.json`).**
The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

This document says what a vector is, how its verdict is reached, what "conforms" means for a verifier, and what
an adapter (a small program that runs one verifier on the vectors) receives and answers. It covers the
**signature layer** of the x402 `exact` scheme on EVM only: EIP-712 typed-data encoding, the signing digest and
secp256k1 recovery against a declared signer. It does not cover balances, nonces, validity windows at runtime,
settlement or transport. It is a document of this suite, written by its author; it is not part of the x402
specification and does not speak for the x402 Foundation.

`tools/check_spec.py` (a CI gate) checks that every field of `schema/vector.schema.json` and of
`schema/adapter-result.schema.json` has exactly one clause below (a heading with its JSON path) and that every
such clause names a field of one of the two schemas, and that the reject classes listed in §4 are the schema's.

## 1. The vector file

A vector is one UTF-8 JSON file in `vectors/`, holding one JSON object. The suite's runner reads it twice: with the
standard reader, to validate it against the schema, and with the strict reader of §3.1, which decides the verdict.
The schema is closed: a member that the schema does not define, at a level where the schema says
`additionalProperties: false`, makes the file not a vector of this suite, and the runner reports it as `FALLITO`
with the member named, before any signature verdict.

### `/id`
Zero-padded ordinal and slug (`^[0-9]{3}-[a-z0-9-]+$`). Stable; never reused for a different vector. A vector found
to be wrong is corrected in place and the change is recorded in `CHANGELOG.md`.

### `/origin`
`spec`: payload and signature taken verbatim from an x402 specification document; the expected verdict is the
result of auditing that example, whatever it is. `generated`: signed in this repository with the published test
key.

### `/standard`
Free text naming the signing standard the vector exercises (for example `EIP-3009 TransferWithAuthorization`).
Informative; no verdict depends on it.

### `/signer`
The address the message attributes as its signer, `^0x[0-9a-fA-F]{40}$`, compared case-insensitively. Declared,
never inferred from a field name such as `from` or `owner`.

### `/eip712`
The typed data, exactly as a verifier would receive it. Four members, all required, no others.

### `/eip712/domain`
The EIP-712 domain object. Members MUST be a subset of `name`, `version`, `chainId`, `verifyingContract`, `salt`;
any other member (including a different capitalisation such as `chainID`) is `encoding_error`. `name`, `chainId`
and `verifyingContract` are required by the schema; `version` is optional because EIP-712 allows partial domains
and the canonical Permit2 domain has none. The `EIP712Domain` type is derived from the members present, in the
EIP-712 order above (`string name`, `string version`, `uint256 chainId`, `address verifyingContract`,
`bytes32 salt`). Member values follow the value forms of §2.

### `/eip712/types`
The EIP-712 struct definitions. `EIP712Domain` MAY be present; if present it MUST equal the derived domain type
(names, types and order), otherwise `encoding_error`. A struct name MUST match `^[A-Za-z_$][A-Za-z0-9_$]*$` and
MUST NOT be spelled like an atomic type (`address`, `uint256`, `bytes32`…), otherwise `encoding_error`.

### `/eip712/types/*/name`
A member name of a struct.

### `/eip712/types/*/type`
A member type: an atomic type of §2, a struct name defined in `types`, or an array `T[]` / `T[k]` of either.

### `/eip712/primaryType`
The struct that is signed. A `primaryType` absent from `types` is `encoding_error`.

### `/eip712/message`
The message object. Every member declared for `primaryType` MUST be present (a missing one is `encoding_error`);
members not declared are ignored, as in EIP-712 `encodeData` (vector 055). Values follow §2.

### `/signature`
The signature as transmitted, a `0x`-prefixed hex string. The schema does not constrain its length: malformed
lengths are what some vectors test. §3.2 says when it is rejected.

### `/expected`
What a conformant verifier MUST produce. All members except `reject_reason` are required.

### `/expected/verdict`
`accept` or `reject`, on the signature layer alone.

### `/expected/recovered_address`
The address the signature recovers to over the vector's signing digest, or `null` when no address is defined:
the message is not encodable, the signature is malformed or out of range, or recovery yields no point. A signature
rejected by a rule while recovery is still defined (high-s, signer mismatch) carries the address, so that a
verifier can tell "rejected by a rule" from "not recoverable".

### `/expected/type_hash`
`keccak256(encodeType(primaryType))`, or `null` when the message is not encodable.

### `/expected/domain_separator`
`hashStruct(EIP712Domain, domain)`, or `null` when the message is not encodable.

### `/expected/hash_struct`
`hashStruct(primaryType, message)`, or `null` when the message is not encodable.

### `/expected/signing_digest`
`keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct)`, the bytes actually signed; `null` when the message is
not encodable.

### `/expected/reject_reason`
REQUIRED when `verdict` is `reject`, absent when it is `accept` (enforced by `tools/check_schema.py`). One class of
§4.

### `/notes`
At least one line saying why the vector exists and what failing it means. Informative.

## 2. Value forms

EIP-712 defines how values are encoded, not how they are spelled in JSON. This suite admits exactly one JSON form
per type and rejects every other form with `encoding_error`, so that the JSON a person reads is the message that
was signed. This is a rule of this suite, stricter than EIP-712; §5.4 keeps divergences on it apart from defects.

| type | admitted JSON value |
|---|---|
| `uintN`, `intN` (N = 8…256, multiple of 8) | a JSON integer (not a boolean, not a number with a fraction or exponent), or an ASCII decimal string matching `^(0\|[1-9][0-9]*)$`, with an optional leading `-` for `intN` (`"-0"` excluded); then the range of the type |
| `address` | a string matching `^0x[0-9a-fA-F]{40}$` (the EIP-55 checksum is not checked) |
| `bytes32` | a string matching `^0x[0-9a-fA-F]{64}$` |
| `bytes` | a string matching `^0x([0-9a-fA-F]{2})*$` |
| `string` | a JSON string, hashed as UTF-8 |
| `bool` | `true` or `false` |
| `T[]`, `T[k]` | a JSON array; exactly `k` elements for `T[k]` |

## 3. How the verdict is reached

### 3.1 Reading
The text is read with a reader that rejects a repeated member name anywhere in the document and the non-JSON
constants `NaN`, `Infinity`, `-Infinity` (`verify.leggi_json_stretto`): class `json_ambiguous`. A text that is not a
JSON object (`null`, array, string, number, boolean, or not JSON at all) is `input_not_object`.

### 3.2 Order of the checks
A verifier computes the signature-form checks and the encoding, then answers with the FIRST class that applies, in
this order:

1. `input_not_object`, then `json_ambiguous` (§3.1);
2. `encoding_error`: the domain, the types or the message break §1 or §2;
3. `signature_malformed`: not a string, no `0x` prefix, odd length or non-hex characters, length ≠ 65 bytes,
   or `v` (the last byte) not 27 or 28;
4. `signature_out_of_range`: `r` or `s` outside `[1, N−1]`, N the secp256k1 group order;
5. `signature_high_s`: `s > N/2` (EIP-2 low-s rule);
6. `recovery_undefined`: recovery yields no public key (x not on the curve, point at infinity);
7. `signer_mismatch`: the recovered address differs from `/signer`.

Otherwise the verdict is `accept`.

## 4. Reject classes (closed list)

| class | meaning |
|---|---|
| `signature_malformed` | not a signature: not `0x` hex, length ≠ 65 bytes, `v` not in {27, 28} |
| `signature_out_of_range` | `r` or `s` outside `[1, N−1]` |
| `signature_high_s` | `s > N/2`: malleable signature (EIP-2) |
| `encoding_error` | the EIP-712 message cannot be encoded under §1–§2 |
| `recovery_undefined` | well-formed signature, but recovery yields no key |
| `signer_mismatch` | recovers to an address other than the declared signer |
| `input_not_object` | the input is not a JSON object |
| `json_ambiguous` | the JSON text has two readings (repeated member, NaN/Infinity) |

No other class exists. A new class is a new version of this document, added at the same time to the schema,
`tools/reject_reasons.py` and the README (`tools/check_docs.py` and `tools/check_spec.py` compare them).

## 5. Conformance and adapters

### 5.1 Conformance of a verifier
On a vector, a verifier is:

- **verdict-conformant** when its verdict equals `/expected/verdict`;
- **reason-conformant** when, in addition, on a `reject` vector it rejects for `/expected/reject_reason`;
- **layer-conformant** when, in addition, the recovered address and the four intermediate hashes it exposes equal
  those in `/expected`.

A verifier that exposes no reason (a boolean API) can be verdict-conformant only; a report says which level was
measured. "Conformant on the suite" means conformant on every applicable vector at the stated level.

### 5.2 What an adapter receives and answers
An adapter runs one entry point of one verifier. It is invoked as

    <adapter> <entry> <vector-path> [<vector-path>…]

and writes, for each path in order, one line holding one JSON object that matches
`schema/adapter-result.schema.json` (closed: a line with another member, a missing member or a value outside the
lists is rejected by the runner, `tools/run_sdk_adapters.py`). Exit status 0 when every path was answered, 2 when the
adapter could not start (usage, missing environment). The adapter MUST report what the verifier answered and MUST
NOT decide a verdict itself.

### `/adapter/id`
The vector's `/id`.

### `/adapter/sdk`
The verifier under test (`typescript`, `python`, …).

### `/adapter/entry`
The entry point used, as named by the adapter (`typed-data`, `facilitator-exact`, …).

### `/adapter/verdict`
`accept` or `reject` when the entry point answered on the signature layer; `not_applicable` when the vector cannot
be expressed as an input of that entry point without changing it (§5.3); `not_reached` when the entry point answered
with a reason outside the signature layer (a time window, a missing domain parameter), so its answer says nothing
about the signature; `error` when the verifier raised instead of answering.

### `/adapter/reject_reason`
A class of §4 when the verifier's own reason maps one-to-one to it; `null` otherwise (including every boolean API).

### `/adapter/sdk_reason`
The verifier's own answer, verbatim (its error code, or `true`/`false`), or `null` when there is none.

### `/adapter/detail`
Free text: the verifier's message, the exception, or why the vector is not applicable; `null` when there is nothing
to add.

### 5.3 Translating a vector into an entry point's input
- An entry point that takes **typed data** (domain, types, primaryType, message, signature, expected signer)
  receives the vector's members unchanged. Integers MUST reach it exact (a reader that turns `2^256−1` into a double
  is a defect of the adapter).
- An entry point that takes an **x402 payment payload** (`exact` scheme, EIP-3009) receives
  `authorization = {from, to, value, validAfter, validBefore, nonce}` from the message and `signature` unchanged,
  with one translation: a JSON integer becomes its decimal string, the wire form of x402; every other value
  (a fractional number, a boolean, a non-canonical string) is passed as it is, so that the verifier's own payload
  check sees it. The domain comes from the server's `PaymentRequirements` (`network = eip155:<chainId>`,
  `asset = verifyingContract`, `extra.name`, `extra.version`), not from the payer: a vector whose domain is not
  exactly those four members in a form a server could hold (chainId an integer of at most 32 digits, the CAIP-2
  reference length; `verifyingContract` matching `^0x[0-9a-fA-F]{40}$`; `name`, `version` strings), or whose types
  are not the six EIP-3009 members, is `not_applicable` there.
  The requirements' `payTo` is the message's `to` and `amount` is the value's integer when the value is a JSON
  integer or a string of ASCII digits (the price the server asked), else `"0"`.
- Off-chain only: the adapter supplies a signer that reports no code at the payer (an EOA), code at the asset, and
  successful contract calls, and pins the clock inside the authorization window. The verdict is therefore the
  verifier's OFF-CHAIN verdict; a deployed facilitator also simulates the transfer on chain, where the token
  contract checks the signature again.
- An entry point that receives an already-parsed object cannot see a repeated JSON member: vectors whose expected
  class is `json_ambiguous` are `not_applicable` for it (the runner marks them; the adapter's own reader decides
  which occurrence it keeps, not the verifier).

### 5.4 Comparing and classifying
For each applicable vector the runner records: **match** (same verdict, and same class when the adapter gives
one), **divergence** (different verdict, or `error`), **reason divergence** (both reject, adapter class given and
different). `not_applicable` and `not_reached` are counted and listed, never counted as matches. Every divergence
is classified in the results as exactly one of:

- **(a) finding about the verifier**: it breaks a rule of a standard or of the x402 specification, quoted with its
  source, on an input that reaches it through x402;
- **(b) defect of this suite** (vector, runner, adapter): corrected, with a test;
- **(c) rule of this suite only**: the verifier follows the standard and this suite is stricter (§2, `v` in
  {27, 28}, the domain members rule), or the input cannot reach the entry point through x402. Reported, not called a
  defect.

## 6. Versions of this document
1.0 (13 November 2026): first version, written against the runner at `cd434c0` and the 81 vectors of v1.4.0. A new
`origin`, a new class or a new value form is a new version, recorded here and in `CHANGELOG.md` together with the
schema change.
