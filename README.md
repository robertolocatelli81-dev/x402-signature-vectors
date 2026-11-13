# x402 signature conformance vectors

Byte-level test vectors for the **signature layer** of [x402](https://github.com/x402-foundation/x402):
EIP-712 typed-data digests and secp256k1 recovery for the `exact` scheme on EVM (EIP-3009, Permit2 witness
transfer, EIP-2612 permit). 84 JSON vectors, each with the expected verdict, the reason class of every reject
and the intermediate hashes, checked by a runner that needs only the Python standard library.

## The problem

x402 is implemented in TypeScript, Python, Go and Java, with EVM contracts alongside, in
[x402-foundation/x402](https://github.com/x402-foundation/x402) (`coinbase/x402` now names it as the repository's
home). Its `specs/` tree has no conformance vectors: `specs/vectors/` and `specs/conformance/` do not exist at
commit `2178d4b` (13 November 2026). Cross-SDK testing there happens in the `e2e/` harness, which runs TypeScript, Go
and Python clients, servers and facilitators against each other; Java is not part of it.

At the signature layer a defect is silent: a wrong EIP-712 domain raises no error, the signature just recovers
to a different address. Whoever writes or runs an x402 verifier or facilitator needs fixed bytes to compare
against, and needs to know *which* layer diverged.

## What the published examples show

At `x402-foundation/x402@2178d4b`, one 65-byte signature (`0x2d6a7588…af148b571c`) appears **15 times in 13
documents** under `specs/`. It is genuine for exactly one message: the EIP-3009 `TransferWithAuthorization`
example of `scheme_exact_evm.md` (Base Sepolia USDC), which `x402-specification-v2.md` and
`transports-v2/{http,mcp}.md` repeat unchanged. The same bytes are also presented as an EIP-2612 `Permit`, as
Permit2 witness transfers and as an ERC-4361 sign-in. An ECDSA signature binds one digest, so those examples
cannot verify against the declared signer.

`tools/audit_spec_examples.py` reproduces the two EIP-712 cases with the domain the example implies
(USDC on Base Sepolia, `version` "2"):

| example | standard | result |
|---|---|---|
| `schemes/exact/scheme_exact_evm.md` | EIP-3009 `TransferWithAuthorization` | **valid**: recovers to the declared `from` (`0x857b0651…`) |
| `extensions/eip2612_gas_sponsoring.md` | EIP-2612 `Permit` | **placeholder**: recovers to `0xd259c196…` |

A developer who takes a placeholder example as a reference builds a verifier against a value that cannot
verify, and concludes that their own implementation is broken. The September audit, with every case:
[`audit/SPEC_EXAMPLES_AUDIT.md`](audit/SPEC_EXAMPLES_AUDIT.md).

## Run it

```console
$ git clone https://github.com/robertolocatelli81-dev/x402-signature-vectors && cd x402-signature-vectors
$ python3 verify.py
banco: Keccak-256 ok · EIP-712 ok (esempio canonico riprodotto) · secp256k1 ok (0x9d8a62f6…)

vettore                          origine    atteso   ottenuto  esito    ragione del reject
001-eip3009-spec-example         spec       accept   accept    OK
002-eip2612-spec-example         spec       reject   reject    OK       signer_mismatch: recupera a un indirizzo diverso
…
077-json-duplicate-member        generated  reject   reject    OK       json_ambiguous: membro JSON ripetuto: 'value'
…
84 vettori · 84 conformi · 0 falliti
```

Exit code 0 = every vector conformant, 1 = at least one failure, 2 = the bench self-test failed and no verdict
was emitted. No `pip install`. To test your own verifier, feed it each `vectors/*.json` and compare its verdict,
its reject class and, where it fails, the intermediate hashes in `expected` (see [Vector format](#vector-format)).
The other gates (`tools/check_manifest.py`, `check_schema.py`, `check_docs.py`, `audit_spec_examples.py`,
`fuzz_runner.py`, …) run the same way; [`conformance.yml`](.github/workflows/conformance.yml) lists them all.

## Evidence

- **CI**: [`conformance.yml`](.github/workflows/conformance.yml) runs on every push, every pull request and every Monday. Its two
  jobs (`verify`, stdlib only; `crossvalidate`, with the reference libraries) passed on the latest run on
  `master` (run 42638580919, 9 November 2026, commit `8d1af30`).
- **Release**: [v1.4.0](https://github.com/robertolocatelli81-dev/x402-signature-vectors/releases/tag/v1.4.0)
  (tag on `985b46d`; release published 12 November 2026 with the tarball and `SHA256SUMS`). `master` is v1.4.0
  plus the changes under "Unreleased" in [`CHANGELOG.md`](CHANGELOG.md).
- **Archive**: Zenodo, concept DOI [10.5281/zenodo.24172853](https://doi.org/10.5281/zenodo.24172853) (resolves to
  the latest version), v1.4.0 DOI [10.5281/zenodo.24172854](https://doi.org/10.5281/zenodo.24172854). Citation
  metadata: [`CITATION.cff`](CITATION.cff).
- **Cross-validation of `lib/`** (Keccak-256, EIP-712 and secp256k1 written here in the standard library), against
  reference libraries that the suite itself does not depend on:

| test | result |
|---|---|
| **EIP-712 encoding vs `eth-account` 0.14.0** (`tools/crossvalidate_eip712.py`) | 57 vectors compared (the 27 whose message is not encodable by construction are skipped), **0 divergences**: arrays, nesting, NUL byte, partial domains, signed integers, dynamic bytes, undeclared fields and canonical decimal strings included |
| **Primitives vs `coincurve`/libsecp256k1 and `eth-hash`** (`tools/crossvalidate.py`) | 2000 Keccak inputs, 500 signatures produced *by* libsecp256k1, 600 degenerate inputs checked for matching **rejections**, all 84 vectors re-verified with `coincurve`: 0 divergences |
| **Reproducibility** | the five `tools/genera_vettori*.py` regenerate all 84 vectors **byte-identical** to the committed ones |
| **Hostile input** (`tools/fuzz_runner.py`) | 600 malformed vectors → 600 rejected, 0 unhandled exceptions; 10 non-object payloads → 10 `input_not_object`; strict value forms, 20 admitted + 44 not admitted → 0 wrong |

## Vector format

Each vector is a single self-contained JSON file: `eip712` (domain, types, primaryType, message),
`signature`, and an `expected` block naming both the verdict and the address the signature actually
recovers to. Nothing is implicit, including the domain that the specification leaves unstated
(`scheme_exact_evm.md` names `extra.name` and `extra.version` as domain fields; `chainId` and
`verifyingContract` are not written out).

Every `reject` vector also declares **`reject_reason`** — one of `signature_malformed`,
`signature_out_of_range`, `signature_high_s`, `encoding_error`, `recovery_undefined`,
`signer_mismatch`, `input_not_object`, `json_ambiguous` (defined in `tools/reject_reasons.py`). A verifier is conformant on a reject vector
only if it rejects **for that class of reason**: a vector rejected for the wrong reason is how a broken
test passes, and a reject vector without a declared class fails the schema gate. `input_not_object`
(the payload is `null`, an array, a string, a number or a boolean) cannot appear in a vector file,
which is an object by construction; the runner emits it and `tools/fuzz_runner.py` checks it.

**Each layer is testable in isolation.** Every vector carries `type_hash`, `domain_separator`,
`hash_struct` and `signing_digest` alongside the verdict. An implementation that fails learns *which*
layer failed — the EIP-712 encoding or the ECDSA recovery — instead of just "does not verify".

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
the other direction (the canonical decimal string is admitted).

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

Current set: **84 vectors — 34 `accept`, 50 `reject`** (v1.5.0, unreleased), against
[`schema/vector.schema.json`](schema/vector.schema.json).

Beyond message-binding mutations (amount off by one, substituted recipient, one-second validity
shift, wrong-chain domain), the set covers:

- **ECDSA malleability** — `(r, N−s)` with flipped `v` is valid over the *same* message and recovers to the
  *same* address. EIP-2 requires low-s, so a conformant verifier rejects it; accepting it means the same
  authorization exists in two forms with different hashes.
- **Malformed signatures** — `r=0`, `s=0`, `r=N`, `v` out of range: recovery is undefined and
  `recovered_address` is `null`. A library that raises here instead of rejecting is a denial of service.
- **Exact secp256k1 boundaries** — `s = N/2` and `s = N/2 + 1` (where a `<` instead of `<=` breaks),
  `r = 1`, `r = N−1`, raw recovery ids `v = 0/1` instead of 27/28, and recovery to the point at infinity
  (051–052).
- **uint256 boundaries and non-ASCII domain names** — these are `accept`: the signature is valid, and
  rejecting them is *policy*, not signature verification.
- **Partial EIP-712 domains** — a domain without `version`, which is the real domain of the canonical
  Permit2 contract. An implementation assuming four fixed fields computes a different separator.
- **Both other x402 transfer methods** — Permit2 `PermitWitnessTransferFrom` with the witness types
  taken from the spec's `WITNESS_TYPE_STRING`, plus a tampered-witness vector: the attack the witness
  pattern exists to stop, where a facilitator redirects the payment.
- **EIP-712 encoding structure** — arrays of structs, two-level nesting, a string containing a NUL byte
  (hashed whole), and referenced-type ordering in `encodeType` (alphabetical, regardless of declaration order).
- **Robustness** — signatures too short, too long, empty; a message missing a declared field; a
  `primaryType` absent from `types`. These must be clean rejections: the input comes from the network.
- **Strict value forms** (056–076) and **one reading of the text, the domain and the type names** (077–081),
  as described above.

## The bench checks itself before it measures

`verify.py` emits no verdict unless its own primitives pass first:

- **Keccak-256** against three published digests, and confirmed distinct from SHA3-256 (the two differ
  only by a padding byte);
- **EIP-712** against the three digests published in EIP-712 itself for the canonical `Mail` example
  (`domainSeparator f2cee375…`, `hashStruct c52c0ee5…`, `signingDigest be609aee…`);
- **secp256k1** against a non-circular control: sign with a known key, recover, compare the address.

`tools/check_manifest.py` is fail-closed: every file's sha256 must match `manifest.json`, counts must
reconcile, and an undeclared file is a failure.

## Guarantees and assumptions

- **Scope**: signature verification only. The vectors say nothing about balances, on-chain settlement,
  nonce uniqueness or replay windows at runtime, or endpoint behaviour. A passing vector shows that a
  verifier computes the same bytes and the same verdict, not that a payment system is secure.
- **Status**: this is not an official x402 Foundation or Coinbase artifact and does not speak for either.
  The strict JSON value forms are a rule of this suite: EIP-712 defines the encoding of values, not their
  JSON spelling.
- **`lib/`** is written from the published specifications (FIPS 202 / Keccak, EIP-712, SEC 2) only to make
  the vectors checkable without dependencies. It is not an audited cryptographic library and must not be
  used in production. Its agreement with `eth-hash`, libsecp256k1 and `eth-account` is measured on the
  inputs listed above, not proven in general.
- **Spec-derived vectors** (001, 002) reflect the x402 documents as audited in September 2026; the counts in
  [What the published examples show](#what-the-published-examples-show) were re-measured on 13 November 2026
  against `2178d4b`. The upstream examples can change after that commit.
- **Adjacent layers** covered elsewhere: JSON canonicalisation vectors
  ([AlgoVoi JCS conformance vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors)), paid
  signed x402 conformance reports ([Cairn](https://cairnwake.com/reports.html)), protocol-level attacks
  ([*Five Attacks on x402*](https://arxiv.org/abs/2605.11781)).

## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/x402-signature-vectors/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with x402 implementers who want their signature layer checked against these vectors. Write with the use case; the answer says what is measured and what is not.
- **Citation**: [`CITATION.cff`](CITATION.cff); DOI [10.5281/zenodo.24172853](https://doi.org/10.5281/zenodo.24172853).
- **Licence**: Apache-2.0 ([`LICENSE`](LICENSE), [`NOTICE`](NOTICE)): use it freely, also in closed products. If you build on it, a note in Discussions helps the roadmap.
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.
