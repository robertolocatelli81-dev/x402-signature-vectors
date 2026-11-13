# x402 signature conformance vectors

Byte-level test vectors for the **signature layer** of [x402](https://github.com/x402-foundation/x402):
EIP-712 typed-data digests and secp256k1 recovery for the `exact` scheme on EVM (EIP-3009, Permit2 witness
transfer, EIP-2612 permit). 84 JSON vectors — three of them from real x402 payments — each with the expected
verdict, the reason class of every reject and the intermediate hashes, checked by a runner that needs only the
Python standard library, and run through the official TypeScript and Python SDKs. Format and meaning of
"conforms": [`SPEC.md`](SPEC.md).

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

`tools/audit_spec_examples.py` recomputes every occurrence with the domain each example implies (a CI gate):

| occurrences | message as published | result |
|---|---|---|
| 7 (`scheme_exact_evm.md`, `x402-specification-v1.md`, `x402-specification-v2.md`, `transports-v1/{http,mcp}.md`, `transports-v2/{http,mcp}.md`) | EIP-3009 `TransferWithAuthorization`, Base Sepolia USDC | **valid**: recovers to the declared `0x857b0651…` |
| 3 (`scheme_exact_evm.md`, `eip2612_gas_sponsoring.md`, `erc20_gas_sponsoring.md`) | Permit2 `PermitWitnessTransferFrom` | **does not verify**: `0x468d6ad8…` |
| 1 (`eip2612_gas_sponsoring.md`) | EIP-2612 `Permit` | **does not verify**: `0xd259c196…` |
| 1 (`sign-in-with-x.md`) | the ERC-4361 string the document publishes, EIP-191 | **does not verify**: `0x5b2acbca…` |
| 3 (`transports-v1/a2a.md`, `transports-v2/a2a.md`, `scheme_upto_evm.md`) | placeholders (`0xServerWalletAddressHere`, `0xFacilitatorAddress…`) where an address is required | **not encodable** |

With `r`, `s` and `v` fixed, the recovered key is an injective function of the digest, so the five "does not
verify" verdicts hold for any domain or string one might assume instead. A developer who takes such an example as a
reference builds a verifier against a value that cannot verify, and concludes that their own implementation is
broken. Every case, with document, line and pinned commit: [`audit/SPEC_EXAMPLES_AUDIT.md`](audit/SPEC_EXAMPLES_AUDIT.md).

## The official SDKs on the vectors

The vectors run through `@x402/evm` 2.31.0 (npm) and `x402` 2.28.0 (PyPI), both released from `07c4caf`, the parent
of `2178d4b`, on two entry points each: the SDK's typed-data signature check and the exact facilitator's `verify()`
on EIP-3009 payloads, off chain (no RPC; the token contract's own on-chain check is not part of the measure).

| SDK / entry | match | divergence | not applicable | not reached |
|---|---|---|---|---|
| TypeScript typed-data | 76 | 7 | 1 | 0 |
| TypeScript facilitator | 47 | 2 | 31 | 4 |
| Python typed-data | 75 | 8 | 1 | 0 |
| Python facilitator | 49 | 2 | 31 | 2 |

All 19 divergences are on rules of this suite that the standards leave open, or on inputs that cannot reach that
entry through x402: both SDKs accept a raw recovery id `v` = 0 and normalise it before the chain, and both
facilitators read `"010000"` as 10000. On these 84 inputs no SDK produced a signature verdict that breaks EIP-712,
EIP-2, EIP-3009 or the x402 text on an input that can reach that entry through x402; the two typed-data entries do
depart from EIP-712 on inputs no x402 `exact` payload can carry (074, a `uint256[2]` with three elements, accepted by
both; 080, a caller-supplied `EIP712Domain` with `string chainId`, accepted by Python). What the run did find is in
the reason codes:

- on the 18 vectors it rejects for their EIP-3009 signature, the TypeScript facilitator answers
  `invalid_exact_evm_signature`, a code that `x402-specification-v2.md` §9 does not list; for that condition §9 lists
  `invalid_exact_evm_payload_signature`, which the Python facilitator returns on 14 of the 18 (on the other four it
  answers with codes that are not in the list either). §9 says its codes "may be returned" and that clients matching
  an error condition "MUST use" the `invalidReason` code, not the message text, so a client written against the
  listed code does not recognise the TypeScript answer;
- with an empty EIP-712 domain `name` or `version`, the TypeScript facilitator refuses the payment as missing its
  domain and the Python facilitator accepts it;
- the Python facilitator reports a 0-, 64- or 66-byte signature from an address with no code as an undeployed smart
  wallet.

Commands, versions, the entry points called, every divergence with its file and line, and the per-vector table:
[`audit/SDK_RESULTS.md`](audit/SDK_RESULTS.md). The CI job `sdk` re-runs it on every push.

## Signatures from real payments

Vectors 082–084 are three x402 payments settled on Base Sepolia by the signer that the SDKs' default facilitator
(`https://x402.org/facilitator`) publishes, each a successful `transferWithAuthorization` call to USDC from a
different payer. The message and the signature come from the calldata alone; the domain comes from the contract,
and the separator the suite computes equals the contract's `DOMAIN_SEPARATOR()` — the same separator the
generated vectors have used since 003 for the domain the specification leaves unstated. All three verify with
`verify.py`, with `coincurve` and with the four SDK entries; `eth-account` computes the same digests. Transaction hashes, blocks and derivation:
[`audit/onchain_sources.json`](audit/onchain_sources.json), rebuilt offline in CI and re-read from any public node
with `python3 tools/genera_vettori_onchain.py --verifica https://sepolia.base.org`.

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
its reject class and, where it fails, the intermediate hashes in `expected` (see [Vector format](#vector-format));
[`SPEC.md`](SPEC.md) §5 defines the levels of conformance and the input/output contract of an adapter, with the two
SDK adapters in `tools/adapters/` as examples.
The other gates (`tools/check_manifest.py`, `check_schema.py`, `check_docs.py`, `audit_spec_examples.py`,
`fuzz_runner.py`, …) run the same way; [`conformance.yml`](.github/workflows/conformance.yml) lists them all.

## Evidence

- **CI**: [`conformance.yml`](.github/workflows/conformance.yml) runs on every push, every pull request and every
  Monday, in four jobs: `verify` (stdlib only), `positive-control` (the gates against 18 sabotages),
  `crossvalidate` (with the reference libraries) and `sdk` (the two official SDKs, pinned). All four passed on the
  v1.5.0 tag (run 43433049744, 13 November 2026, commit `ec53f20`).
- **Releases**: [v1.5.0](https://github.com/robertolocatelli81-dev/x402-signature-vectors/releases/tag/v1.5.0)
  (tag on `ec53f20`, 13 November 2026; changes in [`CHANGELOG.md`](CHANGELOG.md)) and
  [v1.4.0](https://github.com/robertolocatelli81-dev/x402-signature-vectors/releases/tag/v1.4.0) (tag on `985b46d`,
  12 November 2026). Each GitHub release carries the tarball made by `git archive --format=tar.gz` of its tag and
  its `SHA256SUMS`.
- **Archive**: Zenodo, concept DOI [10.5281/zenodo.24172853](https://doi.org/10.5281/zenodo.24172853) (resolves to
  the latest version), v1.5.0 DOI [10.5281/zenodo.24199019](https://doi.org/10.5281/zenodo.24199019), v1.4.0 DOI
  [10.5281/zenodo.24172854](https://doi.org/10.5281/zenodo.24172854). Citation
  metadata: [`CITATION.cff`](CITATION.cff).
- **Cross-validation of `lib/`** (Keccak-256, EIP-712 and secp256k1 written here in the standard library), against
  reference libraries that the suite itself does not depend on:

| test | result |
|---|---|
| **EIP-712 encoding vs `eth-account` 0.14.0** (`tools/crossvalidate_eip712.py`) | 57 vectors compared (the 27 whose message is not encodable by construction are skipped), **0 divergences**: arrays, nesting, NUL byte, partial domains, signed integers, dynamic bytes, undeclared fields and canonical decimal strings included |
| **Primitives vs `coincurve`/libsecp256k1 and `eth-hash`** (`tools/crossvalidate.py`) | 2000 Keccak inputs, 500 signatures produced *by* libsecp256k1, 600 degenerate inputs checked for matching **rejections**, all 84 vectors re-verified with `coincurve`: 0 divergences |
| **Reproducibility** | the five `tools/genera_vettori*.py` regenerate all 84 vectors **byte-identical** to the committed ones |
| **The gates can fail** (`tools/positive_control.py`) | 15 sabotages of `lib/`, `verify.py` and the runner (Keccak padding, low-s removed or off by one, domain without `version`, unsorted `encodeType`, raw `v`, `r` = 0, lax JSON reader, array length, NUL, point at infinity, signer case, class / address / schema / intermediate-value comparison off, NaN read as a number, a struct named `string`): **18 caught**, each changing behaviour on a batch that is not the vectors ([`audit/POSITIVE_CONTROL.md`](audit/POSITIVE_CONTROL.md)) |
| **Hostile input** (`tools/fuzz_runner.py`) | 600 malformed vectors → 600 rejected, 0 unhandled exceptions; 10 non-object payloads → 10 `input_not_object`; strict value forms, 20 admitted + 44 not admitted → 0 wrong; `NaN`/`Infinity` and struct names spelled like atomic types, 16 cases → 0 wrong |

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
`hash_struct` and `signing_digest` alongside the verdict, and the runner checks all four against its own
computation. An implementation that fails learns *which* layer failed — the EIP-712 encoding or the ECDSA recovery — instead of just "does not verify".

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

`origin` separates three statuses that must not be mixed:

- **`spec`** — payload and signature taken verbatim from the x402 specifications. The expected verdict
  is the audit result, whatever it is.
- **`generated`** — signed here with the test key below, so that a valid vector exists even where the
  spec offers none.
- **`onchain`** — taken from the calldata of a real x402 payment (082–084, see
  [Signatures from real payments](#signatures-from-real-payments)).

```
test private key  0x4646…4646   (published on purpose: a conformance vector must hold no secrets)
test address      0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f
```

Current set: **84 vectors — 34 `accept`, 50 `reject`** (v1.5.0), against
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
- **Spec-derived vectors** (001, 002) and the audit reflect the x402 documents at `2178d4b` (13 November 2026); the
  upstream examples can change after that commit.
- **SDK results** are off-chain verdicts of the pinned releases on these vectors, not a security assessment of the
  SDKs; the Go and Java SDKs were not run.
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
