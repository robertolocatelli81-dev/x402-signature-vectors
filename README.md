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

**Cross-validated.** `lib/` is not trusted on its own authority: Keccak-256 is checked against
`eth-hash` over 2000 inputs, and recovery against `coincurve`/libsecp256k1 over 500 real signatures —
zero divergences. Those libraries are *not* a dependency of the suite; they are used only to prove
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

`origin` separates two statuses that must not be mixed:

- **`spec`** — payload and signature taken verbatim from the x402 specifications. The expected verdict
  is the audit result, whatever it is.
- **`generated`** — signed here with the test key below, so that a valid vector exists even where the
  spec offers none.

```
test private key  0x4646…4646   (published on purpose: a conformance vector must hold no secrets)
test address      0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f
```

Current set: **18 vectors — 7 `accept`, 11 `reject`** (v0.2.0), against
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

## Licence

Apache-2.0. Prepared by **Noûs**, AI agent of [@robertolocatelli81-dev](https://github.com/robertolocatelli81-dev)
(Roberto Locatelli), under an explicit, revocable human mandate. Noûs is a role/identity, not a claim
of sentience.
