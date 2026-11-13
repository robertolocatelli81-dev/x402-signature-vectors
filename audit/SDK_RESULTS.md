# The vectors through two official x402 SDKs

**Measured:** 13 November 2026. **Upstream:** `x402-foundation/x402` at `2178d4b` (13 November 2026, 08:22 UTC).
**SDKs:** npm `@x402/evm` 2.31.0 with `@x402/core` 2.31.0 and `viem` 2.57.19 (lockfile
[`tools/adapters/typescript/package-lock.json`](../tools/adapters/typescript/package-lock.json), installed with
`npm ci`); PyPI `x402` 2.28.0 with `eth-account` 0.14.0 and `eth-keys` 0.8.0
([`tools/adapters/python/requirements.txt`](../tools/adapters/python/requirements.txt)). Both releases carry the tags
`npm-@x402/evm@v2.31.0` and `pypi-x402@v2.28.0`, on commit `07c4caf`, the parent of `2178d4b`; `07c4caf..2178d4b`
changes `go/` only. The 257 `.py` files of the installed `x402` wheel are byte-identical to `python/x402` at
`2178d4b`; the npm package was installed as published, not rebuilt from source.
**Not run:** the Go SDK (no Go toolchain on the measuring machine) and the Java SDK.

Raw results, one line per vector and entry point: [`sdk_results.json`](sdk_results.json). Format and rules of the
comparison: [`SPEC.md`](../SPEC.md) §5.

## What was called

| SDK | entry | the SDK's own code that decides |
|---|---|---|
| TypeScript | `typed-data` | `isPlainNonCanonicalEcdsaSignature(sig, false)` (the low-s gate of the exact facilitator), then `verifyTypedDataSignature` (`src/shared/verifySignature.ts`: viem `hashTypedData`, then ecrecover for an address with no code) |
| TypeScript | `facilitator-exact` | `new ExactEvmScheme(signer).verify(payload, requirements)` from `@x402/evm/exact/facilitator`, EIP-3009 payloads |
| Python | `typed-data` | `is_plain_non_canonical_ecdsa_signature(sig, False)`, then `verify_typed_data_strict` (`mechanisms/evm/verify.py`: eth-account `encode_typed_data`, then eth-keys recovery) |
| Python | `facilitator-exact` | `ExactEvmScheme(signer).verify(payload, requirements)` from `x402.mechanisms.evm.exact.facilitator`, EIP-3009 payloads |

Off-chain only (SPEC.md §5.3): the signer given to the SDK reports no code at the payer, code at the asset, and
answers every contract call successfully; the clock is pinned at `validAfter`. The verdicts are the SDKs'
OFF-CHAIN verdicts: a deployed facilitator also simulates `transferWithAuthorization` on chain, where the token
contract checks the signature again. The typed-data entries are boolean APIs: only the verdict (and `signature_high_s`,
which has its own gate) can be compared; the facilitator entries return a reason code, compared where it maps one
to one to a class of this suite.

## Commands

```console
$ npm ci --ignore-scripts --prefix tools/adapters/typescript
$ python3 -m venv /tmp/x402py && /tmp/x402py/bin/pip install -r tools/adapters/python/requirements.txt
$ export X402_TS_ENV=tools/adapters/typescript X402_PY=/tmp/x402py/bin/python
$ python3 tools/test_sdk_adapters.py     # the adapters' own test (known answers, closed lines)
$ python3 tools/run_sdk_adapters.py      # exit 1 if the results differ from audit/sdk_results.json
```

Measured locally with Node 22.23.2 and Python 3.11.2; the `sdk` job of `conformance.yml` runs the same commands
with Node 24 and Python 3.11.

## Summary

| SDK / entry | match | divergence | not applicable | not reached |
|---|---|---|---|---|
| typescript/typed-data | 76 | 7 | 1 | 0 |
| typescript/facilitator-exact | 47 | 2 | 31 | 4 |
| python/typed-data | 75 | 8 | 1 | 0 |
| python/facilitator-exact | 49 | 2 | 31 | 2 |

The three real-payment vectors (082–084, signatures that settled x402 payments on Base Sepolia, see the README)
are accepted by all four entries. No entry raised an exception on any vector, and no reject class disagreed where a class was reported. **Every
divergence is of class (c)**: the SDK follows the standard and this suite is stricter, or the input cannot reach
that entry through x402. None of the 84 vectors produced a signature verdict that breaks EIP-712, EIP-2, EIP-3009 or
the x402 text at an entry reachable through x402. That says what these 84 inputs show; it is not a proof that the
SDKs have no signature defect.

Not applicable: 077 on every entry (a repeated JSON member cannot reach an entry that takes a parsed object); on
the facilitator entries also the 30 vectors that are not EIP-3009 messages with a server-held domain (Permit,
Permit2, structural EIP-712 cases, malformed domains). Not reached: 012 and 045 (inverted or degenerate validity
window, `invalid_exact_evm_payload_authorization_valid_before`) on both facilitators; 033 and 034 on the TypeScript
facilitator only (see finding 2).

## Divergences, classified

| vectors | SDK / entry | what happened | class and reason |
|---|---|---|---|
| 028 | all four | `v` = 0 (raw recovery id) accepted | (c) this suite requires `v` in {27, 28}. Both SDKs accept 0/1 on purpose and normalise before the chain: Python `exact/eip3009_utils.py:463-464`, `verify.py:49-50`; TypeScript `exact/facilitator/eip3009-utils.ts:130,333`. The x402 text says only "the 65-byte signature" (`scheme_exact_evm.md:29`). |
| 063 | all four | `value` "010000" accepted as 10000 | (c) this suite admits one decimal spelling per integer; reachable through x402 (`types.ts:87` `/^[0-9]{1,78}$/`, `types.py:9` `[0-9]{1,78}`); the x402 text states no canonical decimal form. |
| 060, 062, 064 | TypeScript typed-data | whitespace, `+`, `true` as a `uint256` accepted | (c) suite value forms; the TypeScript facilitator rejects all three with `invalid_exact_evm_payload` (measured). |
| 059–062 | Python typed-data | non-ASCII digits, whitespace, `_`, `+` accepted | (c) suite value forms; the Python facilitator rejects all four with `invalid_exact_evm_payload` (measured). |
| 074 | both typed-data | 3 elements for `uint256[2]` accepted | (c) EIP-712 types `T[k]` as k elements; no x402 exact message has an array member. |
| 078 | TypeScript typed-data | domain member `chainID` ignored | (c) suite domain rule; the facilitator builds the domain from `PaymentRequirements`. |
| 080 | Python typed-data | `types.EIP712Domain` with `string chainId` used as given | (c) EIP-712 defines `uint256 chainId`; `verify.py:221-224` lets the caller's `EIP712Domain` replace the derived one; every caller in the SDK passes SDK constants. |

The same table is the closed list `tools/sdk_divergences.py`: the runner fails on a divergence without an entry and
on an entry without a divergence.

## Findings about the SDKs

1. **The TypeScript facilitator reports a bad EIP-3009 signature with a code the x402 specification does not
   define.** `x402-specification-v2.md` §9 (line 601) lists `invalid_exact_evm_payload_signature` — "Payment
   authorization signature is invalid or improperly signed" — and says "When matching specific error conditions,
   clients MUST use the corresponding `invalidReason` or `errorReason` code". `@x402/evm` returns
   `invalid_exact_evm_signature` (`exact/facilitator/errors.ts:15`, returned at `eip3009.ts:237`): measured on 18
   vectors (005–008, 013–016, 023, 025–027, 029, 046–048, 051, 052). The Python facilitator returns the specified
   code (on 14 of those 18; on the other four it answers with the codes of finding 3 and
   `invalid_exact_evm_failed_to_verify_signature` for 015). A client that matches the specified code never matches the TypeScript
   facilitator's answer. Read, not run: the Go v2 facilitator defines the same non-specified string
   (`go/mechanisms/evm/exact/facilitator/errors.go:24`).
2. **The two facilitators disagree on an empty EIP-712 domain name or version.** With `extra.name` = "" (033) or
   `extra.version` = "" (034), the TypeScript facilitator answers `invalid_exact_evm_missing_eip712_domain`
   (`eip3009.ts:102`, `!requirements.extra?.name || !requirements.extra?.version`) and the Python facilitator
   verifies the signature and accepts (`exact/facilitator.py:232`, `"name" not in extra`). `scheme_exact_evm.md:72-73`
   calls both fields "required" and does not say whether an empty string satisfies it; EIP-712 allows an empty
   string. The same signed payment is valid in one official SDK and refused in the other.
3. **The Python facilitator reports a wrong-length signature from an address with no code as an undeployed smart
   wallet.** On 046–048 (64, 66 and 0 bytes, payer without code) it answers
   `invalid_exact_evm_payload_undeployed_smart_wallet` (`exact/eip3009_utils.py:125`: any signature whose length is
   not 65 is classed as a smart-wallet signature); the TypeScript facilitator answers `invalid_exact_evm_signature`.
   Both reject; the Python reason names a cause the input does not have.

## Defects of this suite found while building the adapters (class b), corrected before they were committed

- The TypeScript adapter read vectors with `JSON.parse`, which turns integers above 2^53 into doubles: the
  typed-data entry rejected 004, 011, 031 and 041, judged on values the vectors do not carry. Corrected with a
  reader that keeps integer literals exact (`readVector`).
- The Python adapter put a fractional `value` (056) and a boolean (064) into the server's `PaymentRequirements.amount`,
  which the SDK's model refuses: the adapter raised instead of letting the SDK judge the payload. Corrected: the
  requirements carry the price a server would hold (SPEC.md §5.3).
- The TypeScript facilitator raised `InvalidAddressError` on 067 because the adapter passed a malformed
  `verifyingContract` as the server's asset. Corrected: a domain no server can hold is not applicable there.

`tools/test_sdk_adapters.py` holds a known answer for each: on a copy with the first two defects put back it
fails on 004, 011, 031, 041 and 056 (measured).

## Per vector

Cells: the SDK's verdict, with the class when it reported one; **bold** = divergence, with its class.

| vector | expected | TS typed-data | TS facilitator | Py typed-data | Py facilitator |
|---|---|---|---|---|---|
| 001-eip3009-spec-example | accept | accept | accept | accept | accept |
| 002-eip2612-spec-example | reject `signer_mismatch` | reject | n/a | reject | n/a |
| 003-eip3009-generated-valid | accept | accept | accept | accept | accept |
| 004-eip2612-generated-valid | accept | accept | n/a | accept | n/a |
| 005-mutated-value | reject `signer_mismatch` | reject | reject | reject | reject |
| 006-mutated-to | reject `signer_mismatch` | reject | reject | reject | reject |
| 007-mutated-valid-before | reject `signer_mismatch` | reject | reject | reject | reject |
| 008-wrong-domain-chainid | reject `signer_mismatch` | reject | reject | reject | reject |
| 009-ecdsa-malleability-high-s | reject `signature_high_s` | reject `signature_high_s` | reject `signature_high_s` | reject `signature_high_s` | reject `signature_high_s` |
| 010-value-zero | accept | accept | accept | accept | accept |
| 011-value-max-uint256 | accept | accept | accept | accept | accept |
| 012-window-inverted | accept | accept | not reached | accept | not reached |
| 013-signature-r-zero | reject `signature_out_of_range` | reject | reject | reject | reject |
| 014-signature-s-zero | reject `signature_out_of_range` | reject | reject | reject | reject |
| 015-signature-v-out-of-range | reject `signature_malformed` | reject | reject | reject | reject |
| 016-signature-r-equals-n | reject `signature_out_of_range` | reject | reject | reject | reject |
| 017-domain-name-non-ascii | accept | accept | accept | accept | accept |
| 018-recipient-zero-address | accept | accept | accept | accept | accept |
| 019-eip712-array-of-structs | accept | accept | n/a | accept | n/a |
| 020-eip712-nested-structs | accept | accept | n/a | accept | n/a |
| 021-eip712-string-null-byte | accept | accept | n/a | accept | n/a |
| 022-eip712-type-ordering | accept | accept | n/a | accept | n/a |
| 023-s-exactly-half-n | reject `signer_mismatch` | reject | reject | reject | reject |
| 024-s-just-above-half-n | reject `signature_high_s` | reject `signature_high_s` | reject `signature_high_s` | reject `signature_high_s` | reject `signature_high_s` |
| 025-s-equals-one | reject `signer_mismatch` | reject | reject | reject | reject |
| 026-r-equals-one | reject `signer_mismatch` | reject | reject | reject | reject |
| 027-r-equals-n-minus-one | reject `recovery_undefined` | reject | reject | reject | reject |
| 028-v-raw-zero | reject `signature_malformed` | **accept** (c) | **accept** (c) | **accept** (c) | **accept** (c) |
| 029-v-raw-one | reject `signature_malformed` | reject | reject | reject | reject |
| 030-domain-chainid-zero | accept | accept | accept | accept | accept |
| 031-domain-chainid-max | accept | accept | n/a | accept | n/a |
| 032-domain-verifying-contract-zero | accept | accept | accept | accept | accept |
| 033-domain-empty-name | accept | accept | not reached | accept | accept |
| 034-domain-empty-version | accept | accept | not reached | accept | accept |
| 035-domain-without-version | accept | accept | n/a | accept | n/a |
| 036-array-empty | accept | accept | n/a | accept | n/a |
| 037-array-single | accept | accept | n/a | accept | n/a |
| 038-types-bool-true | accept | accept | n/a | accept | n/a |
| 039-types-bool-false | accept | accept | n/a | accept | n/a |
| 040-address-lowercase-vs-checksum | accept | accept | accept | accept | accept |
| 041-permit2-witness-transfer | accept | accept | n/a | accept | n/a |
| 042-permit2-witness-tampered | reject `signer_mismatch` | reject | n/a | reject | n/a |
| 043-nonce-all-zero | accept | accept | accept | accept | accept |
| 044-nonce-all-ff | accept | accept | accept | accept | accept |
| 045-validity-window-degenerate | accept | accept | not reached | accept | not reached |
| 046-signature-too-short | reject `signature_malformed` | reject | reject | reject | reject |
| 047-signature-too-long | reject `signature_malformed` | reject | reject | reject | reject |
| 048-signature-empty | reject `signature_malformed` | reject | reject | reject | reject |
| 049-message-missing-field | reject `encoding_error` | reject | reject | reject | reject |
| 050-primary-type-not-in-types | reject `encoding_error` | reject | n/a | reject | n/a |
| 051-recovery-point-at-infinity-address-zero | reject `recovery_undefined` | reject | reject | reject | reject |
| 052-recovery-point-at-infinity-zero-point-address | reject `recovery_undefined` | reject | reject | reject | reject |
| 053-int256-negative-minimum | accept | accept | n/a | accept | n/a |
| 054-bytes-dynamic | accept | accept | n/a | accept | n/a |
| 055-undeclared-field-ignored | accept | accept | n/a | accept | n/a |
| 056-uint-float-fraction | reject `encoding_error` | reject | reject | reject | reject |
| 057-uint-float-timestamp | reject `encoding_error` | reject | reject | reject | reject |
| 058-domain-chainid-float | reject `encoding_error` | reject | n/a | reject | n/a |
| 059-uint-string-unicode-digits | reject `encoding_error` | reject | reject | **accept** (c) | reject |
| 060-uint-string-whitespace | reject `encoding_error` | **accept** (c) | reject | **accept** (c) | reject |
| 061-uint-string-underscore | reject `encoding_error` | reject | reject | **accept** (c) | reject |
| 062-uint-string-plus-sign | reject `encoding_error` | **accept** (c) | reject | **accept** (c) | reject |
| 063-uint-string-leading-zero | reject `encoding_error` | **accept** (c) | **accept** (c) | **accept** (c) | **accept** (c) |
| 064-uint-bool | reject `encoding_error` | **accept** (c) | reject | reject | reject |
| 065-address-bad-prefix | reject `encoding_error` | reject | reject | reject | reject |
| 066-address-trailing-whitespace | reject `encoding_error` | reject | reject | reject | reject |
| 067-domain-verifying-contract-bad-prefix | reject `encoding_error` | reject | n/a | reject | n/a |
| 068-bytes32-internal-whitespace | reject `encoding_error` | reject | reject | reject | reject |
| 069-bytes32-bad-prefix | reject `encoding_error` | reject | reject | reject | reject |
| 070-bytes-internal-whitespace | reject `encoding_error` | reject | n/a | reject | n/a |
| 071-domain-version-integer | reject `encoding_error` | reject | n/a | reject | n/a |
| 072-bool-as-string-false | reject `encoding_error` | reject | n/a | reject | n/a |
| 073-array-given-as-string | reject `encoding_error` | reject | n/a | reject | n/a |
| 074-array-fixed-length-mismatch | reject `encoding_error` | **accept** (c) | n/a | **accept** (c) | n/a |
| 075-uint-width-not-multiple-of-8 | reject `encoding_error` | reject | n/a | reject | n/a |
| 076-uint-decimal-string-accepted | accept | accept | accept | accept | accept |
| 077-json-duplicate-member | reject `json_ambiguous` | n/a | n/a | n/a | n/a |
| 078-domain-unknown-member | reject `encoding_error` | **accept** (c) | n/a | reject | n/a |
| 079-domain-types-inconsistent | reject `encoding_error` | reject | n/a | reject | n/a |
| 080-domain-chainid-declared-string | reject `encoding_error` | reject | n/a | **accept** (c) | n/a |
| 081-struct-named-like-atomic-type | reject `encoding_error` | reject | n/a | reject | n/a |
| 082-onchain-x402-base-sepolia-55a0b820 | accept | accept | accept | accept | accept |
| 083-onchain-x402-base-sepolia-5bf1e09a | accept | accept | accept | accept | accept |
| 084-onchain-x402-base-sepolia-9537eb22 | accept | accept | accept | accept | accept |
