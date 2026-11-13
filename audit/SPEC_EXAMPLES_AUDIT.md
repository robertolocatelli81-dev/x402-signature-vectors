# Cryptographic audit of the signature examples in the x402 specifications

**Upstream:** `x402-foundation/x402` at commit `2178d4b77aff61395c375bbdf30757876393b85d` (13 November 2026,
08:22 UTC). **Re-derived:** 13 November 2026. **Method:** every case recomputed with `lib/` (Keccak-256, EIP-712 and
secp256k1 in the Python standard library); the twelve computable cases were also recovered with `eth-account` 0.14.0,
with the same twelve addresses. The first version of this audit (11 September 2026) covered four cases; two of its
models were wrong, see [Corrections](#corrections).

## Question

For every occurrence of a signature in the x402 specification documents: does it recover to the address the
example itself declares as the signer?

## The signature under audit

```
0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c
```

It appears **15 times in 13 documents** under `specs/` (as a hex string; base64-encoded copies inside example
headers are not counted). Every example declares the same signer, `0x857b06519E91e3A54538791bDbb0E22373e36b66`.

## Results

| document:line | message as published | recovered address | verdict |
|---|---|---|---|
| `schemes/exact/scheme_exact_evm.md:56` | EIP-3009 `TransferWithAuthorization`, Base Sepolia USDC | `0x857b0651…6b66` | **valid** |
| `x402-specification-v2.md:179` | the same message | `0x857b0651…6b66` | **valid** |
| `transports-v2/http.md:98` | the same message | `0x857b0651…6b66` | **valid** |
| `transports-v2/mcp.md:121` | the same message | `0x857b0651…6b66` | **valid** |
| `x402-specification-v1.md:138` | the same message, v1 (`network: base-sepolia`) ¹ | `0x857b0651…6b66` | **valid** |
| `transports-v1/http.md:72` | the same message, v1 ¹ | `0x857b0651…6b66` | **valid** |
| `transports-v1/mcp.md:104` | the same message, v1 ¹ | `0x857b0651…6b66` | **valid** |
| `transports-v1/a2a.md:93` | EIP-3009, `to: "0xServerWalletAddressHere"` | — | **not encodable** |
| `transports-v2/a2a.md:109` | EIP-3009, `to: "0xServerWalletAddressHere"` | — | **not encodable** |
| `schemes/exact/scheme_exact_evm.md:149` | Permit2 `PermitWitnessTransferFrom` ² | `0x468d6ad86c21a78c0c1f4f1fdc6c67616b9beb6f` | **does not verify** |
| `extensions/eip2612_gas_sponsoring.md:124` | the same Permit2 payload ² | `0x468d6ad86c21a78c0c1f4f1fdc6c67616b9beb6f` | **does not verify** |
| `extensions/erc20_gas_sponsoring.md:150` | the same Permit2 payload ² | `0x468d6ad86c21a78c0c1f4f1fdc6c67616b9beb6f` | **does not verify** |
| `extensions/eip2612_gas_sponsoring.md:149` | EIP-2612 `Permit` in `extensions.eip2612GasSponsoring.info` ³ | `0xd259c1962ac82d9033ea21cf55d59c1a5d97acbb` | **does not verify** |
| `schemes/upto/scheme_upto_evm.md:120` | Permit2 (upto), `witness.facilitator: "0xFacilitatorAddress1234567890123456789012"`, `nonce` a bytes32 hex string where Permit2 declares `uint256` | — | **not encodable** |
| `extensions/sign-in-with-x.md:150` | ERC-4361 message, EIP-191 `personal_sign`: the EVM string the same document publishes under "Message Format" | `0x5b2acbca0fb899bd73747ac64302145db44d5d66` | **does not verify** |

Count: 7 valid (one message, published seven times), 5 that do not verify, 3 whose message contains a placeholder
that is not a value of its declared type, so no signature can be over it.

¹ A v1 block names `network: base-sepolia` and no asset; the domain used is the one of the v2 example (USDC on Base
Sepolia, `name` "USDC", `version` "2"). The message fields are identical to the v2 example.
² Canonical Permit2 domain (`name` "Permit2", chain 84532, `verifyingContract` `0x000000000022D473030F116dDEE9F6B43aC78BA3`,
no `version`); witness types from the `WITNESS_TYPE_STRING` of `scheme_exact_evm.md`
(`Witness(address to,uint256 validAfter)`); spender `0x402085c2…0001` as published.
³ Token domain from `extra` (`name` "USDC", `version` "2"); `info.version` "1" is the extension's schema version, per
the document's own schema ("Schema version identifier").

## Why no other reconstruction can make the five verify

With `r`, `s` and the recovery id fixed, the recovered key is `Q = r⁻¹(sR − zG)`: two digests `z` that differ modulo
the group order give two different keys. The bytes are a genuine signature over the EIP-3009 digest of
`scheme_exact_evm.md`. Any example whose message hashes to a different digest — a different type, domain, field or
string — recovers to a different key, whatever domain or exact string one assumes, unless the two keys' addresses
collide on 160 bits. So the five "does not verify" verdicts do not depend on the reconstruction choices above; the
addresses shown are those of the reconstruction, the verdict is not.

## Reading the result

One message is genuine: the EIP-3009 example of `scheme_exact_evm.md`, which also made it possible to reconstruct
the EIP-712 domain that the specification does not state in full (see coinbase/x402#324). The other examples reuse
its bytes as a Permit2 witness transfer, an EIP-2612 permit and a sign-in message; they cannot verify against the
declared signer, and a developer who tests a verifier against them sees a failure that is not in their code. Three
more examples carry placeholders (`0xServerWalletAddressHere`, `0xFacilitatorAddress…`) where an address is
required; they are illustrations, not signed messages.

A related observation in the same example of `erc20_gas_sponsoring.md`: `info.signedTransaction` is 65 bytes
(`0x505cbf0d…05ded3`). A signed transaction that calls `approve(address,uint256)` carries at least the 68 bytes of that
call's calldata plus a signature, so a 65-byte value cannot be one.

## Corrections

Two models of the September audit were wrong, and both are corrected above:

1. `erc20_gas_sponsoring.md` was modelled as an EIP-2612 `Permit` (recovering to `0xd259c196…`, the result of the
   EIP-2612 case copied over). That document carries the signature only in `payload.permit2Authorization`, a Permit2
   witness transfer; there it recovers to `0x468d6ad86c21a78c0c1f4f1fdc6c67616b9beb6f`. The verdict ("does not
   verify") is unchanged; the message and the address were wrong.
2. The SIWX case was reported as "indicative only" because "the specification does not publish the exact string
   that was signed", and the message was rebuilt from the example's fields (`0x01147808…`). At `2178d4b`,
   `sign-in-with-x.md` publishes the EVM string under "Message Format"; on that string the signature recovers to
   `0x5b2acbca0fb899bd73747ac64302145db44d5d66` (with a trailing newline, `0x4870eb7d…`). Neither is the declared
   signer, and by the argument above no string other than the EIP-3009 digest's preimage could be.

The September audit also said "seven times across five documents"; the count at `2178d4b` is fifteen in thirteen.

## Reproduce

```bash
python3 tools/audit_spec_examples.py                    # recompute; exit 1 if it differs from spec_examples_audit.json
python3 tools/audit_spec_examples.py --specs <x402>/specs   # provenance: specs/ checked out at 2178d4b
```

The first command is a CI gate. The second needs a checkout of the upstream repository at the pinned commit and
checks that the 15 occurrences sit exactly at the documents and lines of the table, and that the SIWE string is the
published one byte for byte. Machine-readable results: [`spec_examples_audit.json`](spec_examples_audit.json).
