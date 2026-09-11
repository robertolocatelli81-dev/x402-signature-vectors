# Cryptographic audit of the signature examples in the x402 specifications

**Date:** 11 September 2026 · **Method:** clean-room verification, zero dependencies (`lib/` implements Keccak-256, EIP-712 and secp256k1 in the Python standard library).

## Question

For every signature published in the normative x402 documents: does it recover to the address the example itself declares?

## The signature under audit

```
0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c
```

It appears **seven times across five normative documents**, presented as the signature of five different message types. An ECDSA signature is valid for exactly one message.

## Results

| case | document | standard | recovered address | verdict |
|---|---|---|---|---|
| `exact_evm_eip3009` | `specs/schemes/exact/scheme_exact_evm.md` | EIP-3009 TransferWithAuthorization (EIP-712) | `0x857b06519e91e3a54538791bdbb0e22373e36b66` | **VALIDA** |
| `eip2612_permit` | `specs/extensions/eip2612_gas_sponsoring.md` | EIP-2612 Permit (EIP-712) | `0xd259c1962ac82d9033ea21cf55d59c1a5d97acbb` | **PLACEHOLDER (non verifica)** |
| `erc20_gas_sponsoring_permit` | `specs/extensions/erc20_gas_sponsoring.md` | EIP-2612 Permit (EIP-712) | `0xd259c1962ac82d9033ea21cf55d59c1a5d97acbb` | **PLACEHOLDER (non verifica)** |
| `sign_in_with_x` | `specs/extensions/sign-in-with-x.md` | ERC-4361 / EIP-191 personal_sign | `0x01147808a7457af8b8ad66bb8c0fd69c56821f54` | **non verifica (indicativo)** |

Declared signer in every example: `0x857b06519E91e3A54538791bDbb0E22373e36b66`

## Reading the result

One example is genuine: `scheme_exact_evm.md` carries a real signature over a real `TransferWithAuthorization` message, and it verifies — which is also what made it possible to reconstruct the EIP-712 domain the specification never states (see coinbase/x402#324).

The two EIP-2612 cases carry the *same bytes* over a different message, and recover to `0xd259c1962ac82d9033ea21cf55d59c1a5d97acbb`, an address with no relation to the declared owner. They are placeholders.

The ERC-4361 case is reported as **indicative only**: the specification does not publish the exact string that was signed, so the message had to be reconstructed from the example's fields. A negative result there may reflect our reconstruction rather than the example. We do not call it a placeholder.

## Why it matters

This is reported clinically. A placeholder signature in a normative example is not an aesthetic defect: a developer who uses it as a reference builds a verifier against a value that cannot verify, and the first conclusion they will reach is that their own implementation is broken. The cost falls on the implementer, not on the document.

## Reproduce

```bash
python3 tools/audit_spec_examples.py
```

Machine-readable results: [`spec_examples_audit.json`](spec_examples_audit.json).
