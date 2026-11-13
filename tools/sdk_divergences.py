# SPDX-License-Identifier: Apache-2.0
"""Classification of every divergence measured by tools/run_sdk_adapters.py (SPEC.md §5.4), written by hand.

(sdk, entry, vector id) -> (class, rule). Classes: "a" finding about the SDK (a rule of a standard or of the x402
specification, on an input that reaches it through x402); "b" defect of this suite (corrected, with a test);
"c" rule of this suite only, or an input that cannot reach the entry point through x402. The runner fails if a
divergence has no entry here or an entry has no divergence. Files and lines: x402-foundation/x402 at 07c4caf
(= 2178d4b outside go/).
"""
_V01 = ("c", "suite rule: v transmitted as 27/28 (SPEC §3.2). Both SDKs accept the raw recovery id 0/1 on purpose "
             "and normalise it before the chain: python mechanisms/evm/exact/eip3009_utils.py:463-464 and "
             "verify.py:49-50; typescript exact/facilitator/eip3009-utils.ts:130,333 (yParity + 27). The x402 "
             "spec says only 'the 65-byte signature' (scheme_exact_evm.md:29).")
_LEAD0 = ("c", "suite rule: one decimal spelling per integer (SPEC §2). Reachable through x402: the payload checks "
               "admit leading zeros (typescript types.ts:87 /^[0-9]{1,78}$/, python types.py:9 [0-9]{1,78}) and "
               "the value is read as 10000. The x402 spec does not state a canonical decimal form.")
_FORM_TD = ("c", "suite rule: one JSON spelling per EIP-712 type (SPEC §2). Generic typed-data primitive; not "
                 "reachable through x402: the exact facilitator of the same SDK rejects this vector with "
                 "invalid_exact_evm_payload (measured, facilitator-exact entry).")
_ARRAY = ("c", "EIP-712 types T[k] as a fixed-size array of k elements; the primitive encodes 3 elements for "
               "uint256[2]. Not reachable through x402: no x402 exact message type has an array member.")
CLASSIFICATION = {
    ("typescript", "typed-data", "028-v-raw-zero"): _V01,
    ("typescript", "facilitator-exact", "028-v-raw-zero"): _V01,
    ("python", "typed-data", "028-v-raw-zero"): _V01,
    ("python", "facilitator-exact", "028-v-raw-zero"): _V01,
    ("typescript", "typed-data", "063-uint-string-leading-zero"): _LEAD0,
    ("typescript", "facilitator-exact", "063-uint-string-leading-zero"): _LEAD0,
    ("python", "typed-data", "063-uint-string-leading-zero"): _LEAD0,
    ("python", "facilitator-exact", "063-uint-string-leading-zero"): _LEAD0,
    ("typescript", "typed-data", "060-uint-string-whitespace"): _FORM_TD,
    ("typescript", "typed-data", "062-uint-string-plus-sign"): _FORM_TD,
    ("typescript", "typed-data", "064-uint-bool"): _FORM_TD,
    ("python", "typed-data", "059-uint-string-unicode-digits"): _FORM_TD,
    ("python", "typed-data", "060-uint-string-whitespace"): _FORM_TD,
    ("python", "typed-data", "061-uint-string-underscore"): _FORM_TD,
    ("python", "typed-data", "062-uint-string-plus-sign"): _FORM_TD,
    ("typescript", "typed-data", "074-array-fixed-length-mismatch"): _ARRAY,
    ("python", "typed-data", "074-array-fixed-length-mismatch"): _ARRAY,
    ("typescript", "typed-data", "078-domain-unknown-member"): (
        "c", "suite rule: domain members limited to the five EIP-712 names (SPEC §1); viem derives EIP712Domain from "
             "the known keys and ignores `chainID`. Not reachable through x402: the facilitator builds the domain "
             "from PaymentRequirements."),
    ("python", "typed-data", "080-domain-chainid-declared-string"): (
        "c", "EIP-712 defines `uint256 chainId`; verify_typed_data_strict lets a caller's types.EIP712Domain replace "
             "the derived one (mechanisms/evm/verify.py:221-224), so chainId is hashed as a string. Not reachable "
             "through x402: every caller in the SDK passes SDK constants as types."),
}
