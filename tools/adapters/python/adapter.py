#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Adapter: x402 Python SDK (package `x402`, extra `evm`) -> SPEC.md §5 verdict contract.

    <venv>/bin/python -I adapter.py <entry> <vector.json>...

<entry> is one of:
  typed-data         x402.mechanisms.evm.verify.verify_typed_data_strict, preceded by the low-s gate the exact
                     facilitator applies (exact/eip3009_utils.is_plain_non_canonical_ecdsa_signature).
  facilitator-exact  x402.mechanisms.evm.exact.facilitator.ExactEvmScheme.verify, EIP-3009 payloads only.

One JSON object per vector on stdout (SPEC.md §5). The adapter reports what the SDK answered; it maps an SDK reason
code to a suite class only where the mapping is one-to-one, and says not_applicable / not_reached where the entry
point cannot receive the vector or answered outside the signature layer. Run it with the SDK's venv interpreter and
`-I`, so that nothing but that venv is importable.
"""
import json
import re
import sys
from unittest import mock

from x402.mechanisms.evm import constants as C
from x402.mechanisms.evm.exact import facilitator as F
from x402.mechanisms.evm.exact.eip3009_utils import is_plain_non_canonical_ecdsa_signature
from x402.mechanisms.evm.utils import hex_to_bytes
from x402.mechanisms.evm.verify import verify_typed_data_strict
from x402.schemas import PaymentPayload, PaymentRequirements

# Signature-layer reason codes of x402 2.28.0 (mechanisms/evm/constants.py). Only one maps one-to-one to a suite class.
SIG_REASON_TO_CLASS = {
    C.ERR_INVALID_SIGNATURE_S: "signature_high_s",
    C.ERR_INVALID_SIGNATURE: None,
    C.ERR_INVALID_PAYLOAD: None,
    C.ERR_FAILED_TO_VERIFY_SIGNATURE: None,
    C.ERR_UNDEPLOYED_SMART_WALLET: None,     # non-65-byte signature from an address with no code
}
TWA_FIELDS = [("from", "address"), ("to", "address"), ("value", "uint256"),
              ("validAfter", "uint256"), ("validBefore", "uint256"), ("nonce", "bytes32")]


class MockSigner:
    """EOA everywhere except the asset (a deployed contract); every eth_call succeeds. The chain is modelled as
    accepting, so the facilitator's verdict is its OFF-CHAIN verdict (a real facilitator also simulates on chain)."""

    def __init__(self, asset=None):
        self.asset = (asset or "").lower()

    def get_addresses(self):
        return ["0x0000000000000000000000000000000000000001"]

    def get_code(self, address):
        return b"\x60\x80" if self.asset and str(address).lower() == self.asset else b""

    def read_contract(self, *a, **k):
        return None

    def __getattr__(self, name):           # anything else (write, send, receipts) must not be reached offline
        raise RuntimeError(f"adapter: signer.{name} must not be reached")


def typed_data(vec):
    e = vec["eip712"]
    try:
        sig = hex_to_bytes(vec["signature"])           # the SDK's own conversion (facilitator.py does the same)
    except Exception as ex:                            # noqa: BLE001
        return {"verdict": "reject", "reject_reason": None, "sdk_reason": "hex_to_bytes raised",
                "detail": f"{type(ex).__name__}: {ex}"[:200]}
    if is_plain_non_canonical_ecdsa_signature(sig, False):
        return {"verdict": "reject", "reject_reason": "signature_high_s",
                "sdk_reason": "is_plain_non_canonical_ecdsa_signature"}
    ok = verify_typed_data_strict(MockSigner(), vec["signer"], e["domain"], e["types"], e["primaryType"],
                                  e["message"], sig)
    return ({"verdict": "accept", "reject_reason": None, "sdk_reason": "True"} if ok
            else {"verdict": "reject", "reject_reason": None, "sdk_reason": "False"})


def exact_applicable(vec):
    e, d = vec["eip712"], vec["eip712"]["domain"]
    if e["primaryType"] != "TransferWithAuthorization":
        return "primaryType is not TransferWithAuthorization"
    if list(e["types"]) != ["TransferWithAuthorization"]:
        return "types other than TransferWithAuthorization"
    f = e["types"]["TransferWithAuthorization"]
    if [(x.get("name"), x.get("type")) for x in f] != TWA_FIELDS:
        return "TransferWithAuthorization fields differ from EIP-3009"
    if sorted(d) != ["chainId", "name", "verifyingContract", "version"]:
        return "domain members are not exactly name, version, chainId, verifyingContract"
    c = d["chainId"]
    if not (type(c) is int and c >= 0 and len(str(c)) <= 32):
        return "domain chainId is not a CAIP-2 reference (integer, at most 32 digits)"
    if not (isinstance(d["name"], str) and isinstance(d["version"], str) and isinstance(d["verifyingContract"], str)
            and re.fullmatch(r"0x[0-9a-fA-F]{40}", d["verifyingContract"])):
        return "domain value not in the form a server's PaymentRequirements carries"
    return None


def decimal(v):
    """JSON integer -> x402 wire form (decimal string); anything else passes through UNCHANGED (SPEC.md §5.3)."""
    return str(v) if type(v) is int else v


def int_of(v):
    if type(v) is int:
        return v
    if isinstance(v, str) and re.fullmatch(r"(0|[1-9][0-9]*)", v):
        return int(v)
    return None


def amount_of(v):
    """The amount the server asks for (SPEC.md §5.3): the value's integer when it is a JSON integer or a string of
    ASCII digits, else "0" (both SDKs check the payload's field types before they compare amounts)."""
    if type(v) is int:
        return str(v)
    if isinstance(v, str) and re.fullmatch(r"[0-9]{1,78}", v):
        return str(int(v))
    return "0"


def facilitator_exact(vec):
    why = exact_applicable(vec)
    if why:
        return {"verdict": "not_applicable", "reject_reason": None, "sdk_reason": None, "detail": why}
    e, d = vec["eip712"], vec["eip712"]["domain"]
    m = e["message"]
    req = {"scheme": "exact", "network": f"eip155:{d['chainId']}", "asset": d["verifyingContract"],
           "amount": amount_of(m.get("value")), "payTo": m.get("to"), "maxTimeoutSeconds": 60,
           "extra": {"name": d["name"], "version": d["version"]}}
    requirements = PaymentRequirements.model_validate(req)
    payload = PaymentPayload.model_validate({
        "x402Version": 2, "accepted": req,
        "payload": {"signature": vec["signature"],
                    "authorization": {"from": m.get("from"), "to": m.get("to"), "value": decimal(m.get("value")),
                                      "validAfter": decimal(m.get("validAfter")),
                                      "validBefore": decimal(m.get("validBefore")), "nonce": m.get("nonce")}}})
    after = int_of(m.get("validAfter"))
    now = after if after is not None else 1740672089
    with mock.patch.object(F.time, "time", return_value=float(now)):
        r = F.ExactEvmScheme(MockSigner(d["verifyingContract"])).verify(payload, requirements)
    if r.is_valid:
        return {"verdict": "accept", "reject_reason": None, "sdk_reason": "is_valid"}
    code = r.invalid_reason
    if code in SIG_REASON_TO_CLASS:
        return {"verdict": "reject", "reject_reason": SIG_REASON_TO_CLASS[code], "sdk_reason": code,
                "detail": (r.invalid_message or None)}
    return {"verdict": "not_reached", "reject_reason": None, "sdk_reason": code, "detail": (r.invalid_message or None)}


def main(argv):
    if len(argv) < 2 or argv[0] not in ("typed-data", "facilitator-exact"):
        print("usage: adapter.py typed-data|facilitator-exact <vector.json>...", file=sys.stderr)
        return 2
    entry = argv[0]
    for path in argv[1:]:
        with open(path, encoding="utf-8") as fh:
            vec = json.load(fh)
        base = {"id": vec["id"], "sdk": "python", "entry": entry, "detail": None}
        try:
            r = typed_data(vec) if entry == "typed-data" else facilitator_exact(vec)
        except Exception as ex:                        # noqa: BLE001 — the SDK raised instead of answering
            r = {"verdict": "error", "reject_reason": None, "sdk_reason": None,
                 "detail": f"{type(ex).__name__}: {str(ex).splitlines()[0] if str(ex) else ''}"[:200]}
        print(json.dumps({**base, **r}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
