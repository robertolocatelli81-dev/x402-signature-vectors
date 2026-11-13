// SPDX-License-Identifier: Apache-2.0
// Adapter: x402 TypeScript SDK (@x402/evm) -> SPEC.md §5 verdict contract.
//
//   X402_TS_ENV=<dir with node_modules/@x402/evm> node adapter.mjs <entry> <vector.json>...
//
// <entry> is one of:
//   typed-data         @x402/evm verifyTypedDataSignature (src/shared/verifySignature.ts), preceded by the same
//                      low-s gate the exact facilitator applies (isPlainNonCanonicalEcdsaSignature, eip3009.ts).
//   facilitator-exact  @x402/evm/exact/facilitator ExactEvmScheme.verify, EIP-3009 payloads only.
// One JSON object per vector on stdout (SPEC.md §5). The adapter never decides a verdict itself: it reports what
// the SDK answered, maps the SDK's reason code to a suite class only where the mapping is one-to-one, and says
// not_applicable / not_reached where the SDK entry point cannot receive the vector or answered outside the
// signature layer.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import path from "node:path";

const ENV = process.env.X402_TS_ENV;
if (!ENV) {
  console.error("X402_TS_ENV not set: directory holding node_modules/@x402/evm");
  process.exit(2);
}
const require = createRequire(path.join(path.resolve(ENV), "package.json"));
const evm = require("@x402/evm");
const fac = require("@x402/evm/exact/facilitator");

const [entry, ...files] = process.argv.slice(2);
if (!["typed-data", "facilitator-exact"].includes(entry) || files.length === 0) {
  console.error("usage: adapter.mjs typed-data|facilitator-exact <vector.json>...");
  process.exit(2);
}

// The SDK's facilitator error codes, as published in src/exact/facilitator/errors.ts of @x402/evm 2.31.0.
// SIGNATURE-LAYER codes map to a suite class only where the mapping is one-to-one.
const SIG_REASON_TO_CLASS = {
  invalid_exact_evm_non_canonical_signature: "signature_high_s",
  invalid_exact_evm_signature: null,              // "does not verify": the SDK does not say why
  invalid_exact_evm_payload: null,                // payload field-type check (validateExactEvmPayload)
  invalid_exact_evm_failed_to_verify_signature: null,
};

const TWA_FIELDS = [
  ["from", "address"], ["to", "address"], ["value", "uint256"],
  ["validAfter", "uint256"], ["validBefore", "uint256"], ["nonce", "bytes32"],
];

function out(o) {
  process.stdout.write(JSON.stringify(o) + "\n");
}

// EOA everywhere except the asset (a deployed contract), and an eth_call that succeeds: the chain is modelled as
// accepting, so the facilitator's verdict is its OFF-CHAIN verdict. A real facilitator also simulates the transfer
// on chain, where the token contract checks the signature again.
function mockSigner(asset) {
  const calls = [];
  return {
    calls,
    getAddresses: () => ["0x0000000000000000000000000000000000000001"],
    getCode: async ({ address }) => {
      calls.push(["getCode", address]);
      return asset && address.toLowerCase() === asset.toLowerCase() ? "0x6080" : "0x";
    },
    readContract: async (args) => {
      calls.push(["readContract", args.functionName]);
      return undefined;
    },
    verifyTypedData: async () => { throw new Error("adapter: verifyTypedData must not be reached"); },
    writeContract: async () => { throw new Error("adapter: writeContract must not be reached"); },
    sendTransaction: async () => { throw new Error("adapter: sendTransaction must not be reached"); },
    waitForTransactionReceipt: async () => { throw new Error("adapter: no receipts offline"); },
  };
}

// The vector's JSON is read keeping every integer exact: JSON.parse turns 2^256-1 into a double, and the SDK would then
// be judged on a value the vector does not carry (measured 13/11/2026 with JSON.parse: 004, 011, 031, 041 rejected by the typed-data entry).
function readVector(text) {
  return JSON.parse(text, (k, v, ctx) =>
    typeof v === "number" && !Number.isSafeInteger(v) && ctx && /^-?(0|[1-9][0-9]*)$/.test(ctx.source)
      ? BigInt(ctx.source) : v);
}

function decimal(v) {
  // JSON integer -> the x402 wire form (decimal string). Anything else is passed through UNCHANGED, so the SDK's own
  // payload check sees the vector's value (SPEC.md §5.3).
  return Number.isSafeInteger(v) || typeof v === "bigint" ? String(v) : v;
}

function intOf(v) {
  if (Number.isSafeInteger(v)) return v;
  if (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v)) return Number(v);
  return null;
}

// The amount the server asks for (SPEC.md §5.3): the value's integer when it is a JSON integer or a string of ASCII
// digits, else "0" (both SDKs check the payload's field types before they compare amounts).
function amountOf(v) {
  if (Number.isSafeInteger(v) || typeof v === "bigint") return String(v);
  if (typeof v === "string" && /^[0-9]{1,78}$/.test(v)) return BigInt(v).toString();
  return "0";
}

async function typedData(vec) {
  const e = vec.eip712;
  const sig = vec.signature;
  if (typeof sig === "string" && sig.startsWith("0x") && evm.isPlainNonCanonicalEcdsaSignature(sig, false)) {
    return { verdict: "reject", reject_reason: "signature_high_s", sdk_reason: "isPlainNonCanonicalEcdsaSignature" };
  }
  const ok = await evm.verifyTypedDataSignature(mockSigner(null), {
    address: vec.signer, domain: e.domain, types: e.types, primaryType: e.primaryType,
    message: e.message, signature: sig,
  });
  return ok ? { verdict: "accept", reject_reason: null, sdk_reason: "true" }
            : { verdict: "reject", reject_reason: null, sdk_reason: "false" };
}

function exactApplicable(vec) {
  const e = vec.eip712;
  const d = e.domain;
  if (e.primaryType !== "TransferWithAuthorization") return "primaryType is not TransferWithAuthorization";
  const keys = Object.keys(e.types);
  if (keys.length !== 1 || keys[0] !== "TransferWithAuthorization") return "types other than TransferWithAuthorization";
  const f = e.types.TransferWithAuthorization;
  if (f.length !== 6 || f.some((x, i) => x.name !== TWA_FIELDS[i][0] || x.type !== TWA_FIELDS[i][1]))
    return "TransferWithAuthorization fields differ from EIP-3009";
  const dk = Object.keys(d).sort().join(",");
  if (dk !== "chainId,name,verifyingContract,version")
    return "domain members are not exactly name, version, chainId, verifyingContract";
  // The domain is the server's PaymentRequirements (network, asset, extra.name, extra.version), not the client's
  // payload: a malformed domain value is not something a payer can send (SPEC.md §5.3).
  if (!((Number.isSafeInteger(d.chainId) && d.chainId >= 0) || (typeof d.chainId === "bigint" && d.chainId >= 0n))
      || String(d.chainId).length > 32)
    return "domain chainId is not a CAIP-2 reference (integer, at most 32 digits)";
  if (typeof d.name !== "string" || typeof d.version !== "string"
      || typeof d.verifyingContract !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(d.verifyingContract))
    return "domain value not in the form a server's PaymentRequirements carries";
  return null;
}

async function facilitatorExact(vec) {
  const why = exactApplicable(vec);
  if (why) return { verdict: "not_applicable", reject_reason: null, sdk_reason: null, detail: why };
  const e = vec.eip712, d = e.domain, m = e.message;
  const requirements = {
    scheme: "exact", network: `eip155:${d.chainId}`, asset: d.verifyingContract,
    amount: amountOf(m.value), payTo: m.to, maxTimeoutSeconds: 60,
    extra: { name: d.name, version: d.version },
  };
  const payload = {
    x402Version: 2, accepted: requirements,
    payload: {
      signature: vec.signature,
      authorization: {
        from: m.from, to: m.to, value: decimal(m.value), validAfter: decimal(m.validAfter),
        validBefore: decimal(m.validBefore), nonce: m.nonce,
      },
    },
  };
  // Clock pinned inside the authorization window, so the time checks pass when the window admits it.
  const after = intOf(m.validAfter);
  const realNow = Date.now;
  Date.now = () => (after !== null ? after : 1740672089) * 1000;
  const signer = mockSigner(d.verifyingContract);
  try {
    const scheme = new fac.ExactEvmScheme(signer);
    const r = await scheme.verify(payload, requirements);
    if (r.isValid) return { verdict: "accept", reject_reason: null, sdk_reason: "isValid" };
    const code = r.invalidReason;
    if (code in SIG_REASON_TO_CLASS)
      return { verdict: "reject", reject_reason: SIG_REASON_TO_CLASS[code], sdk_reason: code,
               detail: r.invalidMessage ?? null };
    return { verdict: "not_reached", reject_reason: null, sdk_reason: code, detail: r.invalidMessage ?? null };
  } finally {
    Date.now = realNow;
  }
}

for (const f of files) {
  const vec = readVector(readFileSync(f, "utf8"));
  const base = { id: vec.id, sdk: "typescript", entry };
  try {
    const r = entry === "typed-data" ? await typedData(vec) : await facilitatorExact(vec);
    out({ ...base, detail: null, ...r });
  } catch (ex) {
    out({ ...base, verdict: "error", reject_reason: null, sdk_reason: null,
          detail: `${ex?.name ?? "Error"}: ${String(ex?.message ?? ex).split("\n")[0].slice(0, 200)}` });
  }
}
