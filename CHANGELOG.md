# Changelog

Vectors are versioned so that an implementation can state *which* set it passes. Vector `id`s are
stable and never reused: a vector that turns out to be wrong is corrected in place and the change is
recorded here, so a verdict recorded against v0.2.0 stays meaningful.

## 1.6.0 — 2026-11-22

### 2026-11-21 — an integer of more than 4,300 digits is `input_not_object` on every interpreter and environment

- **Rule** (`SPEC.md` 1.3, §3.1; RFC 8259 §9: "An implementation may set limits on the range and precision of
  numbers"): a text holding a JSON number without fraction or exponent written with more than 4,300 digits, anywhere in
  the document, counted outside strings before the text is read (`verify.numero_oltre`, `verify.CIFRE_MAX`), is
  `reject` / `input_not_object`. Integers within the limit are converted in pieces of 600 digits
  (`json.loads(..., parse_int=verify._intero_json)`), so the answer does not depend on `PYTHONINTMAXSTRDIGITS`.
- **Why**: Python's `json.loads` converts integers with `int()`, whose limit (4,300 digits by default) that variable
  moves. Measured on 21 and 22 November 2026, vector 003 with one more member, ignored by the verdict, holding an integer of
  4,301 digits: `reject` / `input_not_object` by default and `accept` with `PYTHONINTMAXSTRDIGITS=0`, with the runner
  of 1.5.0 on CPython 3.9.25, 3.11.2, 3.12.15, 3.13.15 and 3.14.8; with `PYTHONINTMAXSTRDIGITS=640` an integer of
  641 digits was `input_not_object`. Now 56 cases give the same answers on the five interpreters with the variable
  unset, `0` and `640`; with the variable unset they are those of 1.5.0 except 10 numbers of 640 digits or more
  written with `.5` or `e0`, now `input_not_object` (numbers with a fraction or an exponent, below).
- **Verdicts**: none of the 85 vectors changes (verdict, recovered address, class, four intermediate values; their
  longest integer has 78 digits). No vector added: `input_not_object` cannot be the expectation of a vector file,
  which is an object (README).
- **Runner**: a file in `vectors/` that the reader of §3.1 does not read (more than 64 levels, an integer of more than
  4,300 digits, not JSON) is now `FALLITO` with `schema: testo non leggibile: …`. Before, a truncated file made
  `verify.py` exit with a `JSONDecodeError` traceback, and a file with an integer of 5,000 digits did the same or not
  according to `PYTHONINTMAXSTRDIGITS` (measured on copies of the suite). `tools/test_runner_schema.py` (CI) plants the
  three files: each one `FALLITO`, with the variable unset and `=0`; on the runner of 1.5.0 the first
  one already fails the test (`('testo tronco', 1, [])`).
- **`tools/fuzz_runner.py`** (CI): integers of 1, 78, 79, 640, 641, 4,300, 4,301, 5,000 and 100,000 digits in an
  ignored member (also negative), in `value`, in a list, as the whole text, inside a string, inside a string after
  `\\` and `\"`, as a member name, with a fraction, with an exponent, and as UTF-16 bytes; run in this process and in
  two children with `PYTHONINTMAXSTRDIGITS=0` and `=640`: 99 cases × 3, the same answers, 0 wrong; and 18 readings
  of integers of 1 to 4,300 digits, positive, negative and `-0`, equal to the exact values; and 7 texts at the limit
  (4,300 and 4,301 digits, negative, in a list, at the very end of the text, with a fraction, with an exponent, in a
  string) given to `numero_oltre` and `leggi_json_stretto`.
- **`tools/positive_control.py`**: the sabotages `json-reader-lax` and `nan-admitted` patch the reader line, which now
  also passes `parse_int`; their target strings are updated (each found once). On the runner of 1.5.0 the 56 cases of the
  measurement above give 12 different answers with `PYTHONINTMAXSTRDIGITS=0` and 4 with `=640` (each of the five
  interpreters).
- **Numbers with a fraction or an exponent** (same rule, same day): the 4,300 digits are counted on the whole number,
  integer part, fraction and exponent (`verify.numero_oltre`), and a number that
  `float()` reads as infinite is `input_not_object` (`parse_float=verify._float_json`). Measured on 22 November
  2026 with the runner of 1.5.0, vector 003 with one more member holding `1e400`, `-1e400`, `1E+309`, or
  5,000 digits followed by `.5`, was `accept`, and the same number in `value` was `encoding_error`; now all are
  `input_not_object` (of the 13 numbers measured, 9 change, in both places). Finite numbers keep their answer (`1.5`,
  `1e-400` → 0.0, `1.7976931348623157e308`). None of the 85 vectors changes. `tools/fuzz_runner.py`: the texts at
  the limit become 11, the 7 above included (fraction and exponent digits counted) and 21 cases of non-finite and finite numbers (ignored member,
  `value`, bytes); the long-number cases with a fraction or an exponent now expect `input_not_object` from 309 digits
  (infinite) and above 4,300 digits. `tools/test_runner_schema.py`: a vector file with `1e400` in an extra member is
  `FALLITO` «testo non leggibile».

### 2026-11-21 — a struct that `primaryType` does not reach is `encoding_error` (SPEC.md 1.3)

- **Rule** (`SPEC.md` 1.3, §1 `/eip712/types`): `types` MUST NOT define a struct that is not `EIP712Domain` and is not
  reachable from `primaryType`, otherwise `encoding_error`. EIP-712 `encodeType` includes only the referenced structs,
  so such a struct is not signed. Measured on 21 November 2026 on vector 001 with one more struct: the runner of 1.5.0
  answers `accept`; eth-account 0.14.0 refuses the typed data ("Unable to determine primary type", and "The provided
  `primaryType` does not match the derived `primaryType`" when the extra struct holds the primary type); viem 2.57.19
  and the typed-data check of `@x402/evm` 2.31.0 recover the signer. EIP-712 does not state the rule: it is a rule of
  this suite (§5.4 class c).
- **`lib/eip712.valida_struttura(domain, types, primary)`** takes `primaryType` and applies the rule
  (`strutture_raggiungibili`, iterative); `verify.digest_di`, `verify.strati`, `lib/eip712.signing_digest` and
  `tools/crossvalidate.py` pass it. A `primaryType` that is not a string naming a struct of `types` stays
  `encoding_error`.
- **Vector 085** `085-types-unreachable-struct` (reject, `encoding_error`): the message and signature of 003 with
  `types.Unused` added; the runner of 1.5.0 accepts it. Generated by `tools/genera_vettori_81.py`.
- **Verdicts**: none of vectors 001–084 changes (verdict, recovered address, class and the four intermediate values
  compared one by one between this runner and those of the v1.5.0 tag and of the parent commit); 085 is the one
  verdict that changes (`accept` with both).
- **SDKs and reference libraries** (re-run with the pinned versions): 085 is `accept` on the TypeScript typed-data
  entry (a class (c) divergence, listed in `tools/sdk_divergences.py`: viem encodes only the structs reachable from
  `primaryType`), `reject` on the Python one (eth-account), not applicable on both facilitators; the 336 results of
  001–084 are unchanged; 20 divergences, all class (c) (`audit/sdk_results.json`, `audit/SDK_RESULTS.md`, README).
  `tools/crossvalidate.py`: 85 vectors re-verified with coincurve, 0 discordant (with the `valida_struttura` of the
  parent commit, 085 is discordant); `tools/crossvalidate_eip712.py`: 57 compared, 28 skipped, 0 divergences.
- **`tools/fuzz_runner.py`** (CI): 240 random type graphs (atomic members, structs, `T[]` / `T[k]`, cycles through empty
  `T[]`, `EIP712Domain` declared or not, key order shuffled), the message built on them and signed with the test key;
  120 get one to three structs that `primaryType` does not reach (isolated, empty, holding the primary type, chained,
  recursive, with an unknown type, not a list, members that are not objects). Read as text and as an object,
  passed to `lib/eip712.signing_digest` (digest only when every struct is reachable) and to `verify.strati` (the four
  intermediate values only when every struct is reachable), plus 7 invalid `primaryType`
  values, plus 37 hostile shapes of `types`, `primaryType` and the domain given to `lib/eip712.valida_struttura` and to
  `lib/eip712.signing_digest` (each call must raise the library's own `ValoreNonConforme`: no other exception, and no
  silent return; a `primaryType` that is not a string is refused by that reason), plus chains of 980 and 3,000 reachable structs read three ways: 1052 cases, 0 wrong. The expected answer comes from a fixed
  point written in the test, not from `lib/`. The verdict cases of the graphs, run on the parent commit (whose `lib/eip712.py` is that
  of 1.5.0), report 240 wrong: the 120 graphs with extra structs, accepted, as text and as object.
- **Positive control kept able to fail**: with the rule, a struct named like an atomic type that nothing references is
  refused for two reasons, and the sabotage `struct-named-string` of `tools/positive_control.py` was no longer caught
  (measured on this branch: «catturati 17/18», B1 and B2 diff 0). The fuzz case and the B1 input now make that struct
  reachable from `primaryType` and sign over the struct reading, as vector 081 does (`fuzz_runner.py` «letture e
  nomi»: 26 cases; on a copy with the sabotage: 2 wrong, `string` and `bool` accepted).
- **Review of the commit above, same day** (the recursion of `encode_type` is older than the rule; it is in 1.5.0):
  - `valida_struttura` returned without an exception on 18 of the 25 hostile `types` shapes of the fuzz (a struct that
    is not a list, a member that is not an object with `name` and `type` strings), and `signing_digest` then raised
    `TypeError`, `KeyError` or `AttributeError` on them; a `primaryType` that is an integer of 5,000 digits raised the
    `ValueError` of `str()`. The runner answered `encoding_error` in every case; a caller of the library got an
    exception that is not the library's. Now `valida_struttura` refuses those shapes itself and answers every form of
    its three arguments with `ValoreNonConforme`.
  - `encode_type` collected the referenced structs by recursion. A chain of structs, each an empty `T[]` member of the
    one before, all reachable and signed, raised `RecursionError` from about 990 structs (`encoding_error`), and the
    answer depended on the caller: measured with 980 structs, `accept` when `verdetto_da_testo` is called directly,
    `reject` when called from 30 frames deeper, `accept` again after `sys.setrecursionlimit(3000)` (the same on the
    v1.5.0 tag). The visit is now iterative: chains of 980 and 3,000 structs are `accept` as text, as object and from
    200 frames deeper.
  - `verify.strati` without the rule passed every gate (the runner does not call it on an `encoding_error`): the
    fuzz now reads `verify.strati` on each of the 240 graphs.
  - Texts: the README said «15 sabotages … 18 caught» (18 sabotages, since 1.5.0); `SPEC.md` §1 says that a struct is
    reachable also as the element type of a nested array (`T[k][]`), which the runner already followed;
    `audit/POSITIVE_CONTROL.md` has the table of 21 November (the B1 batch changed with the reachable struct named like
    an atomic type; 18 of 18 caught, 18 of 18 not equivalent).
  - No verdict, recovered address, class or intermediate value of the 85 vectors changes.

### 2026-11-20 — a text nested deeper than the reader follows is rejected, not raised

- **`verify.verdetto_da_testo`**: measured on 1.5.0 on 20/11/2026, `"[" * 1000 + "]" * 1000` and `'{"a":' * 1000 + "1" +
  "}" * 1000` (and deeper) made it raise `RecursionError` instead of answering on Python 3.9 and 3.11; the reader of
  Python 3.12 and 3.13 reads 5,000 levels and raises at 20,000, that of 3.14 reads 20,000 and raises at 100,000 (first
  depth of nested arrays refused by `json.loads`: 993 on 3.9.25 and 3.11.2, 9,998 on 3.12.15, 9,999 on 3.13.15,
  65,197 on 3.14.8). The input of a verifier comes from the network. Now such a text is `reject` / `input_not_object` (`SPEC.md` 1.3, §3.1, citing RFC 8259 §9: "An
  implementation may set limits on the maximum depth of nesting").
- With the reader's limit alone the answer between those depths depended on the interpreter: the first vector with one
  more member, ignored by the verdict and nested 1,500 levels deep, was `reject` / `input_not_object` on 3.9 and 3.11
  and `accept` on 3.12, 3.13 and 3.14. So the limit is a number of this suite: a text in which arrays and objects are
  nested more than 64 levels deep, counted outside strings before the text is read (`verify.annidato_oltre`,
  `verify.PROFONDITA_MAX`), is `reject` / `input_not_object` on every interpreter; the vectors nest 5 levels.
  `SPEC.md` §3.1 and the table of §3.3, `README.md` and `tools/reject_reasons.py` say so. `tools/fuzz_runner.py`: 19
  cases (64 levels read, 65 not; 200 sibling values are not levels, nor are brackets inside a string or a member
  name; the same text as bytes; a reader raising `RecursionError`; a `signer` that is a number, a list or the address
  followed by a space is `signer_mismatch` with the recovered address reported).
- **`verify.verdetto`** on an object already read: a `signer` that is not a string is `signer_mismatch` ("`signer`
  non e' una stringa"). Before, `str(signer)` was compared, which never equals an address; on a `signer` nested
  thousands of levels deep `str()` raised `RecursionError`.
- **`tools/fuzz_runner.py`** (CI): a value nested 50, 5,000 and 200,000 levels deep, as a list and as an object, put in
  place of every node of vector 003 (root included), read as text and as an object: 600 cases, no exception, every
  text nested more than 64 levels deep (200 of them, on every interpreter) is `reject` / `input_not_object` (the
  section fails if no such text was produced), and a nested value in place of `signer` is `reject`.
  On the `verify.py` of 1.5.0 the same section reports `RecursionError`.
- **`tools/positive_control.py`**: the sabotage `signer-case-sensitive` patches the new comparison line.
- No vector, class or schema changed.

## 1.5.0 — 2026-11-13

### 2026-11-13 — specification, audit at `2178d4b`, two official SDKs, real payments, positive control

- **`SPEC.md`** (1.1): the vector format field by field, the value forms, the order of the checks, the closed list
  of reject classes, three levels of conformance, the input/output contract of an adapter
  (`schema/adapter-result.schema.json`), how divergences are classified. `tools/check_spec.py` (CI) checks that every
  field of the two schemas has one clause and every clause a field (28/28), with a built-in positive control.
- **Audit re-derived at `x402-foundation/x402@2178d4b`**: all 15 occurrences of the reused signature in 13
  documents — 7 valid (one message), 5 do not verify, 3 not encodable. Two models of the September audit were
  wrong: `erc20_gas_sponsoring.md` carries the signature in a Permit2 payload (it recovers to `0x468d6ad8…`, not
  `0xd259c196…`), and `sign-in-with-x.md` does publish the signed SIWE string (it recovers to `0x5b2acbca…`; the case
  was "indicative"). `tools/audit_spec_examples.py` was not a gate (it rewrote its JSON and exited 0); it now exits 1
  when the recomputation differs, and `--specs` checks against an upstream checkout that the 15 occurrences sit at the
  documents and lines of the cases and that the SIWE string is the published one (the EIP-712 messages are constants
  of the tool, compared with the documents by hand).
- **`tools/check_manifest.py` in a git worktree**: a `.git` file was reported as undeclared and recorded by
  `--genera`; it is skipped now (`tools/test_check_manifest.py`, failed on the old code). `node_modules` skipped too.
- **Two official SDKs** (`@x402/evm` 2.31.0, `x402` 2.28.0, tagged at `07c4caf`): adapters in `tools/adapters/`,
  runner `tools/run_sdk_adapters.py`, results `audit/SDK_RESULTS.md` / `audit/sdk_results.json`, CI job `sdk`. 19
  divergences, all on rules of this suite or on inputs that cannot reach the entry through x402; three findings on
  reason codes (TypeScript `invalid_exact_evm_signature` vs the specified `invalid_exact_evm_payload_signature`; the
  two facilitators disagree on an empty domain `name`/`version`; Python calls a wrong-length EOA signature an
  undeployed smart wallet). `tools/test_sdk_adapters.py` was committed before the adapters.
- **Vectors 082–084** (`origin` `onchain`, new): three x402 payments settled on Base Sepolia by the signer the
  default facilitator publishes, derived from calldata; sources in `audit/onchain_sources.json`, rebuilt offline in
  CI (`tools/genera_vettori_onchain.py --confronta`). The contract's `DOMAIN_SEPARATOR()` equals the separator the
  suite computes. 84 vectors, 34 accept / 50 reject; `crossvalidate_eip712.py` 57 compared, 0 divergences.
- **Positive control** (`tools/positive_control.py`, CI job `positive-control`): 18 sabotages, 18 caught, 18
  non-equivalent. Before `tools/test_runner_compares.py` the runner's class and address comparisons could be
  switched off with every gate green (13/15 of the first set); `audit/POSITIVE_CONTROL.md`.
- **Review of this branch (same day)**: four sabotages and three second readings passed every gate, and are caught
  now. No gate read `expected.type_hash` or `expected.domain_separator`: `verify.py` now checks the four intermediate
  values (`tools/test_runner_compares.py` plants two wrong ones). `NaN`/`Infinity` and a struct named `string` or
  `bool` had no test (`tools/fuzz_runner.py`, 16 cases). A member definition in `types` with an extra key, a vector
  member repeated outside `/eip712` (two readings of the vector's own expectations) and a schema string with a
  trailing newline (Python's `$`) were accepted by the runner; they are `FALLITO` now (`tools/test_runner_schema.py`).
  A malformed signature with `v` = 29/30 and a small `r` reported a recovered address, against SPEC.md §1; it is
  `null` now. `tools/run_sdk_adapters.py` reads adapter lines with the strict reader. SPEC.md 1.2. No vector changed.
- README rewritten: problem, finding, run, evidence first; limits in "Guarantees and assumptions"; `CITATION.cff`
  (Zenodo concept DOI 10.5281/zenodo.24172853, v1.4.0 DOI 10.5281/zenodo.24172854).

### 2026-10-10 — the runner enforces the vector schema (closed)

- `verify.py` validates every vector against `schema/vector.schema.json` (`additionalProperties: false` at the levels
  the schema closes) BEFORE judging the signature: a vector carrying a field the schema does not define is `FALLITO`
  with the reason `schema: <path>: campo non previsto '<field>'`, printed in full so the field is named (review 2026-10-11:
  the first version cut the reason at 55/60 characters and dropped the field name; `tools/test_runner_schema.py`, run in CI,
  plants the three fields in a temporary copy) (the container is read with the standard reader for this check, so the repeated-member
  vector 077 still reaches the strict verdict path and rejects as `json_ambiguous`, as the suite expects). Measured
  on 1.4.0 (2026-10-10): `x_unknown_2026` at the top level, inside `eip712` and inside `expected` left the vector
  «conforme» with no trace in the runner's output; only the separate CI step `tools/check_schema.py` saw it. The
  schema is unchanged; `verdetto()` / `verdetto_da_testo()` (the signature verdict on an already-read vector) are
  unchanged — the closure is the runner's, where the suite's grammar is decided.

Review attributions no longer name the reviewing models (the reviews, adversarial reviews run by the same author,
are still recorded with their dates and findings). The two raw review transcripts under `audit/` were
removed from the tree (they remain in the repository history); `manifest.json` regenerated at that commit: 110
files, 81 vectors. That change touched no vector, verdict or tool.

## 1.4.0 — 2026-09-26

Two review rounds on 25/09/2026: a malformed-input fuzz (vectors 056–076) and a second round on the text of the
payload (077–081). Figures dated 25/09 are from those rounds and were not all re-measured; the 26/09 re-run on the
release commit is at the end of this entry.

### First round (056–076): fixes for two defects measured by the malformed-input fuzz

- **Strict value encoding in `lib/eip712.py`.** The encoder called `int()`, `str()` and
  `bytes.fromhex()` on JSON values, which *normalize*: `10000.9`, `"١٠٠٠٠"` (Arabic-Indic digits),
  `" 10000\n"`, `"10_000"`, `"+10000"` all encoded as 10000; an address or `bytes32` with `XX` or `::`
  instead of `0x`, or with spaces inside, encoded as the clean value; `"false"` encoded as `true`; the
  string `"123"` typed `uint256[]` encoded as `[1, 2, 3]`; a `uint256[2]` with three elements and a
  `uint7` were encoded anyway. The runner therefore returned `accept` on messages whose displayed JSON
  is not the signed message. Now each EIP-712 type admits one reading (table in the README, rule in
  the `lib/eip712.py` source) and anything else is `encoding_error`. Admitted for integers: a JSON
  integer or its canonical ASCII decimal string, both the same number, and no other spelling; hex strings
  (`"0x2710"`) are **not** admitted — one textual form per number is the point.
- **056–076**, 21 new vectors: 20 `reject` / `encoding_error`, each signed by the test key over the
  message a normalizing parser derives, plus 076 `accept` (canonical decimal string `"10000"`, same
  signature as 003). Measured: the runner at `fa91c0f` accepts all 20 rejects (56/76 conformant); with
  the fix 76/76. 31 accept / 45 reject at the end of this round. All 76 vectors regenerated
  byte-identical from `tools/genera_vettori*.py` on 25/09; 001–055 are unchanged.
- **eth-account 0.14.0 differs from this rule on 6 of the 20** (measured with `encode_typed_data` +
  `Account.recover_message`, offline): it recovers the declared signer on 059–063 (decimal strings with
  non-ASCII digits, whitespace, `_`, `+`, leading zeros) and 074 (fixed-array length). The other 14 it
  refuses or recovers to a different address. Its encoding still agrees with `lib/` on every encodable
  vector: 54 compared, 0 divergences (the 22 non-encodable ones are skipped by construction, and the 6
  differences above are all among them).
- **New reject class `input_not_object`.** A payload that is not a JSON object (`null`, array, string,
  number, boolean) raised `AttributeError` on `vec.get`, which landed in the signature branch and came
  out as `signature_malformed`: right verdict, wrong reason. Added to `tools/reject_reasons.py`, the
  schema enum and the README list; `tools/check_docs.py` now fails if those three lists disagree, and
  `tools/fuzz_runner.py` checks 10 non-object roots (0/10 right at `fa91c0f`, 10/10 now) plus a table
  of 20 admitted and 44 non-admitted value forms (31 wrong at `fa91c0f`, 0 after the fix; counts of 25/09).
- **`verify.py digest_di`**: `vec["eip712"]` is read inside the `try`, so a vector without the block is
  `encoding_error` instead of an unhandled `KeyError`.
- **Schema**: the value constraints on `eip712.domain` members were removed (the members stay
  required). A malformed domain value is what 058, 067 and 071 test; rejecting it is the verifier's job,
  as the schema already said for the signature length.
- **`tools/check_manifest.py --genera`** now ends `manifest.json` with a newline.

### Second round (077–081)

- **One reading of the text, the domain and the type names.**
  After the strict value forms, the JSON shown could still differ from the message signed:
  a repeated member (`"value": 99999999999, "value": 10000`: `json` keeps the last) — new class
  `json_ambiguous` and a strict reader `verify.leggi_json_stretto` / `verdetto_da_testo`; a domain member
  outside the five EIP-712 names; a `types.EIP712Domain` that does not match the domain (including `chainId`
  declared `string`); a struct named like an atomic type. Each new vector carries a real signature; this runner
  rejects each for the declared class, and each check, ablated on 25/09, turned exactly its own vectors red.
  Measured 26/09: the 1.3.0 runner (`af02a79`) accepts all five, and all 25 rejects added in 1.4.0 (056–081 without
  076): 56/81 conformant.
- **eth-account 0.14.0 on 077–081** (measured 26/09 with `encode_typed_data` + `Account.recover_message`): it raises
  on 078 (`Invalid domain key`) and 079 (`ValidationError`); it recovers a different address on 081 (its digest
  differs); it recovers the declared signer on 080 (`chainId` declared `string` in `types.EIP712Domain`) — it
  accepts that message; and it cannot see 077, because it receives a dict already parsed (and recovers the declared
  signer from it). These five are among the 27 vectors that `tools/crossvalidate_eip712.py` skips (no digest is
  declared for a non-encodable message), so its "0 divergences" does not cover them; the results above are direct
  calls. `tools/crossvalidate.py` now applies the same two reading rules before the cryptographic check.
- **Declared, not repaired (measured 25/09):** the strict value forms of the first round also turned three
  inputs that the 1.3.0 runner accepted, and that eth-account 0.14.0 encodes with the same digest as the 1.3.0 runner, into
  `encoding_error`: `"-0"` for an `intN`, the width-less type `uint`, and the zero-length array type `uint256[0]`.
  None has a canonical form under the rule in the README: the EIP-712 text states that "there are no aliases `uint` and `int`",
  `-0` is not the canonical decimal of 0, and the EIP-712 text is silent on zero-length arrays.

### Re-run on 26/09/2026 on the release commit

81 vectors, 81 conformant (31 `accept` / 50 `reject`); schema 81/81; manifest 112 files, every sha256 matching; all
81 vectors regenerated from `tools/genera_vettori*.py` into an empty directory, byte-identical; `tools/crossvalidate.py`
(coincurve + eth-hash): 81 re-verified, 0 discordant; `tools/crossvalidate_eip712.py` (eth-account 0.14.0): 54
compared, 27 skipped, 0 divergences; `tools/fuzz_runner.py`: no panic, classes and forms as declared.

## 1.3.0 — 2026-09-11

Second adversarial review by the same author, this time over the complete code. Everything it found was
checked against the code and the curve; everything that held is fixed here. Rule applied: a wrong
statement is not softened, it is replaced by the true one.

- **Two dormant defects in `lib/eip712.py`**, dormant because no vector touched them: `intN` was
  encoded without `signed=True`, so a **negative `int256` — a valid message — raised `OverflowError`**
  (a library that refuses a valid message is worse than one that crashes); and dynamic `bytes` was
  hashed as the JSON string object instead of the decoded content (`TypeError`). Both fixed; values
  outside the declared width now raise (→ `encoding_error` for the runner) instead of silently
  encoding. Cross-validated against `eth-account` 0.14.0.
- **053–055**: signed-integer minimum with `uint8` maximum and empty `bytes`; non-empty dynamic
  `bytes`; and an **undeclared field** — the message of 054 plus a key not in `types`, carrying the
  *same* signature, because `encodeData` concatenates the declared members and nothing else (both
  `eth-account` and this library ignore the field). 30 accept / 25 reject.
- **Two wrong statements removed.** The note of 027 said the recovery at `r = N−1` "is defined": it
  is not — `x = N−1` is not on the curve (`x³+7` is not a quadratic residue mod p), which is exactly
  why the runner classifies it `recovery_undefined`. And the cross-validation count "48 vectors" was
  stale since 1.0.1 (it is 53 now: all vectors whose message is encodable).
- Confirmed by the review, unchanged: `signer_mismatch` is the right class for 023/025/026 — an
  arbitrary `r` or `s` still recovers to *some* key, and `ecrecover` returns that address, so the only
  cryptographic reason to reject is that it is not the declared signer.
- **`tools/check_docs.py`, in CI**: the numbers in the README (vector counts, version, how many
  vectors the `eth-account` cross-validation can compare) are recomputed from the vectors, each
  vector's notes are checked against its own data, and the changelog must carry the manifest
  version. Why: "48 vectors compared" survived three releases because no gate ever read a sentence.
- Still open (missing coverage, not a wrong claim): EIP-191 / `personal_sign` vectors for the
  ERC-4361 sign-in flow. That needs a `format` dimension in the schema and runner; next release.

## 1.2.0 — 2026-09-11

Adversarial review by the same author (same day) of the whole v1.1.0. Three findings survived
verification and are fixed here; the others were checked against the code and rejected (r=0/s=0 are
vectors 013/014; the domain mapping in x402 PR #324 reads `extra` from the *resource server's*
requirements and settlement uses the contract's own domain on-chain).

- **`expected.reject_reason` — a reject must be for the declared reason.** The runner rejects
  everything it does not understand (input arrives from the network; raising is a denial of
  service), which means a *broken* vector — a mistyped key, a wrong type — also becomes a "reject",
  and if the vector expected "reject" it passed. Before this change, 049 and 050 (EIP-712 messages
  that cannot be encoded) were rejected with the **same reason as a failed ECDSA recovery** and
  nobody could tell. Now every reject vector declares one of six classes (`signature_malformed`,
  `signature_out_of_range`, `signature_high_s`, `encoding_error`, `recovery_undefined`,
  `signer_mismatch`; see `tools/reject_reasons.py`), declared **by hand per vector**, not derived
  from the runner; the runner classifies independently and a class mismatch is a FAIL. Fail-closed:
  a reject without a declared class fails the schema gate and the runner. Shown to fail in both
  directions (wrong declared class → FAIL; vector with a renamed `domain` key → `encoding_error`
  ≠ declared → FAIL). Encoding is now computed before and separately from recovery in `verify.py`.
  The 27 accept vectors are byte-identical.
- **`tools/discriminate_infinity.py`** — positive control of 051/052, in CI: simulates the two
  defective recoveries the vectors claim to catch (identity → `address(0)`; identity → keccak of 64
  zero bytes) and requires that both ACCEPT. A reject vector nobody could accept proves nothing.
- **052 note corrected.** `(0, 0)` is not a point of secp256k1 (0 ≠ 7 mod p) and the identity has
  no affine coordinates: the address is what a *software convention* for the neutral element
  produces when serialised as 64 bytes, not a mathematical serialisation of ∞.

## 1.1.0 — 2026-09-11

**52 vectors** (27 accept, 25 reject). Closes the last item left open by the review: recovery at the
point at infinity.

- **051–052 — recovery yields the point at infinity.** `Q = r⁻¹(sR − eG)` is the identity whenever
  `sR = eG`, and that is constructible without any private key: `R = kG`, `r = R.x`, `s = e·k⁻¹`
  (here `k = 2`, chosen so that `s` is low-s). The signature is well-formed in every syntactic
  respect — 65 bytes, `r` and `s` in range, low-s — so the **only** reason to reject is that the
  identity is not a public key. libsecp256k1 fails the recovery (`failed to recover ECDSA public
  key`). The declared `signer` is, in turn, the address a *defective* implementation would derive
  from ∞: `address(0)` (051, the Solidity `ecrecover` failure sentinel) and `keccak256(0x00 × 64)`
  = `0x3f17…5fb5` (052, the identity serialised as `(0, 0)`). Both defective mappings were
  simulated against the vectors and both would ACCEPT; `verify.py` rejects.
- **`lib/secp256k1.py`** now raises on the identity instead of returning `None`. Before this change
  the runner rejected only because of its blanket exception handler, and `public_key_to_address`
  would have raised a `TypeError` — the same class of defect the fuzzer caught in 1.0.1, one layer
  lower.
- `tools/check_manifest.py` ignores the local cross-validation venv (`.xval/`) — and, found while
  doing so, **now covers `.github/workflows/conformance.yml`**: the old exclusion matched `.github`
  as well as `.git`, so the CI definition was outside the integrity gate. 77 files declared.

## 1.0.1 — 2026-09-11

Pre-publication testing, and what it found.

- **EIP-712 encoding cross-validated against `eth-account` 0.14.0**: 48 vectors, 0 divergences. Until
  now the encoding had a single external oracle — the canonical `Mail` example in EIP-712 itself.
  One example is not coverage.
- **Runner hardening**: `tools/fuzz_runner.py` threw 600 malformed vectors at `verify.py` and found
  **79 unhandled `ValueError`s** — `fromhex` on an unvalidated string. A verifier that raises instead
  of rejecting is a denial of service, since the input arrives from the network. Now 600/600 rejected,
  0 exceptions, and the fuzzer runs in CI.
- **Reproducibility**: vectors regenerate byte-identical.
- **Clean-clone test**: a fresh `git clone` passes every gate with no local state.

## 1.0.0 — 2026-09-11

**50 vectors** (27 accept, 23 reject). The additions are not padding: each one is a documented way an
implementation goes wrong.

- **Exact curve boundaries** (023–029): `s = N/2`, `s = N/2+1`, `r = 1`, `r = N−1`, raw recovery ids.
- **Domain boundaries** (030–035): `chainId` 0 and max, zero `verifyingContract`, empty `name`/`version`,
  and **a domain without `version`** — the canonical Permit2 domain.
- **EIP-712 encoding** (036–040): empty array, single-element array, atomic types at their limits,
  lowercase vs checksummed address (the encoding uses the 20 bytes; hashing the *string* diverges
  silently).
- **The other x402 transfer methods** (041–045): Permit2 `PermitWitnessTransferFrom` with the spec's
  own witness types, a **tampered-witness** vector, nonce boundaries, degenerate validity window.
- **Robustness** (046–050): malformed signature lengths, missing message field, unknown `primaryType`.

**Three defects found in our own code by these vectors**, which is what they are for:
1. `lib/secp256k1.py` accepted a recovery id of `−27` (from `v = 0`) and returned a **fabricated**
   address where libsecp256k1 rejects. Found by the differential cross-validation. Fixed.
2. `verify.py` had the EIP-712 domain fields hard-coded to four, so every partial domain — including
   Permit2's — failed. Now derived from the domain actually present.
3. Vectors 049/050 initially passed *for the wrong reason* (rejected on a dummy signature rather than
   on the encoding). They now carry a syntactically valid signature, so the rejection comes from where
   the vector claims.

The JSON Schema was relaxed exactly where the vectors demanded it — optional `version`, unconstrained
signature length, nullable digests — and nowhere else.

## 0.3.0 — 2026-09-11

- **Negative differential fuzzing**: 600 degenerate inputs (`r=0`, `s=0`, `r≥N`, `s≥N`, out-of-range
  recovery id, random non-curve points) checked for *matching rejections* against libsecp256k1. The
  positive test alone only proved the happy path; the real risk is accepting what the reference
  refuses.
- **Layer separation**: every vector now carries `type_hash`, `domain_separator`, `hash_struct` and
  `signing_digest`, so the EIP-712 encoding can be tested independently of ECDSA recovery. A failing
  implementation learns *which* layer broke.
- **Four EIP-712 structural vectors** (019–022): array of structs, two-level nesting, NUL byte inside
  a string, referenced-type ordering in `encodeType`. Vector 019 immediately found a real gap: `lib/`
  did not implement array encoding at all and raised. Now implemented.
- **`signer` is declared, not inferred.** The runner used to guess the signer from field names
  (`from`, `owner`) — which silently breaks on any struct that names it otherwise.
- Vector 012 (inverted validity window) relabelled explicitly as a **boundary marker** between
  cryptography and policy, not a cryptographic test.

## 0.2.0 — 2026-09-11

- **Cross-validation** against independent reference implementations: Keccak-256 vs `eth-hash`
  (2000 cases) and recovery vs `coincurve`/libsecp256k1 (500 real signatures), zero divergences.
  The reference libraries are *not* a dependency of the suite — they are used only to show that
  `lib/` has no blind spot of its own.
- **Ten cryptographic edge cases** added (009–018): ECDSA malleability (high-s, EIP-2), uint256
  boundaries, inverted validity window, malformed signatures (`r=0`, `s=0`, `v` out of range,
  `r=N`), non-ASCII domain `name`, zero-address recipient.
- **Form checks before recovery** in `verify.py`: EIP-2 low-s, `r`/`s` range, `v` ∈ {27,28}. A
  verifier that only calls ecrecover accepts the malleable signature — the replay door.
- **JSON Schema** (`schema/vector.schema.json`) plus a stdlib validator. It immediately caught an
  id-naming inconsistency, which is what a schema is for.
- **CI**: integrity gate, schema, conformance run and audit on every push; cross-validation in a
  separate job; weekly scheduled run.

## 0.1.0 — 2026-09-11

- First 8 vectors (3 accept, 5 reject), fail-closed manifest, self-validating bench,
  audit of the signature examples in the x402 specifications.
