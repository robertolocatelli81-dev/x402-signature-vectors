# Positive control of the gates

**Measured:** 13 November 2026 with `tools/positive_control.py` (Python 3.11.2). Each sabotage is one textual patch,
applied exactly once to a fresh copy of the suite; the copy's `manifest.json` is regenerated so that the hash gate
cannot catch it by construction; then every offline gate of the `verify` job runs in the copy. Non-equivalence is
measured apart from the gates: **B1** = 264 seeded inputs built by the tool (not the vectors) through
`verdetto_da_testo()`; **B2** = the 84 vectors with their `expected` block corrupted one way each, through the
copy's `verify.py`. A column counts the inputs (B1) or rows (B2) whose answer differs from the intact copy's.

## Before `tools/test_runner_compares.py` existed

    sabotage                   caught by                                                   B1 diff  B2 diff
    keccak-padding             verify.py, genera_vettori_onchain.py, test_runner_schema.p      168       84
    low-s-skipped              verify.py, test_runner_schema.py                                 34        1
    low-s-boundary             verify.py, test_runner_schema.py                                 24        0
    domain-version-dropped     verify.py, test_runner_schema.py, discriminate_infinity.py      112       16
    encodetype-unsorted        verify.py, test_runner_schema.py                                 24        1
    v-raw-admitted             verify.py, test_runner_schema.py                                 24        0
    r-zero-admitted            verify.py, test_runner_schema.py                                 24        0
    json-reader-lax            verify.py, test_runner_schema.py                                 24        1
    array-length-unchecked     verify.py, test_runner_schema.py, fuzz_runner.py                 24        0
    string-nul-truncated       verify.py, test_runner_schema.py                                 24        0
    infinity-serialised        verify.py, test_runner_schema.py, discriminate_infinity.py       24        0
    signer-case-sensitive      verify.py, test_runner_schema.py                                 24        0
    runner-reason-ignored      NOT CAUGHT                                                        0       12
    runner-address-ignored     NOT CAUGHT                                                        0       12
    runner-schema-skipped      test_runner_schema.py                                             0       38
    catturati 13/15; non equivalenti sul lotto 15/15 (exit 1)

Two sabotages of the runner were invisible: with the comparison of the reject class, or of the recovered
address, switched off, every gate stayed green, because the committed vectors are all correct and no gate fed the
runner a wrong expectation. Both are real changes of behaviour (12 B2 rows each).
`tools/test_runner_compares.py` now plants a wrong class (009), a wrong address (005) and a flipped verdict (003)
in a copy and requires exactly that vector to fail.

## With it

    sabotage                   caught by                                                   B1 diff  B2 diff
    keccak-padding             verify.py, genera_vettori_onchain.py, test_runner_schema.p      168       84
    low-s-skipped              verify.py, test_runner_schema.py, test_runner_compares.py        34        1
    low-s-boundary             verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    domain-version-dropped     verify.py, test_runner_schema.py, test_runner_compares.py,      112       16
    encodetype-unsorted        verify.py, test_runner_schema.py, test_runner_compares.py        24        1
    v-raw-admitted             verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    r-zero-admitted            verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    json-reader-lax            verify.py, test_runner_schema.py, test_runner_compares.py        24        1
    array-length-unchecked     verify.py, test_runner_schema.py, test_runner_compares.py,       24        0
    string-nul-truncated       verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    infinity-serialised        verify.py, test_runner_schema.py, test_runner_compares.py,       24        0
    signer-case-sensitive      verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    runner-reason-ignored      test_runner_compares.py                                           0       12
    runner-address-ignored     test_runner_compares.py                                           0       12
    runner-schema-skipped      test_runner_schema.py                                             0       38
    
    catturati 15/15; non equivalenti sul lotto 15/15; 1039 s

The intact copy passes all 11 gates. Gate names are cut at 58 characters in the tool's output. The run took
1039 s; it is the `positive-control` job of `conformance.yml`.
