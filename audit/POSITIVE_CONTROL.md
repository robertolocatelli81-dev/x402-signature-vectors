# Positive control of the gates

**Measured:** 13 November 2026 with `tools/positive_control.py` (Python 3.11.2). Each sabotage is one textual patch,
applied exactly once to a fresh copy of the suite; the copy's `manifest.json` is regenerated so that the hash gate
cannot catch it by construction; then every offline gate of the `verify` job runs in the copy (12 since 13/11, the
first two tables ran 11: `tools/test_check_manifest.py` was not in the list). Non-equivalence is
measured apart from the gates: **B1** = seeded inputs (264 in the first two tables, 312 in the third) built by the tool (not the vectors) through
`verdetto_da_testo()`; **B2** = the 84 vectors with their `expected` block corrupted one way each, through the
copy's `verify.py`. A column counts the inputs (B1) or rows (B2) whose answer differs from the intact copy's.

## Before `tools/test_runner_compares.py` existed (11 gates, B1 = 264)

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

## With it (11 gates, B1 = 264)

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

## After the review of 13 November 2026 (12 gates, B1 = 312, B2 in five ways)

The review found four sabotages that every gate let through: a wrong `expected.type_hash` or
`expected.domain_separator` in a vector (no gate read them), `NaN`/`Infinity` read as numbers, and a struct named
`string` or `bool`. The runner now checks the four intermediate values and `tools/fuzz_runner.py` reads the constants
and every atomic struct name; three of the four are sabotages of the tool (the first is a sabotage of the data, caught
by `tools/test_runner_compares.py`). B1 gained two inputs per round (a non-JSON constant, an atomic struct name) and B2 a
fifth way (a wrong `type_hash`), so the B1 and B2 columns are not comparable with the tables above.

    sabotage                   caught by                                                   B1 diff  B2 diff
    keccak-padding             verify.py, genera_vettori_onchain.py, test_runner_schema.p      168       84
    low-s-skipped              verify.py, test_runner_schema.py, test_runner_compares.py        35        1
    low-s-boundary             verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    domain-version-dropped     verify.py, test_runner_schema.py, test_runner_compares.py,      126       20
    encodetype-unsorted        verify.py, test_runner_schema.py, test_runner_compares.py        24        1
    v-raw-admitted             verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    r-zero-admitted            verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    json-reader-lax            verify.py, test_runner_schema.py, test_runner_compares.py,       48        1
    array-length-unchecked     verify.py, test_runner_schema.py, test_runner_compares.py,       24        0
    string-nul-truncated       verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    infinity-serialised        verify.py, test_runner_schema.py, test_runner_compares.py,       24        0
    signer-case-sensitive      verify.py, test_runner_schema.py, test_runner_compares.py        24        0
    runner-reason-ignored      test_runner_compares.py                                           0       10
    runner-address-ignored     test_runner_compares.py                                           0        9
    runner-schema-skipped      test_runner_schema.py                                             0       36
    nan-admitted               fuzz_runner.py                                                   24        0
    struct-named-string        fuzz_runner.py                                                   24        0
    runner-layers-ignored      test_runner_compares.py                                           0       11

    catturati 18/18; non equivalenti sul lotto 18/18

A sabotaged copy that cannot answer B1 at all (a patch that breaks the import) now stops the tool: the first run of
`runner-layers-ignored` had such a patch and was counted as non-equivalent with B1 = -1. The intact copy passes all 12
gates. Gate names are cut at 58 characters in the tool's output. It is the `positive-control` job of
`conformance.yml`; the full run took 1785 s on the measuring machine (13/11/2026).
