# Statistical battery results

Landing area for the outputs of the four batteries required by the spec
(NIST SP 800-22, Dieharder, TestU01, PractRand). Runs are executed on a
second machine per `docs/statistical_testing_runbook.md`; this directory
holds what comes back.

Present now:

- `fingerprints.txt` — the cross-platform determinism handshake. Pinned by a
  test in `tests/test_main.cpp`, so a byte change anywhere in an engine's
  output path fails the build rather than silently invalidating a battery run.

Expected, one subdirectory per battery, named for the tool:

- `nist_sts/` — final analysis reports, one per source
- `dieharder/` — full `-a` output, one per source
- `testu01/` — SmallCrush / Crush driver output, one per source
- `practrand/` — `RNG_test` stdout to the fold at which each run was stopped

Six sources are streamed by `rng_stream`: `xoshiro`, `pcg64`, `hmac`, `ctr`,
`pf`, and `randu`. The last is a deliberately defective generator included as
a positive control — a battery that does not fail `randu` has not been run
correctly, which is the only way to tell a passing suite from an inert one.

Adjudication rules for borderline p-values are in the runbook, fixed in
advance of the runs so a marginal result cannot be argued either way after
the fact.
