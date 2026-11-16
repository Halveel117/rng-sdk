# Statistical test batteries — design (OPEN_RESEARCH item #3)

Date: 2026-08-18. Status: approved, pre-implementation.

## 1. Purpose

The SDK is validated today by *known-answer* testing: given input X, does the
code emit exactly the bytes the standard says? That proves conformance. It
proves nothing about whether the output *looks* random.

Statistical batteries supply the missing evidence. They consume a raw byte
stream and hunt for structure that should not be there. Three reasons this
item ranks above the remaining ones:

* It is the last open item that can **find a defect**. Everything else open
  (#5–#10) documents or extends what exists.
* It supplies the **quality** column of the two-tier pitch. The speed column
  is measured (DESIGN_NOTES §8/§8b); quality is currently an appeal to the
  algorithm authors' published results, not to our port.
* It is the artefact a licensee's technical reviewer asks for first.

Spec requirement: NIST SP 800-22, Dieharder, TestU01 (≥ SmallCrush, Crush
preferred), PractRand.

## 2. Success criteria

1. A pass/fail matrix: every source × every battery.
2. Raw logs committed under `docs/statistical_results/`, so results are
   auditable rather than asserted.
3. A p-value analysis. Under the null hypothesis p-values are uniform on
   [0,1]; across ~160 tests a handful of marginal results is *expected*.
   "Zero failures out of 160" is a claim to distrust, not to celebrate.
4. A methodology section: tool versions, seeds, sample sizes, and how
   marginal results were adjudicated. Without it the matrix is unfalsifiable.
5. The negative control fails (§4).

## 3. What gets tested

The SDK is not one source of bytes. Five distinct code paths:

| Source | Path exercised | Depth |
|---|---|---|
| `xoshiro` | `Random<Xoshiro256pp>::NextBytes` | deep |
| `pcg64` | `Random<Pcg64>::NextBytes` | deep |
| `pf` | `pf::ByteStream` over incrementing nonces | deep |
| `randu` | deliberately broken control (§4) | deep |
| `hmac` | `Random<HmacDrbgEngine>::NextBytes` | shallow |
| `ctr` | `Random<CtrDrbgEngine>::NextBytes` (OpenSSL builds) | shallow |

**Why the crypto tier is shallow.** Both engines already match NIST CAVP
vectors byte for byte — a strictly stronger claim than "no pattern found".
If a conformant HMAC-DRBG's output were distinguishable from random, that
would be a break of SHA-256, not a finding available on a laptop. Cost is
also prohibitive: BigCrush consumes ~10^11 numbers, and HMAC-DRBG emits
2.31e6/s, so generation alone is ~12 hours before TestU01 computes anything.

**Why shallow is not zero.** CAVP validates the DRBG *core*. It does not
validate our engine adapter, which buffers 4 KiB per DRBG request and hands
out slices. A fault there — a slice replayed instead of refilled, an
off-by-one on refill — passes every CAVP vector (they test single generate
calls) while making the real stream repeat every 4 KiB. That bug class is
**gross**: it dies in the first megabyte of PractRand. So the crypto tier
needs a short run, not a long one.

Consequence: the crypto tier must be streamed through `Random::NextBytes`,
never the raw DRBG, or the buffering layer is not in the path at all — which
would omit the only plausible defect.

`NextBytes` is used for all engine sources for the same reason: it is what a
consumer actually calls, and it is where a mapping-layer bug would live.

## 4. The negative control

If every source passes, how do we know the harness works? A miswired pipeline
passes everything. So one source is a generator known to be broken: RANDU
(x ← 65539·x mod 2^31, IBM 1968), whose consecutive triples lie on 15 planes
in 3-space. It **must** fail. If it passes, the harness is broken and every
other result in the report is void.

**Bit-layout decision.** `RanduBad::Next()` in `tools/pi_monte_carlo.cpp`
returns the 31-bit state shifted left 33, so the low 33 bits are always zero.
That is correct for the π study (which reads only `NextDouble`), but as a
byte stream it is half constant zeros — every battery would reject it in the
first kilobyte for a trivial reason, demonstrating nothing about the harness's
ability to detect *structure*. The stream tool therefore emits the **top 16
bits** of each RANDU output (two bytes per step). No structurally constant
bits remain, and the lattice defect survives in the high bits — which is
precisely where the spectral test looks for it. The control then fails for
the right reason.

Refactor: `RanduBad` moves from `tools/pi_monte_carlo.cpp` to a shared
`tools/randu_bad.hpp` so both tools use one definition. It stays out of
`include/rngsdk/` deliberately — a deliberately broken generator must not be
reachable from the shipped SDK headers.

Note the control does **not** route through `Random<Engine>::NextBytes` as the
engine sources do, so it validates the *batteries* rather than the
engine-to-stdout wiring. That is the right trade-off: routing RANDU through
the mapping layer would reintroduce the 33 constant zero bits and destroy the
control's value. The wiring itself is covered by the unit tests, which assert
each engine source equals the SDK call it advertises.

## 5. The Provably Fair stream

`pf::ByteStream` is separate code from every engine, untested by anyone
outside this project, and it is the stream that decides real bets. Its
plausible defects are in the nonce→block mapping, so the tool must exercise
the *realistic usage pattern*: emit a fixed number of bytes per nonce, then
increment the nonce. Streaming a single nonce's cursor forever would test the
cursor path and miss the nonce path entirely.

Default: 32 bytes (one HMAC block) per nonce, `--pf-bytes-per-nonce` to
override. Correlation between adjacent nonces is the killer bug, and this
layout is what would expose it.

## 6. The one new component: `tools/stream.cpp` → `rng_stream`

No existing tool emits raw bytes: `rng_verifier` prints hex, `rng_pi` prints
statistics, `rng_bench` prints timings. The batteries need bytes on stdout
and nothing else.

```
rng_stream --source <name> [--seed N] [--bytes N] [--pf-bytes-per-nonce N]
```

* `--source` — one of `xoshiro pcg64 hmac ctr pf randu`. Required.
* `--seed` — default 1. For `pf`, derives the server/client seeds
  deterministically so a run is reproducible from the seed alone.
* `--bytes` — byte count, accepts `K`/`M`/`G` suffixes. Omitted = stream
  until the pipe closes (what PractRand wants).
* Unknown arguments are a hard error. A tool that silently defaults after a
  typo produces a log that names one source and tests another.

stdout is binary and carries *only* stream bytes; diagnostics go to stderr.
On Windows stdout must be switched to binary mode or `0x0A` becomes `0x0D 0x0A`
and every battery sees corrupted data.

`ctr` is only available in OpenSSL builds; requesting it otherwise is a clear
error, not a silent substitution.

**Endianness note.** `Random::NextBytes` `memcpy`s a `uint64` in native order,
so its byte stream differs on a big-endian host. Both test machines are x86,
so the handshake (§7) is unaffected. Recorded because it is a genuine
portability property of a licensed SDK — and because `pf::ByteStream` is
*not* affected (HMAC output has a defined byte order), which is the half that
matters for cross-platform Provably Fair verification.

## 7. Cross-platform determinism handshake

Runs happen on a macOS machine with clang; development is Windows with MSVC.
Before any battery runs, both builds must be shown to produce identical
bytes — otherwise every returned log is unattributable.

`rng_stream --source <s> --seed 1 --bytes 32`, hex-dumped, for every source.
Expected values are committed as `docs/statistical_results/fingerprints.txt`
and checked by `rng_tests`, so a regression breaks the build rather than
being discovered by a collaborator.

This doubles as the cross-compiler determinism evidence item #9 requires.

## 8. Depth matrix and division of labour

All battery runs execute on the collaborator's macOS machine (stronger
hardware; the development laptop is a 2-core 2.4 GHz Athlon with 3.4 GB RAM,
where deep runs would take days at full load). No WSL install is needed.

If that machine is Apple Silicon it also supplies the project's first ARM64
data point, which open item #9 needs for the spec's "results across CPU
architectures" requirement — one asset serving two deliverables. Byte output
is unaffected: ARM64 is little-endian, so §7's fingerprints must still match
exactly, and a mismatch would be a genuine portability bug rather than an
expected platform difference.

| Battery | Deep sources | Shallow sources |
|---|---|---|
| NIST SP 800-22 | full (125 MB) | full (125 MB) |
| Dieharder | `-a` full | `-a` full |
| TestU01 | SmallCrush → Crush → BigCrush | SmallCrush |
| PractRand | to 256 GB or first failure | to 8 GB |

NIST STS and Dieharder are cheap enough that restricting them buys nothing.
TestU01 and PractRand carry the cost, so that is where the tiering applies.

## 9. Deliverables

| Artefact | Owner |
|---|---|
| `tools/stream.cpp`, CMake target, tests | this repo |
| `tools/randu_bad.hpp` (extracted) | this repo |
| `docs/statistical_results/fingerprints.txt` | this repo |
| `docs/statistical_testing_runbook.md` | this repo, for the collaborator |
| Raw battery logs | collaborator → `docs/statistical_results/` |
| Pass/fail matrix, p-value analysis, methodology | report (§3 of the final report) |

## 10. Out of scope

* Automating battery installation. The runbook is instructions, not a script;
  a script that silently fails on a different distro is worse than a list.
* Running the batteries in CI. They take days.
* Multi-threaded generation. Streams are single-threaded by design; threading
  is item #9.
