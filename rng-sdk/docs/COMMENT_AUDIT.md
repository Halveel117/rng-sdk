# Comment audit — 2026-08-21

A one-off sweep of every comment in `include/`, `tools/`, `tests/` and
`examples/` for **claims about behaviour that nothing verifies**.

## Why this was run

Four separate defects in this project traced to the same root cause — a
comment asserting a property, and no test bound to it:

| Comment claimed | Reality | Found by |
|---|---|---|
| a test crosses the 4 KiB refill boundary | none did | code review, 2026-08-18 |
| nonce repetition "blocked by ServerSession" | not blocked — SA-01, exploitable | security analysis, 2026-08-21 |
| xoshiro state "recoverable from 4 outputs" | true for `**`, unproven for our `++` | citation review, 2026-08-20 |
| HMAC-DRBG is backtracking-resistant | disproved for our configuration in 2019 | citation review, 2026-08-20 |

Two of those were security defects, one of them critical and directly
monetisable. That is a pattern, not a run of bad luck, and it is worth naming
precisely: **this codebase's comments carry design rationale, security
properties and proof sketches.** That is a genuine strength — it is why a
reviewer can follow our reasoning — but it means our comments make
*falsifiable assertions*. "Increments the counter" cannot be wrong. "Nonce is
strictly monotonic — enforced" is a testable claim wearing documentation's
clothes.

## Method

Grepped all comment lines for claim vocabulary in two passes —
`enforce/guarantee/ensure/never/always/cannot/must/impossible`, then
`exactly/proven/verified/validated/tested/covers/identical`, then a third for
`prevents/protects/safe/unreachable/unbiased/by construction`. Every hit was
checked against what the code actually does and against the test suite.

## Findings

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| **CA-01** | **High** | `provably_fair.hpp` credited nonce monotonicity to a class called **`VerifierSession` that does not exist anywhere in the codebase**. The claim was doubly false: no such enforcer, and (until SA-01 was fixed) no enforcement at all. | Comment rewritten to credit `ServerSession` and name the test. |
| **CA-02** | Medium | The same bullet described the nonce as monotonic *per (server, client) pair* — the design that **produced** the replay bug, left stale by yesterday's fix. | Corrected to per-session, never rewound. |
| **CA-03** | **High** | `xoshiro256pp.hpp` claimed jumped streams have "guaranteed non-overlap", the property per-thread parallel use depends on. The only test did `j1.Jump(); CHECK(j1.Next() != j2.Next())` — one inequality, which a **wholly incorrect jump would also pass**. `LongJump()` had **no coverage at all**. | Golden vectors added from an independent Python transcription of the reference C. **The port is correct** — this was a coverage gap, not a bug. |
| **CA-04** | Low | `splitmix64.hpp` claimed a bijection on `uint64` so "distinct seeds never collide". Untested, and **load-bearing**: `MATH_JUSTIFICATION` Prop 4.2 uses it to prove the forbidden all-zero xoshiro state is unreachable. | `TestSplitMix64Injective` added; comment now gives the invertibility argument and names the test. |
| **CA-05** | Low | `provably_fair.hpp` referred to `NextIntUnbiased`; the function is `NextIntsUnbiased`. | Corrected. |
| **CA-06** | Low | `provably_fair.hpp` called nonce reuse "a real, exploited failure mode in the wild" — a factual claim about the world with **no source**. Written by us. | Removed; the file now points at `SECURITY_ANALYSIS.md` §5.1, where the exploit is demonstrated on our own code rather than asserted about someone else's. |

### Claims checked and found sound

Recorded so the sweep is falsifiable rather than a list of only bad news:

* SHA-256 "validated against FIPS 180-4 … cross-checked against hashlib" — `TestSha256`, four vectors including the 1M-'a' streaming case. ✅
* HMAC "validated against RFC 4231" — `TestHmac`, cases 1, 2 and 6 (6 exercises the >block-size key path). ✅
* PCG64 "cross-validated word-for-word against numpy.random.PCG64 by state injection" — `TestPcg64`. ✅
* xoshiro256++ core "verified against an independent transcription" — `TestXoshiro`. ✅
* HMAC-DRBG "cross-validated against an independent Python" — `TestHmacDrbg` + 12 NIST CAVP vectors. ✅
* `Source::Fill` "splitting a run across calls must not change the byte sequence" — `CheckStreamChunkingInvariant`. ✅
* `HmacDrbg` "SP 800-90A limits enforced" — `kMaxBytesPerRequest = 2^16` bytes = 2^19 bits, `kReseedInterval = 2^48`, both throwing. ✅
* Lemire "eliminates modulo bias exactly" — proven (`MATH_JUSTIFICATION` §3, Thm 3.4), demonstrated by `TestModuloBiasDemo`. ✅
* `OsEntropy` "never truncate and silently succeed" — `TestOsEntropy` covers chunking past the 256-byte `getentropy` cap. ✅

### Not a finding, but noted

`tools/` binaries (`benchmark.cpp`, `pi_monte_carlo.cpp`, `verifier_cli.cpp`)
carry no claim-bearing comments — they describe usage, not guarantees. The
one exception, "a volatile sink prevents the optimizer eliding the loop"
(`benchmark.cpp`), is an implementation-technique claim verifiable by
inspection and is left as-is.

## The convention going forward

Two kinds of comment, treated differently:

* **Explanatory** — why a choice was made, what a formula means, what a
  trade-off costs. No obligation. Write as many as the reader needs.
* **Claim-bearing** — anything asserting the code *does*, *enforces*,
  *guarantees*, *never*, or *always*. Each of these MUST either
  1. name the test that proves it, or
  2. be attributed to a citation (a property of the algorithm, not of our
     port — and note that our *port* then needs its own vector), or
  3. be softened into a non-claim.

`ServerSession` and `Xoshiro256pp` now model this: a block at the top of the
class listing each guarantee next to the test that holds it up.

**A comment asserting coverage is not coverage.** The reviewer who caught the
4 KiB defect checked the arithmetic, not the comment — which is exactly why
they found it.

## Effect on the statistical batteries

**None.** Every change here is a comment, a test, or a golden vector. No
generated byte moved:

* all six rows of `docs/statistical_results/fingerprints.txt` regenerate
  identically, `pf` included;
* `Jump`/`LongJump` are not referenced anywhere in `tools/`, so the battery
  path never touched the one finding that could have implied a code change —
  and that port turned out to be correct in any case.

Suites after the audit: **666,654 bundled / 889,380 OpenSSL**, both
warning-free.
