# Open items: research and documentation checklist

What separates this prototype from the licensable deliverable. "Docs" = goes
in the math justification or final report; "Eng" = implementation work.
Effort in person-days.

Item numbers are cited from source comments and other documents, so they are
stable. Numbers are never reused or renumbered.

## Status at a glance

| # | Item | Status | Landed in |
|---|---|---|---|
| 1 | Entropy sourcing | RESOLVED 2026-08-14 | `crypto/os_entropy.hpp` |
| 2 | AES-CTR-DRBG | RESOLVED 2026-08-15 | `crypto/ctr_drbg.hpp`, `CtrRandom` |
| 3 | Statistical batteries | **HARNESS DONE, RUNS PENDING** | `rng_stream`, runbook |
| 4 | CAVP vectors | SUBSTANTIALLY RESOLVED 2026-08-15 | `tests/golden/golden_cavp.hpp` |
| 5 | Math justification | DELIVERED 2026-08-20 | `MATH_JUSTIFICATION.md` |
| 5b | ServerSession reveal-lock | RESOLVED 2026-08-15 | `provably_fair.hpp` |
| 6 | Security analysis | DELIVERED 2026-08-21 | `SECURITY_ANALYSIS.md` |
| 6b | Comment audit | DELIVERED 2026-08-21 | `docs/COMMENT_AUDIT.md` |
| 7 | ODE Monte Carlo | DELIVERED 2026-08-24, audited 08-27 | `ODE_MONTE_CARLO.md`, `rng_ode` |
| 7b | Spec traceability gaps | CLOSED 2026-09-12 | table below |
| 7c | Full traceability matrix | PASS DONE 2026-08-24 | table below |
| 8 | Web and library verifiers | DELIVERED 2026-09-03 | `web/verifier.html`, `c_api/` |
| 9 | Multithreading and platforms | DELIVERED 2026-09-12, both machines | `rng_thread_bench` |
| 10 | Report assembly | **OPEN** | |
| 11 | OpenSSL HMAC call pattern | **FIXED** x86_64 2026-09-13; ARM64 re-run owed | |
| 12 | HMAC-DRBG additional input | DECIDED 2026-09-07, accepted not fixed | `SECURITY_ANALYSIS.md` 4.2 |

Two items remain open on the critical path: the battery runs (#3) and the
report (#10). The "Open follow-ups" section at the end collects the smaller
deferrals that live inside otherwise-closed items, so they are findable
without reading every entry.

## Constraints that still bind

Claims the evidence does not support, collected here because each was
established at cost and each is easy to over-state when assembling #10.

* **CTR-vs-HMAC has no single value. Quote it with its platform: ~13x on
  x86_64, ~31x on ARM64.** Both are correct for their own machine, measured
  the same way, against the bundled HMAC denominator. On x86_64 specifically,
  12.9x and 13.6x are one quantity measured twice and a third significant
  figure is not measurable on that hardware. Never cite 27.8x, which compares
  against the OpenSSL HMAC row and is itself slowed by #11, or 14.6x, which is
  supported by nothing in the repository. A bare "~13x" in the report is now a
  defect too, since it presents one machine's figure as the SDK's.
* **The crypto tier is not backtracking-resistant** and does not offer
  SP 800-90A prediction resistance. Neither may be asserted. See #12.
* **No engine is separable from any other on stability.** At R=25 the sample
  SD carries +/-14.4% of its own sampling uncertainty, so the report must not
  rank engines on that axis. The honest finding is that all five sound engines
  are indistinguishable, which is the expected and correct result.
* **Do not write "pi convicts RANDU".** RANDU's slope CI excludes -0.50 in
  exactly one place, pi-3D, and RANDU is single-orbit, so its repeats overlap
  and the nominal standard error understates the true one. The supported claim
  is that with repeats, pi's 3D estimator resolves RANDU, consistent with a
  three-dimensional defect. The serial box test (chi2/df 10 to 93) is what
  convicts it outright.
* **Benchmarks are load-sensitive more than they are hardware-limited.** Idle
  machine, at least 4 runs, report median and spread. A number taken while a
  build was running is not a measurement.
* **No static OpenSSL artifact exists.** The procedure is documented; the
  artifact has not been produced. Nothing in the repository claims otherwise.

## 1. Entropy sourcing, RESOLVED 2026-08-14

`crypto/os_entropy.hpp`: `OsEntropy()` and `OsEntropyFill()` consume the
platform CSPRNG (BCryptGenRandom, getrandom(2), getentropy(3),
/dev/urandom). No conditioning, since OS output is full-entropy and
H(f(X)) <= H(X). No fallback: it throws on failure, and `std::random_device`
was eliminated. `SecureEntropy()` returns 48 OS bytes; `HmacDrbgEngine()` and
`CryptoRandom` default-construct OS-seeded, while an explicit seed stays
deterministic and leaves golden vectors unchanged; `pf::GenerateServerSeed()`
returns a 256-bit hex seed. Windows links bcrypt, with `BCryptGenRandom`
declared directly rather than via `<windows.h>`, so the public header does not
reshape a consumer's Win32 macros. 21 contract tests.

SP 800-90B obligations are delegated to the platform, the consume-not-own
argument, stated in `SECURITY_ANALYSIS.md`.

The weak-server-seed follow-up this item deferred was closed by SA-02 (#6).
The remaining one is under Open follow-ups.

## 2. AES-CTR-DRBG, RESOLVED 2026-08-15

`crypto/ctr_drbg.hpp` (SP 800-90A 10.2.1, AES-256, **no derivation
function**), `crypto/ctr_drbg_engine.hpp` adapter, and `rngsdk::CtrRandom`.
AES comes from OpenSSL `EVP_aes_256_ecb`, a raw block cipher on a counter we
manage, never hand-rolled, for cache-timing and audit reasons. Guarded by
`RNGSDK_USE_OPENSSL`; the bundled build is unaffected.

No-df was chosen because our seed material is exactly seedlen (48 B) of
full-entropy OS output, so a derivation function would be pure overhead, and
NIST publishes CAVP vectors for this exact configuration.

Validated against 12 NIST CAVP `[AES-256 no df]` vectors, covering both the
zero-length section and `PersonalizationStringLen=384,
AdditionalInputLen=384`. Measured ~13x faster than HMAC-DRBG, inside the
predicted 5-20x band.

Code review of the first cut caught two SP 800-90A conformance defects, both
fixed and both now covered by vectors that would have caught them.
`Instantiate` and `Reseed` concatenated personalization and additional input
where 10.2.1.3.1 and 10.2.1.4.1 mandate zero-pad-then-XOR for no-df, which is
invisible to zero-length vectors because the two constructions agree there.
Short entropy was silently zero-extended instead of rejected; `entropy.size()`
must now be exactly seedlen. **A KAT suite only validates the paths its
vectors exercise.** Check the parameter matrix, not the pass count.

`CtrDrbg` also gained move semantics so `std::vector<CtrRandom>` works for
per-thread pools.

## 3. Full statistical batteries, HARNESS DONE 2026-08-18, RUNS PENDING

Required by spec: NIST SP 800-22, Dieharder, TestU01 (SmallCrush minimum,
Crush preferred), PractRand. Design:
`docs/design/2026-08-18-statistical-batteries-design.md`.

**Delivered:** `tools/stream.cpp` to `rng_stream`, emitting raw bytes on
stdout for six sources (`xoshiro pcg64 hmac ctr pf randu`);
`tools/stream_sources.hpp`; `tools/randu_bad.hpp`;
`docs/statistical_testing_runbook.md`, with install steps, exact commands, and
p-value adjudication rules fixed in advance of the runs so a marginal result
cannot be argued either way afterwards; and
`docs/statistical_results/fingerprints.txt`, the cross-platform determinism
handshake, pinned by `TestStreamFingerprints`.

Engine sources stream `Random<Engine>::NextBytes`, the consumer-facing call,
so the mapping layer and the DRBG engines' 4 KiB buffering are both inside the
tested path. That buffering is precisely what CAVP does not cover: CAVP
validates the DRBG core, and a fault in the adapter would pass every official
vector while making the real stream repeat every 4 KiB. Hence the crypto tier
gets shallow runs rather than none. That bug class is gross and dies in the
first megabyte, whereas a subtle statistical flaw in a conformant HMAC-DRBG
would be a break of SHA-256.

`randu` is the negative control and must fail. If it passes, the harness
cannot detect failure and every other result is void. It emits the top 16 bits
of each 31-bit output rather than the raw engine word, which carries 33
constant zero bits, so it fails for the lattice defect rather than for stuck
bits.

**Runs are pending** on the collaborator's macOS machine. Remaining
deliverable: pass/fail matrix, p-value distribution analysis, methodology
section. Results land in `docs/statistical_results/`, layout described in the
README there.

Bug found while building this: `RanduBad::Seed` used
`(seed % 0x7FFFFFFF) | 1`, which is not injective, so seeds 4 and 5 and every
adjacent even/odd pair collapsed to one state. Fixed to `2*(seed % 2^30) + 1`,
a bijection onto the odd residues mod 2^31. `rng_pi` shared the defect, since
its RANDU rows use consecutive seeds `777+e`, so the N=10^5 and N=10^6 rows
were secretly the same sequence. `docs/pi_results.*` regenerated, conclusion
unchanged.

## 4. CAVP vector validation, SUBSTANTIALLY RESOLVED 2026-08-15

`tests/golden/fetch_cavp.py` downloads NIST's drbgtestvectors.zip, parses
`drbgvectors_no_reseed`, and emits `tests/golden/golden_cavp.hpp`. Both crypto
engines run 12 official CAVP vectors each, HMAC_DRBG `[SHA-256]` and CTR_DRBG
`[AES-256 no df]`, following the CAVP procedure: instantiate, discard the
first Generate, compare the second. Both passed on first run, which
independently confirms the earlier Python cross-validation was not a shared
misreading.

The generator asserts the section parameters it depends on, so a re-fetch
against a changed upstream file fails loudly instead of silently testing
nothing.

Remaining: the `pr_true` and `reseed` vector families are not exercised,
because the SDK does not implement prediction-resistance-on-demand. Whether to
add that capability or document its absence is a product decision. Whether
formal ACVP/FIPS validation is worth pursuing commercially is a lab
engagement, not a code task.

## 5. Mathematical justification, DELIVERED 2026-08-20

`docs/MATH_JUSTIFICATION.md`, 8 sections: algorithm descriptions, uniformity
proofs (lane-counting for Lemire, preimage counting for doubles), period
analysis (xoshiro 2^256-1 via characteristic polynomial primitivity, Blackman
and Vigna 2019; PCG64 2^128 per stream by Hull-Dobell; DRBG at least
2^48 * 2^19 bits between reseeds), entropy and collision analysis, avalanche,
and security reductions.

Two errors in the original plan for this document, both corrected there:

* **The birthday figure was wrong.** n = 2^32 seeds in a 64-bit space is
  precisely the birthday point, P(collision) ~= 1 - e^(-1/2) ~= **39.3%**, not
  2^-64. The 2^-64 figure is the probability that one specified pair collides,
  not that any pair does. The operative numbers are in 5.1: a 64-bit seed space
  reaches P ~= 10^-6 at only ~6.1e6 seeds, which is why the 64-bit `Seed()`
  path is a reproducibility facility and PF server seeds are 256-bit.
* Woodage and Shumow is EUROCRYPT **2019** (ePrint 2018/349), and it is not a
  supporting citation. See #12.

## 5b. ServerSession reveal-lock, RESOLVED 2026-08-15

`ServerSession::Play()` throws if called after `Reveal()`. `Reveal()` sets a
`revealed_` flag and is no longer `const`, since it now mutates state. Ported
from the same guard in the teammate's Python prototype. Test:
`TestRevealLock`.

Player-side replay through the free `Generator::NextFloats` functions is
untouched, which is the correct scope, since replay verification legitimately
happens after reveal.

## 6. Security analysis, DELIVERED 2026-08-21

`docs/SECURITY_ANALYSIS.md`: 10 sections, threat model A1/A2/A3, findings
register SA-01 to SA-10. Covers the full spec list: seed recovery, next-value
prediction, state compromise, nonce attacks, seed reuse, timing side channels,
commitment grinding economics.

SA-01, SA-02, SA-03 and SA-07 were fixed the same day, test-first, with all
four regression tests watched failing before implementation. The three
original findings, kept because the reasoning is what matters:

* **SA-01 (CRITICAL, demonstrated).** `SetClientSeed()` reset `next_nonce_` to
  0 with no record of used `(server, client)` pairs, so re-selecting a
  previously played client seed replayed the identical outcome sequence.
  Exploit: probe at minimum stakes, reset, bet maximum on the known winners.
  **Fixed by removing the reset entirely**, not by the `std::set` guard first
  proposed. Letting the nonce run monotonically makes seed reuse harmless
  rather than forbidden, so the guarantee needs no bookkeeping, is O(1) memory,
  and cannot be worn down by a player spamming seed changes. A rule somebody
  must remember to enforce is weaker than a design in which the dangerous
  action does nothing. The fix surfaced a second route to the same bug, a
  server restart re-instantiating at nonce 0, hence the optional `start_nonce`
  constructor argument and the operator obligation to persist the nonce
  alongside the seed.
  This file previously claimed nonce repetition was "blocked by
  ServerSession". That claim was false, asserted in a header comment and never
  tested. It is the second instance in this project of a comment standing in
  for coverage, and it is why #6b exists.
* **SA-02 (HIGH).** No entropy floor on the server seed. The published
  commitment is a free offline brute-force oracle, and an 8-character lowercase
  seed falls in ~20 s at 1e10 SHA-256/s. Fixed via `kMinServerSeedChars = 32`.
  Length is an explicit proxy: it stops a hand-typed seed, not a long one
  derived from a counter. The real rule is to use `GenerateServerSeed()`, and
  the floor makes the common accident loud.
* **SA-03 (MEDIUM).** `client_seed_` defaulted to `"default"`, so an integrator
  who never called `SetClientSeed` handed the operator a known client seed at
  commit time, collapsing the anti-grinding defence while the scheme still
  looked correct. Fixed: `Play()` throws until a client seed is set explicitly.
  **Only the library half is closeable here.** We receive a `std::string` and
  cannot tell a browser-generated seed from a server-generated one, so the
  integration guide carries it as a MUST.

Research result feeding #10 and the two-engine pitch: Woodage and Shumow prove
robustness for the HMAC and Hash constructions but could not for CTR_DRBG, and
found an attack on its prediction resistance. Cohney et al. (S&P 2020) confirm
at design level and recommend HMAC or Hash where FIPS compliance is required.
CTR-DRBG's ~13x speed advantage is therefore bought partly with weaker
provable guarantees, so `CryptoRandom` stays aliased to HMAC-DRBG. Audited
against Cohney's four countermeasures: 2 of 4 met, AES-NI verified by
measurement and the 4 KiB request cap. The two gaps, never reseeds and never
supplies additional input, are #12.

## 6b. Comment audit, DELIVERED 2026-08-21

`docs/COMMENT_AUDIT.md`. One-off sweep of every comment in `include/`,
`tools/`, `tests/` and `examples/` for claims about behaviour that nothing
verifies, run because four separate defects, two of them security issues and
one critical, all traced to the same root cause.

Six findings, all fixed. The two that mattered: `provably_fair.hpp` credited
nonce monotonicity to a `VerifierSession` class that does not exist anywhere
in the codebase (CA-01); and `xoshiro256pp.hpp` claimed jumped streams are
non-overlapping, the property per-thread parallel use depends on, while the
only test asserted a single inequality that a wholly incorrect jump would also
pass, with `LongJump()` uncovered entirely (CA-03). CA-03 was fixed with
golden vectors from an independent Python transcription, and the port turned
out to be correct, so it was a coverage gap rather than a bug. Nine claims
were also checked and found genuinely backed, so the sweep is falsifiable
rather than a list of only bad news.

**Convention now in force.** Explanatory comments are free. Claim-bearing
comments, anything asserting `does`, `enforces`, `guarantees`, `never` or
`always`, must name a test, cite a source, or be softened. `ServerSession` and
`Xoshiro256pp` model it with a guarantee-to-test block at the top of the
class.

## 7. ODE Monte Carlo, DELIVERED 2026-08-24

`docs/ODE_MONTE_CARLO.md`, tool `rng_ode`, estimator `tools/ode_solver.hpp`,
results `docs/ode_results.{txt,csv}`, design spec
`docs/design/2026-08-24-ode-monte-carlo-design.md`.

Volterra form plus von Neumann-Ulam, the spec's recommended option 1. The
boundary-value and Feynman-Kac routes were rejected because y'' = -y is
Helmholtz, so the path weight grows rather than decays. Importance sampling
collapses the per-step weight to the constant -x^2/2; Russian roulette makes
the estimator exactly unbiased, which is what allows every observed deviation
to be attributed to variance or RNG defect rather than to method.

**The result worth carrying into the report is a sensitivity threshold rather
than a pass/fail.** Both broken controls fail, three orders of magnitude
apart: LCG5's ~7e-2 floor is obvious at N=1e4, RANDU's ~4e-4 floor needs N of
1e6 to 1e7. An error floor e is resolved once sigma/sqrt(N) < e. Consequence:
a Monte Carlo task a generator passes at small N says very little, which is a
quantitative argument for the external batteries rather than an assertion.

**RANDU's mechanism, identified.** `DepthDecomposition` isolates each Neumann
term K^d f(x) via d forced walk hops with zero roulette, so d=3 is the first
depth spanning three consecutive draws, the exact width of RANDU's documented
defect (x_{n+2} = 6x_{n+1} - 9x_n mod 2^31). At N=2e7, x=pi/2: RANDU is clean
at d=1 (z=+0.01), mild at d=2 (z=-2.03), and breaks decisively at d=3
(z=-9.69). xoshiro is clean at all three. LCG5 shows the opposite signature,
massive at d=2 and d=3, since its bias enters at the first pair and
propagates. See `docs/ODE_MONTE_CARLO.md` 7.1.

Three process lessons, all expensive:

* The first write-up claimed RANDU passes, contradicting its own committed
  table. The design spec had pre-registered exactly this risk and pre-committed
  to reporting whatever was measured, and the write-up kept the prediction
  anyway. **Pre-registration only works if the measurement is allowed to
  overrule it.**
* Layer-1 tests originally checked a parallel implementation of the mathematics
  sharing no code with the estimator, so the attribution claim, that a Layer 1
  pass with a Layer 2 failure implicates the RNG, was unfounded. Fixed with a
  quadrature test routed through the real `SampleT` and `WalkWeight`, then all
  six tests validated by mutation testing. **A test suite that has never been
  shown to fail is a hypothesis.**
* An interim claim that RANDU fails worst at q=0.05 had no committed artefact
  and did not reproduce. **A hypothesis that does not survive the evidence
  needs the evidence committed, not recalled.** The actual mechanism was
  sitting in `randu_bad.hpp`'s own header the whole time, untested because
  every diagnostic built so far spanned at most two consecutive draws.

Also fixed here: the `rand()` builtin adapter masked 16 bits from a 15-bit
`RAND_MAX` on MSVC, fixing the top bit of every word to 0, so `u01() < 0.5`
always and `OdeWalkScore`'s roulette check could never terminate. Regression
test `TestRandBuiltinSpansAboveHalf`.

## 7b. Spec traceability gaps found 2026-08-24

Found by re-reading the source spec clause by clause against what was actually
built, prompted by the user noticing the ODE plotting requirement was missing.
Root cause worth naming: the requirement had been dropped when the PDF was
summarised into the project brief, and the design spec was then written from the
lossy summary. **Anything lost in that summarisation is invisible
downstream**, so the whole contract needed checking, which is #7c.

| Spec | Gap | Status |
|---|---|---|
| 10.3 | Mersenne Twister and language built-in absent from the MC comparison | CLOSED, `tools/std_engine_adapters.hpp`, wired into `rng_ode` and `rng_pi` |
| 10.2 | Plot numerical vs analytical; error graph | CLOSED 2026-08-24, `tools/plot_monte_carlo.py`, `docs/plots/ode_solution.png` and `ode_error.png` |
| 10.1 | Plot error vs trials; convergence rate | CLOSED 2026-08-24, same script, `pi_convergence.png` and `pi_error.png` |
| 6 | Memory consumption never measured | CLOSED 2026-09-12, `rng_memory`, `docs/memory_results.txt` |
| 2.5 | No returning `NextBytes(n)`; no `Generate(server_seed, client_seed, nonce)` | CLOSED 2026-09-12, both as delegating aliases |
| 9 | "Complete specification" and "API documentation" as delivery artifacts | **OPEN**, belongs with #10 |

`tools/plot_monte_carlo.py` reads both result CSVs and writes all four figures
in one run. Error is kept as its own figure in every case, per the spec
wording.

### Memory consumption, CLOSED 2026-09-12

`tools/memory_report.cpp` to `rng_memory`, both backend tables in
`docs/memory_results.txt`. Static footprint rather than heap profiling: no
engine allocates to produce output, so there is no growth curve, and a
profiler would have added allocator noise rather than information. The numbers
are printed by the compiler that built the binary rather than worked out by
hand, because a figure no tool recomputes is the failure mode this project has
already hit twice.

**Result:** fast tier 32 B per engine, no heap ever. Crypto tier ~4.1 KiB per
engine (4184 HMAC, 4176 CTR), of which 98% is the 4 KiB output buffer, since
the SP 800-90A state itself is 80 B (HMAC) or 72 B (CTR). The crypto tier's
memory cost is therefore almost entirely a speed trade we chose, not an
intrinsic cost of the standard, and it is the one knob a licensee with many
concurrent sessions can turn. PF session objects are 120 B plus one heap
allocation per seed string.

Four things `sizeof` cannot see are enumerated by the tool itself rather than
left to prose that can drift: CtrDrbg's opaque `EVP_CIPHER_CTX*`,
`HmacDrbg::Update`'s 33-byte transient per Generate, the PF seeds'
`std::string` heap, and caller-sized output buffers, which are not library
overhead.

Exact sizes are pinned by `static_assert` only where layout is genuinely
ABI-invariant. The buffered engines are asserted as `< kBufBytes + 128`
instead, deliberately, since an exact assert would break the x86-32 configure
that #9 still wants.

### Spec 2.5 API surface, CLOSED 2026-09-12

Both spec-named entry points exist verbatim, each as a **delegating alias with
no second implementation**, which is the point: the spec's names had to appear
without creating a second derivation of any bet-bearing value.

* `Random<E>::NextBytes(std::size_t n) -> std::vector<std::uint8_t>` calls the
  existing pointer form, so the chunking logic has exactly one copy. Pinned by
  a test that fills both ways from the same seed and compares byte for byte at
  n = 37, deliberately not a multiple of 8 so the partial-word tail is inside
  the comparison, plus n = 0.
* `pf::Generate(server_seed, client_seed, nonce) -> double` is
  `Generator::NextFloats(..., 1)[0]`. Pinned against the golden vectors and
  against `NextFloats` itself, so it cannot drift from the stream every
  third-party verifier reimplements.
* C ABI: `rngsdk_pf_generate`, mirrored into `bindings/python/rngsdk.py` and
  asserted in `cross_check.py` against every float vector.

**Deliberately not added: a returning `NextBytes(n)` in the C ABI.** It would
have to allocate library-side, which forces an `rngsdk_free_bytes`, which
reintroduces the cross-heap allocate/free mismatch the C ABI design eliminated
by construction. The existing `rngsdk_next_bytes(h, out, n)` already satisfies
2.5 in C: the caller owns the buffer and an undersized one is refused rather
than truncated. This paragraph exists so the absence reads as a decision
rather than an oversight.

Exports moved 34 to 35, re-diffed with `dumpbin /exports`: 35/35
byte-identical across both flavours. `cross_check.py` ran 32/32 against both
DLLs on a real interpreter. The binding was briefly reported as edited but
unverified when no Python existed on the dev box; **unverified by inspection
is not verified**, and that gap was closed rather than carried.

## 7c. Full spec traceability matrix, PASS DONE 2026-08-24

Every clause of the source spec (2 to 11) mapped to the artifact that
satisfies it. Status of the whole contract, so #10 can be assembled against a
checked list rather than a remembered one.

| Spec clause | Artifact | Status |
|---|---|---|
| 2.1 determinism + avalanche | `tests/test_main.cpp`, reproducibility and 50.0% bit-flip | MET |
| 2.2 uniformity, modulo bias, [0,1) via top 53/24 bits | `random.hpp`, DESIGN_NOTES 4, MATH_JUSTIFICATION 3 | MET |
| 2.3 crypto strength, SP 800-90A | `hmac_drbg.hpp`, `ctr_drbg.hpp`, 12 CAVP vectors each | MET |
| 2.4 PF three components, commit-reveal, monotonic nonce | `provably_fair.hpp`, SA-01 fix | MET |
| 2.5 API surface | `random.hpp`, `provably_fair.hpp`, `rngsdk_c.h` | MET 2026-09-12 |
| 3 two implementations + comparison | both tiers exist; quality comparison is test pass rates, which is #3 | PARTIAL |
| 4 mathematical justification | `MATH_JUSTIFICATION.md` | MET |
| 5 NIST / Dieharder / TestU01 / PractRand | harness done, runs pending (#3) | PARTIAL |
| 6 throughput | `rng_bench`, `docs/benchmark_results.txt` | MET |
| 6 memory consumption | `rng_memory`, `docs/memory_results.txt` | MET 2026-09-12 |
| 6 scalability / multithreading | `rng_thread_bench`, `docs/scalability_results.txt` | MET 2026-09-12 |
| 6 different CPU architectures | ARM64 (Apple M4 Pro) via the partner | MET 2026-09-12 |
| 7 security analysis, all five attack classes | `SECURITY_ANALYSIS.md`, SA-01/02/03/07 fixed | MET |
| 8 console verifier | `rng_verifier` | MET |
| 8 web verifier, integrator library | `web/verifier.html`, `INTEGRATION_GUIDE.md`, `c_api/`, `bindings/python/` | MET, browser matrix partial |
| 9 test suite, permissive licence | 672k checks, MIT, no restrictive deps | MET |
| 9 complete specification, API documentation | | **OPEN** (#10) |
| 10.1-10.4 | see breakdown below | MET except as noted |
| 11 final report, 8 sections | | **OPEN** (#10) |

### Spec 10, Monte Carlo: wanted vs built

| Spec 10.x asks | Have | Status |
|---|---|---|
| 10.1 pi by point-dropping, N = 10^4 to 10^7 | `rng_pi`, 2D and 3D, all four N | MET |
| 10.1 plot error vs trials | `docs/plots/pi_error.png` with theoretical 95% band | MET |
| 10.1 plot convergence rate | `pi_convergence.png`, err*sqrt(N) | MET |
| 10.1 absolute + relative error | `abs_err`, `rel_err` columns | MET |
| 10.1 confidence intervals | `ci95` column and band on both figures | MET |
| 10.1 agreement with O(1/sqrt(N)) | fitted log-log exponent with 95% CI, R=25 | CLOSED 2026-08-27 |
| 10.2 Volterra + von Neumann-Ulam | `ode_solver.hpp`, exactly unbiased | MET |
| 10.2 plot numerical vs analytical | `ode_solution.png` | MET |
| 10.2 error graph, separate | `ode_error.png` | MET |
| 10.2 RMSE, max error | ODE 6.1 | MET |
| 10.2 influence of RNG quality | RANDU floor ~4e-4, LCG5 ~7e-2, depth-3 localisation | MET |
| 10.3 own RNG, MT, PCG64, xoshiro, built-in | all five, in `rng_pi` and `rng_ode` | MET |
| 10.3 metric: accuracy | ODE 6.2, pi table | MET |
| 10.3 metric: speed | `rng_bench` times C `rand()` through the same adapter | CLOSED 2026-08-25 |
| 10.3 metric: stability | run-to-run sd over R=25 vs theoretical prediction | CLOSED 2026-08-27 |
| 10.4 bad RNG to systematic error, pi | RANDU serial box chi2/df 10 to 93, plus LCG5 failing the estimate itself | CLOSED 2026-08-25 |
| 10.4 bad RNG to systematic error, ODE | LCG5 flat 6.9e-2 floor; RANDU 3.41 ratio at 10^7 | MET |
| 10.4 and convergence of the method | err*sqrt(N) and RMSE*sqrt(N)/RMS(sigma) both diverge for the controls | MET |

10.1, 10.2 and 10.4 are fully met, and 10.3's three named metrics are all
measured. The one qualifier left is architectural rather than methodological:
the speed axis rests on a single x86-64 box, closed by #9's ARM64 row.

### Gaps (a) to (e) found by this pass, all closed

**(a) Benchmark artifacts.** `benchmark_results.txt` was stale and recorded no
machine. `rng_bench` now prints a provenance block, and the committed file
carries both backend tables, necessary because the CTR row exists only in an
OpenSSL build and the bundled HMAC baseline only in a bundled build, so an
honest ratio needs the same machine twice. Tables are now medians via
`tools/bench_median.py`, which runs one binary at a time by construction, so
the protocol cannot be violated by hand. Median-of-7 bundled, median-of-5
OpenSSL, idle, per-row spreads 1.05 to 1.38x.

The expensive lesson: a surprising variance measurement, a 2.6 to 7.9x spread,
was treated as a finding and propagated into five files, including a
retraction notice on DESIGN_NOTES 8b, before anyone tested the obvious
confound. The runs had been taken while builds and test suites were running on
the same box. Idle spread is 1.08 to 1.29x, and idle medians corroborate 8b
rather than breaking it. All five edits were reverted. **Measure the confound
before writing the conclusion down.**

**(b) Speed comparator.** `rng_bench` measured `std::minstd_rand` and called it
"the language built-in". It is a standard-library LCG, while the Monte Carlo
tools use C `rand()` via `rngtools::RandBuiltin`, so the table silently
answered a different question than the spec asked. Fixed by measuring
`RandBuiltin` through the same adapter. `RandBuiltin` spends five `rand()`
calls per 64-bit word, so that row is the cost of a word as the Monte Carlo
tools consume it, not of a single `rand()` call.

**(c) Stability.** `tools/stability_stats.hpp` plus `--repeats R` in both tools,
committed at R=25. The reported metric is run-to-run sd against its
theoretical prediction, so `sd_ratio ~= 1` is an independent check rather than
a restatement of the same numbers. Over the 40 sound-engine pi cells
`sd_ratio` lies in [0.75, 1.36]; over the 40 ODE cells, [0.75, 1.55] at
x=pi/4 and [0.69, 1.12] at x=pi/2.

Three engines are excluded from the stability conclusions as single-orbit: the
two deliberate controls, and **C `rand()`, which is not a control at all**.
MSVC's `rand()` has an output period of 2^31, verified by LCG jump, and the
adapter spends 5 calls per 64-bit word, so at N=10^7 the 25 repeats consume
1.16x to 1.75x the entire period. Reported positively, that is a spec 10.3
finding in its own right: the language built-in cannot supply 25 independent
runs at this scale, where xoshiro256++ and pcg64 are nowhere near a limit.

**(d) Convergence exponent.** `FitLogLogSlope` regresses log10 rms_err on log10 N
and reports a 95% CI at df=2, using t=4.303, since the normal 1.96 would
understate the interval by 2.2x at this df. Results in
`docs/{pi,ode}_convergence_fit.csv`.

| Engine | pi-2D slope [95% CI] | pi-3D slope [95% CI] |
|---|---|---|
| sound (5 engines) | all cover -0.50 | all cover -0.50 |
| `RANDU(bad)` | -0.499 [-0.637, -0.362], covers | **-0.335 [-0.477, -0.194], excludes** |
| `LCG5(bad)` | **-0.011 [-0.035, +0.014]** | **-0.022 [-0.073, +0.030]** |

LCG5 is flat in both dimensions, which is what an error floor is, and the
cleanest single number in the whole 10.4 study. RANDU covers -0.50 in 2D and
excludes it in 3D, recovering its own defining defect from the pi estimate
alone. On the ODE the same fit does not convict RANDU: its slopes sit above
-0.50 but both CIs cover it, and its floor shows up in the bias column
instead, constant at ~9e-4 while sd falls 7.9e-3 to 2.0e-4, so bias/sd climbs
0.14 to 4.6.

**(e) Second control.** LCG5 wired into `rng_pi`. The 3D row is the single best
statement of bias in the project: LCG5's estimate converges, to **3.2644, not
to pi**. At N=10^7 its 95% CI is +/-1.85e-3 while it sits 0.123 from the true
value, roughly 66 CI half-widths off. More samples buy precision around the
wrong answer. The 2D row shows the same through the error floor: `abs_err` is
7.3e-2 at N=10^4 and still 5.3e-2 at N=10^7, where a sound engine falls ~31.6x
over those three decades.

The two controls fail differently, which is why both earn their place: RANDU
is a near-miss that only a targeted diagnostic convicts, LCG5 wrecks the
headline estimate outright. That contrast is the argument for the external
batteries.

### (f) Audit of item #7, 2026-08-27

Audited by two independent agents before commit, one on code and mathematics,
one on cross-document consistency. The mathematics held: the bias/variance
identity reproduced on all 112 stability rows, all 28 slope fits reproduce to
better than 3e-6, and the seed scheme was proved collision-free through both
controls' modular `Seed`. Four defects:

1. **The ODE's second grid point was not a second measurement.**
   `RunOdeStability` seeded both grid points with `RepeatSeed(base, r, e)`,
   which has no x term, and `OdeWalkScore`'s roulette test is x-independent
   too, so for a given (engine, N, repeat) the two points consumed a
   bit-identical uniform stream, differing only in deterministic scoring.
   Measured correlation of bias/predicted_sd between the points: **1.00**; bias
   sign agreed in 26 of 28 cells against 14 expected by chance. The second
   point had been added specifically so the result could not be dismissed as
   holding only at the hardest point, and under the bug it appeared to
   corroborate the RANDU finding. With independent streams (`GridSlotBase`,
   pinned by `TestGridSlotBasesAreDisjoint`) it does not. **An experiment
   claiming two independent measurements needs a test that the two are
   actually different, not merely a differently-parameterised call.**
2. C `rand()` exhausts its period in the experiment meant to give it 25
   independent runs. See (c) above.
3. **The auditable CSVs were lossy.** Every writer used the default 6
   significant digits, so `bias` could not be re-derived as mean - exact, and
   in `pi_results.csv` `abs_err` was unrecomputable from `estimate` in 50 of 56
   rows, by up to 3.7% in the worst. All writers now emit 17 significant
   digits, which round-trips a double exactly: the identity residual over the
   committed pi file fell from 3.7e-7 to **1.2e-15**. **A CSV that cannot
   reproduce its own derived columns is not an auditable artefact.**
4. **Write-failure detection had silently regressed**, `if (!f)` with no
   preceding `flush()`, so the destructor's flush happens after the check and a
   full disk reports success. Third occurrence of this exact defect. See Open
   follow-ups.

## 8. Web and library verifiers, DELIVERED 2026-09-03

The spec requires three verifier forms. The console one (`rng_verifier`)
already existed; this item closed the other two.

**Web verifier.** `web/verifier.html`, a single static file with no network
access, no build step and no third-party dependency, opened directly from
`file://`. WebCrypto is the primary backend, with a KAT-validated pure-JS
SHA-256/HMAC fallback for contexts where `crypto.subtle` is unavailable, so
the page still computes correctly offline years from now. A visible banner
names the active backend. Three layers: the verdict, with commitment mismatch
as a hard stop; "show the work", giving the exact HMAC message, the key in
both interpretations of the hex-string-as-ASCII convention, block bytes and
arithmetic; and tools, an in-page self-test and a client-seed generator so a
player never has to trust the operator to produce their own seed.

Correctness is anchored to a third, independently written implementation.
`tests/golden/generate_pf_vectors.py` emits both `docs/pf_test_vectors.json`,
embedded verbatim in the page, and `tests/golden/golden_pf_vectors.hpp`,
consumed by `TestPfGoldenVectors`, so the JS core, the C++ core and Python all
agree on the same vectors rather than two implementations merely agreeing with
each other. A C++ drift guard string-compares the JSON embedded in the HTML
against the canonical file, so a future regeneration that forgets the HTML
fails the build instead of the page self-testing green against stale data.

Headless verification via `tools/web_selftest.js`, a dev-only Node harness
outside the build: 89/89 checks on both backends. Cross-verified against the
console verifier and a live `rng_integration_demo` session. Note when
comparing output: the CLI prints with `precision(17)` while JS prints the
shortest round-trip representation of the same double, so the strings differ
although the value does not. Do not read the agreement as a
17-significant-figure string match.

**Two reimplementation traps caught on paper, before any JS existed.** The
HMAC key for the PF byte stream is the 64-character hex seed string's own
ASCII bytes, not a hex decode. The natural instinct given a value described as
hex-encoded is to decode it, which silently produces a different key and an
entirely different result stream with nothing to signal the error. The
derivation panel displays both interpretations, the wrong one struck through.
Second, the Lemire rejection path needs BigInt throughout, since JS `Number`
silently loses precision above 2^53, which `NextUInt64` output exceeds almost
always, so a `Number` implementation returns plausibly-ranged, wrong,
invisibly-biased integers rather than erroring.

**Three defects the reviews then caught in the code.** A reflected DOM
injection where an operator-supplied commitment string reached
`verdict.innerHTML` unescaped on the mismatch path, serious specifically
because the operator is the adversary this page exists to police, so a
doctored commitment could rewrite the verdict to a fabricated "Commitment OK".
A stale derivation panel that survived a failed re-verify, leaving the first
bet's derivation on screen under the red mismatch banner, where the first fix
attempt only nulled a variable nothing read and it took a second review pass
to notice the DOM was never cleared. And an infinite loop in the JS port of
`nextIntsUnbiased` for any bound above 2^64-1, a JS-only porting defect of
exactly the class this item's three-way cross-check exists to catch, which
escaped the vector set because no vector used a bound that high.

**Integrator library.** `docs/INTEGRATION_GUIDE.md`: API reference for every
`provably_fair.hpp` symbol, the five security obligations the library cannot
enforce on its own, each with a failure mode, wrong code, right code and a
`SECURITY_ANALYSIS.md` cross-reference, and a pre-launch checklist. Backed by
`examples/integration_demo.cpp`, whose code appears verbatim in the guide's
quickstart, confirmed by direct diff.

The five obligations, each a real hole the library cannot close on the
integrator's behalf:

1. **Generate the client seed on the player's device**, after the commitment
   is published. Never server-side, never derived from anything the operator
   controls. A server-generated client seed still verifies and still replays
   correctly, it is simply not binding, and the player cannot tell the
   difference from the UI. This is the single most likely thing for a licensee
   to get wrong, because getting it wrong looks exactly like getting it right.
2. **Persist the nonce with the server seed.** A restart re-instantiating
   `ServerSession` at nonce 0 replays outcomes the player has already seen, the
   SA-01 exploit by another route. Use `start_nonce` on resume.
3. **Use `pf::GenerateServerSeed()`.** The 32-character floor is a proxy that
   catches typed seeds, not low-entropy derived ones.
4. **Never use the fast tier for paid outcomes** (SA-09), and note that
   `CryptoRandom` at namespace or static scope can `std::terminate` if OS
   entropy fails during dynamic initialisation.
5. **Re-verify AES-NI** on deployment hardware (SA-10).

**C ABI wrapper, DELIVERED 2026-09-03.** Built per
`docs/design/2026-09-02-c-abi-wrapper-design.md`: `c_api/` with public header,
translator, internal type erasure and a C-compiler parse test; `rngsdk_c`
shared and static targets in both crypto flavours; equivalence tests; and
`bindings/python/`. `include/rngsdk/` is byte-identical to its pre-item state,
so the "one folder of MIT headers" story for C++ consumers is untouched.

Two deliberate divergences from the C++, both refusals rather than
computations, both asserted in the suite so nobody "fixes" them: `bound == 0`
returns `RNGSDK_ERR_INVALID_BOUND` where `Random::NextUInt64(0)` returns 0,
since one C enum cannot defend two behaviours for identically-shaped calls;
and `lo > hi` in `rngsdk_next_int_range` is refused rather than wrapped
through unsigned span arithmetic into a value from the wrong interval.

**`rngsdk_build_info_t` is frozen.** The final review flagged it as an ABI
hazard the append-only enum promise does not cover, since the struct is
caller-allocated, so a future field would make a new library write past an old
caller's allocation. The conventional remedy, a caller-set `size_t
struct_size` in/out field, fails silently when a caller forgets to set it, and
FFI authors in C#, Java, Node, Go and Python are precisely the population that
would forget. The struct is therefore frozen in the header, with future
introspection arriving as new functions. Recorded because the choice is only
cheap before a licensee compiles against it.

**The defect worth remembering**, found by the whole-branch review rather than
any per-task review: the Python binding sized `reveal()`'s buffer from
`RNGSDK_HEX_BUF` (65) while `rngsdk_pf_session_create` accepts any server seed
of 32 characters or more. A longer seed bricked the session, with reveal
failing after the reveal latch had already fired, so the session could neither
play nor surrender the seed and bets already placed were **permanently
unverifiable**. A commit-reveal failure from a documented-legal input, in the
very file every non-C++ licensee copies. The per-task review had checked every
`argtypes` and buffer size against the vectors, which all use 64-character
seeds; only a reader asking what inputs the C API actually accepts found it.
Pinned with a 100-character seed.

Second lesson from the same close-out: the integration guide's flavour table
claimed the OpenSSL artifact has no licensee-side dependencies while
`OPEN_RESEARCH.md` said the opposite in the same commit. **Two of our own
documents contradicting each other on a shippability claim.**

## 9. Multithreading and platform matrix, DELIVERED 2026-09-12

`tools/thread_bench.cpp` to `rng_thread_bench`: aggregate throughput vs thread
count, 1/2/4 up to `hardware_concurrency` plus an oversubscribed 2x row, one
engine per thread, `--repeats` with median and spread per cell, and `--csv`.
Per-thread separation is xoshiro `Jump()` x t, PCG64 distinct seed, DRBGs
independent instances. Results in `docs/scalability_results.txt`, raw artifacts
in `docs/perf_x86_64/` and `docs/perf_arm64/`.

**The tool's design point worth keeping:** a stream-separation self-check runs
before any timing and refuses to report if two threads' first words coincide.
The failure it guards is specific. A seeding slip giving every thread the same
stream produces a textbook-perfect linear scaling curve, the prettiest possible
result, and no timing assertion can detect it. Same family as the
correlated-ODE-grid-point bug in #7's audit: the artifact looked like
corroboration precisely because the streams were not independent.

Provenance printing moved out of `benchmark.cpp` into `tools/provenance.hpp`,
so the two benchmark tools cannot print different provenance for the same
machine.

**x86_64 (AMD Ryzen 7 260, 8 cores / 16 threads).** No shared-state
contention, which is the claim the tool exists to test: the oversubscribed
32-thread row does not degrade, with 32/16 ratios of 0.991 to 1.164x across
all seven engine instances, and a contention defect would collapse there.
Efficiency knees at 8 threads, around 55 to 70%, reproducibly hardware, and
**deliberately left undiagnosed** in the doc because separating mobile-APU
power limiting from SMT sibling scheduling needs affinity pinning that was not
done.

**ARM64 (Apple M4 Pro, 10P+4E, no SMT), delivered by the partner.** Both
benchmarks, both configs, against this repo's warm-up-patched harness.
Efficiency sags past 8 threads as the scheduler fills E-cores, as anticipated.
Both suites green at the same counts as x86_64, and every
determinism-sensitive value in the logs is byte-identical across
architectures, not merely the pass count.

**Finding that feeds #11:** OpenSSL's HMAC path scales worse, not merely
slower. On x86_64, bundled over OpenSSL HMAC-DRBG is 1.29x at 1 thread but
2.42x at 16, an efficiency of 53.5% against 28.5%. On ARM64 OpenSSL is ~1.2x
faster single-threaded, the reverse of x86_64, but collapses under threading,
with 28-thread throughput ~2.6x slower than 1-thread. The EVP_MAC_CTX caching
fix is therefore worth more than #11's single-threaded ~2x implies, since
concurrent sessions are exactly where the penalty grows.

*Follow-up 2026-09-13:* the fix landed and the x86_64 half of this finding is
reversed, with the widening gap closing rather than growing (bundled over
OpenSSL now 0.36x at 1 thread and 0.53x at 16). The prediction that threading
was where the penalty lived held up: the gain was larger at 16 threads than at
1. The ARM64 collapse is unmeasured post-fix. See #11.

`detail/uint128.hpp`'s `_umul128` path compiles clean and warning-free under
MSVC 19.51. The 32-bit-limb fallback is still unexercised, since both tested
targets are 64-bit; covering it needs an x86-32 configure specifically.

## 10. Report assembly, OPEN (Docs, ~2d)

Final report skeleton is the spec's 8 sections. `DESIGN_NOTES.md` maps to
sections 1 and 2; this file's outputs fill 3 to 7. An internal summary
consolidates the Monte Carlo material for sections 5 and 6; it is scaffolding
for this item and is deleted once the report absorbs it. Keep
`docs/pi_results.csv` regenerating from `rng_pi --csv` so report figures stay
reproducible.

Also open under this item, from #7b and #7c: the spec's clause 9 asks for a
"complete specification" and "API documentation" as delivery artifacts.

## 11. OpenSSL HMAC call-pattern regression, FIXED on x86_64 2026-09-13; ARM64 re-run owed

**The fix.** `crypto/hmac_sha256.hpp` no longer calls OpenSSL 3.x's one-shot
`HMAC()`, which re-ran the provider fetch and MAC-context setup on every call
and which the DRBG invoked once per 32-byte block. It now holds one `EVP_MAC`
and one `EVP_MAC_CTX` per thread, with the SHA-256 digest bound once at
construction, and each call is `EVP_MAC_init`/`update`/`final` on that context.
Per-thread rather than shared, so there is no lock to serialise on.

**No bytes changed.** The OpenSSL suite passes at 895,577/895,577, the count
recorded before the change, which covers the CAVP vectors, the golden vectors
and the cross-backend determinism fingerprints. Nothing downstream of the
generator is affected: no battery run, no fingerprint row, no test vector and
no Provably Fair result is invalidated, so no re-run is owed for correctness.
The only artifacts invalidated are performance tables.

**Measured, x86_64 (Ryzen 7 260, MSVC 1951), same box and tool before and
after, with the bundled rows re-run as a control.** Full tables in
`docs/scalability_results.txt` and `docs/benchmark_results.txt`, both dated
2026-09-13.

* Single-threaded: 3.681e6 to 1.327e7 u64/s, 3.6x.
* 16 threads aggregate: 1.856e7 to 8.190e7 u64/s, 4.4x.
* The direction against the bundled backend **reversed**: OpenSSL was 1.30x
  slower single-threaded and 2.42x slower at 16 threads; it is now 2.75x and
  1.90x **faster**. x86_64 and ARM64 no longer disagree about the sign.
* Scaling efficiency improved but did not equalise: 31.5% to 38.4% at 16
  threads, against 56.0% for bundled. Some per-call shared state remains. It
  costs nothing that matters at any measured thread count, but the path must
  not be described as contention-free.

**Consequence that inverts a standing instruction.** With the denominator no
longer artificially slow, CTR-DRBG over OpenSSL HMAC-DRBG is 6.8x on this box,
against 18.7x over the bundled HMAC. The like-for-like OpenSSL-to-OpenSSL
ratio is now the *conservative* one, so the older rule forbidding it, and
DESIGN_NOTES 8b's "never cite 27.8x", applied to pre-fix builds. The 27.8x
figure is unreachable now by any measurement; quote 6.8x with its platform for
post-fix production builds.

**Still open: ARM64.** Table 4's collapse to 0.38x at 28 threads was measured
on pre-fix code. The mechanism removed here is a plausible cause and the
x86_64 result is consistent with it, but the single-threaded direction
previously reversed between the two platforms, so a shared mechanism must not
be assumed. Owed: partner re-runs `rng_thread_bench --repeats 5` and
`tools/bench_median.py` on the M4 Pro, OpenSSL config. Until then the ARM64
tables stand as pre-fix history and no current ARM64 throughput claim exists.

## 12. HMAC-DRBG additional input, DECIDED 2026-09-07, accepted not fixed

Raised 2026-08-20 by the math-doc citation review, resolved by user decision:
option (a), leave as-is and document. Recorded in `SECURITY_ANALYSIS.md` 4.2,
4.4 for the SA-06 half, the findings register, and 9.1 item 1.

**The finding.** Woodage and Shumow (EUROCRYPT 2019, ePrint 2018/349, 7.1)
disprove SP 800-90A's backtracking-resistance claim for HMAC-DRBG when
additional input is omitted. With `addin = {}` the 0x01 pass of Update is
skipped, leaving the post-Generate state satisfying `V* == HMAC(K*, r*)` where
`r*` is the last output block returned. Anyone holding output and the state
can test that relation, a forward-security distinguisher with advantage ~1.
Verified to apply here: `HmacDrbgEngine::Refill()` calls
`Generate(buf_, kBufBytes)` with `additional` defaulted empty.

**Why accepting it is defensible**, and the premise that must travel with the
conclusion. The attack is conditional on the adversary already holding the
DRBG's live `K`/`V` state out of server process memory, from which all future
output is predictable anyway, strictly worse than the distinguisher. Knowing
our source or the algorithm grants nothing, since SP 800-90A and HMAC-SHA256
are public. The Provably Fair path never touches the DRBG state machine, since
`pf::ByteStream` computes HMAC directly, so no bet-bearing outcome is
implicated at any severity. The control is operator-side memory hygiene, which
the library cannot supply. SA-06, no automatic reseed, closes on the same
premise; `Reseed()` stays available and caller-driven.

**What may not be claimed:** the crypto tier is not backtracking-resistant and
does not offer SP 800-90A prediction resistance.

**Consequence for #3:** because nothing changes, no bytes change, so the
`hmac` fingerprint row, the HMAC golden vectors and any battery run in flight
stay valid. The long-standing "do not land while #3 is outstanding" constraint
is discharged rather than deferred, and #12 no longer gates #3 in either
direction.

Options (b), a deterministic per-request counter as additional input, and (c),
a constructor flag defaulting off, remain available if a licensee's threat
model ever demands provable backtracking resistance. Woodage and Shumow's 7.2
proves robustness does hold when additional input is supplied on every
Generate, and `HmacDrbg::Generate` already accepts `additional`; only the
adapter declines it. Either option is a versioned stream break requiring
regeneration of the `hmac` fingerprint row and the HMAC golden vectors, so it
belongs at a major version rather than a patch.

## Open follow-ups

Small deferrals that live inside otherwise-closed items, collected here so
they are findable. None blocks #3 or #10.

| From | Item | Effort |
|---|---|---|
| #2 | Expose CTR-DRBG through the OpenSSL-enabled quickstart example. | Eng, <0.5d |
| #2 | Decide whether `CtrRandom` becomes the default crypto alias on AES-NI targets. `CryptoRandom` is HMAC-DRBG today, unchanged for compatibility and for the Woodage-Shumow reason in #6. | Decision |
| #2 | `HmacDrbgEngine` is copyable while `CtrDrbgEngine` is move-only. Pick one policy; move-only is safer, since copying a DRBG forks its stream. | Eng, <0.5d |
| #4 | `pr_true` and `reseed` CAVP families unexercised, since the SDK has no prediction-resistance-on-demand. Add the capability or document the absence. | Decision |
| #7c | Shared `WriteCsv` helper. Write-failure detection has regressed three times in separate writers. | Eng, <0.5d |
| #8 | No test exercises ordinary nonce resumption away from the `uint64_t` overflow boundary. `TestNonceOverflowRefused` covers only `max-1`; the integration guide states that limitation explicitly. | Eng, <0.5d |
| #8 | Browser compatibility matrix. Brave and Chrome on Windows both select WebCrypto from `file://` and pass the self-test; Safari and Firefox untested. | Human at a browser |
| #8 | Static OpenSSL release artifact. Procedure in `INTEGRATION_GUIDE.md` 4.1; the artifact belongs to release packaging and has not been produced. | Release |
| #8 | Exported-symbol snapshot test, diffing `dumpbin` or `nm` output against a committed baseline. Worth doing when a version ships under a compatibility promise. | Eng, <0.5d |
| #8 | `rngsdk_random_create_secure` maps every `std::runtime_error` to `RNGSDK_ERR_ENTROPY`, so an OpenSSL `EVP` failure is logged as an entropy failure. Correctness is unaffected; only post-incident diagnosis is misled. Splitting it needs a distinguishable exception type from the core. | Eng, core change |
| #9 | 32-bit-limb fallback in `detail/uint128.hpp` unexercised. Needs an x86-32 configure. | Eng, <0.5d |

`CryptoRandom` at namespace or static scope can `std::terminate` if OS entropy
fails during dynamic initialisation (#1). There is no in-tree usage, and the
integration guide documents it, so this is closed rather than open.

## Deliberately fine as-is

* Reference SHA-256 against OpenSSL: the backend switch exists and outputs are
  proven equal by the suite.
* DRBG throughput, ~2.3M u64/s, is irrelevant for per-bet workloads.
* `Random<Engine>`'s template API matches the spec's `Seed()` and `Next*()`
  naming.
