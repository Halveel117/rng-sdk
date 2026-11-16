# Design notes — what was built, how, and why

Audience: you (for the math doc and the report) and any auditor of the SDK.
Each section = one decision, its reasoning, and where it's proven.

## 1. Architecture: header-only INTERFACE library

One folder of MIT headers, no binary artifacts, no dependencies. Reasoning:
licensability (the spec demands source delivery, permissive licensing, easy
integration) and templates — `Random<Engine>` is compile-time polymorphic, so
the mapping layer costs zero overhead over any engine. Trade-off: longer
compile times for consumers; acceptable at this size.

## 2. Engines

**xoshiro256++** — faithful port of the canonical C (fetched from
prng.di.unimi.it during development, public domain). Period 2^256−1, passes
BigCrush/PractRand per authors, ~0.6–1 ns/word measured. `Jump()`/`LongJump()`
(2^128 / 2^192 steps) give provably non-overlapping parallel streams — that is
the multithreading answer for the fast tier.

**PCG64 (XSL-RR 128/64, setseq)** — chosen deliberately because NumPy ships
it as the default BitGenerator: our port is cross-validated *word-for-word*
against `numpy.random.PCG64` via state injection (tests/golden). 128-bit LCG
state; output permutation rotates by the state's top 6 bits.

**Seeding** — both engines expand a 64-bit seed through SplitMix64 (authors'
recommendation). SplitMix64 is a bijection: distinct seeds → distinct states;
xoshiro's forbidden all-zero state cannot occur. Avalanche measured at 50.0%.

**HMAC-DRBG (SHA-256)** — SP 800-90A §10.1.2 implemented function-by-function
(Update/Instantiate/Reseed/Generate) with the standard's limits enforced:
reseed_interval 2^48, ≤2^19 bits/request, ≥32-byte entropy. Unpredictability
reduces to HMAC-SHA256's PRF security; Update() after each Generate gives
backtracking resistance. The engine adapter buffers 4 KiB per DRBG request —
statistically free, ~128× fewer per-request Updates.

**Why not AES-CTR-DRBG yet:** without AES-NI intrinsics or OpenSSL it would
be both slow and hand-rolled crypto — the worst combination. Deferred (open
item #2) to be built on the OpenSSL backend where it's 5–20× faster than
HMAC-DRBG.

## 3. Crypto backend policy

`RNGSDK_USE_OPENSSL` routes SHA-256/HMAC through OpenSSL; default is a bundled
reference implementation validated against FIPS 180-4 / RFC 4231 vectors and
Python hashlib. Reasoning: the prototype must compile on a bare Windows +
MSVC machine with zero setup; production/licensed builds should use a
FIPS-validated, side-channel-hardened library. The backends are proven
bit-identical by the test suite, so the switch is risk-free.

War story (kept deliberately): the initial K-table had a one-character typo
(K[11] = 0x550c7d63 vs correct 0x550c7dc3). Every known-answer test failed;
regenerating the constants from cube roots of primes located it in minutes.
That is exactly why the SDK's tests use *independently generated* golden
values rather than self-produced ones.

### 3b. Entropy sourcing (2026-08-14, closes OPEN_RESEARCH #1)

`crypto/os_entropy.hpp` consumes the platform CSPRNG directly:
BCryptGenRandom (Windows CNG), getrandom(2) (Linux), getentropy(3)
(macOS/BSD), /dev/urandom (other POSIX). Three deliberate decisions, each
one an argument the security doc can make:

* **Consume, don't own.** SP 800-90B health-test/estimation obligations
  belong to whoever owns the noise source; delegating to FIPS-validated /
  kernel-audited OS DRBGs is the auditable answer.
* **No conditioning.** OS output is already full-entropy; a SHA-256 pass
  cannot add entropy (H(f(X)) ≤ H(X)) and would be one more construction
  to justify. The old random_device+time+ASLR pool is deleted, not wrapped:
  if `std::random_device` degenerates (which the standard permits), the
  surviving sources are a timestamp and an ASLR-derived address — plausibly
  only a few tens of bits, platform-dependent, behind a 256-bit claim.
* **No fallback — throw.** A silently degraded seed source passes every
  statistical test while being brute-forceable; commit–reveal even hands
  the attacker a free offline oracle (published SHA-256(server_seed)).
  Loud failure is the security feature.

API consequences: `SecureEntropy()` = 48 OS bytes (entropy‖nonce);
`HmacDrbgEngine()` / `CryptoRandom` default-construct OS-seeded, while
explicit seeds remain byte-for-byte deterministic (golden vectors
unchanged); `pf::GenerateServerSeed()` returns a 256-bit hex server seed
(2× the documented 128-bit floor). Windows builds link `bcrypt`
(CMake INTERFACE + MSVC `#pragma comment`).

## 4. Mapping layer — the "no bias" proofs in brief

**Doubles.** `(x >> 11) * 2^-53`. The top 53 bits are uniform on
{0,…,2^53−1}; each grid value k·2^-53 has exactly 2^11 preimages among the
2^64 words → exactly uniform on the grid, every value representable, never
1.0. A naive x/2^64 would produce non-equidistributed rounded values and
inherits weak low bits. Floats: same with 24 bits.

**Bounded integers (Lemire, arXiv:1805.10941).** For bound N, compute the
128-bit product m = x·N. The map x ↦ ⌊xN/2^64⌋ partitions [0,2^64) into N
lanes of size ⌊2^64/N⌋ or ⌈2^64/N⌉. Rejecting exactly when
(m mod 2^64) < (2^64 mod N) trims every lane to identical width ⌊2^64/N⌋,
hence P(result = k) equal for all k — **zero bias**, and the expensive `%`
runs only on the rare rejection branch (P ≤ N/2^64). This is the algorithm
in libstdc++, MSVC STL, Go, Swift, Julia, the Linux kernel. The test suite
also *demonstrates* the naive bias it removes: `byte % 6` gives chi² ≈ 252
where rejection gives ≈ 5 (df 5).

**32-bit path** uses the top 32 bits of a 64-bit word (weak-low-bits
hygiene), 32×32→64 multiply, same rejection rule with 2^32 mod N.

## 5. Provably Fair — protocol reasoning

`commitment = SHA-256(server_seed)` published **before** play; without it the
operator could grind seeds after seeing bets. Player owns `client_seed`
(may change it any time pre-bet), server owns the HMAC key; neither side can
predict or steer outcomes alone. `nonce` is a strictly monotonic per-pair
counter (enforced by `ServerSession`); reuse would replay outcomes.
Byte derivation `HMAC-SHA256(server_seed, client_seed:nonce:cursor)` with the
cursor extending streams past 32 bytes — deliberately identical in shape to
the scheme Stake documents publicly, so the SDK is verifiable by existing
third-party tools and familiar to operators.

Two outcome mappings, both exposed on purpose:
- *industry mapping*: 4 bytes → float (b0/256 + b1/256² + …), then ⌊f·N⌋.
  Bias ≤ N/2^32 relative — negligible for game-sized N, but nonzero.
- *unbiased mapping*: Lemire rejection over the HMAC stream — exact, for
  when the math doc must claim zero bias. Trade-off: not byte-compatible
  with other operators' verifiers; the verifier CLI supports both
  (`--unbiased`).

Server seed hygiene (documented requirement): ≥128 bits of entropy, single
session use, never reused after reveal.

## 6. Test strategy

Three layers: (1) known-answer vectors generated by *independent* stacks —
Python hashlib/hmac (OpenSSL-backed), NumPy's PCG64, a Python transcription
of canonical xoshiro — regenerable via `tests/golden/generate_golden.py`;
(2) construction properties — determinism, avalanche 50%, nonce monotonicity,
commit–reveal round trip, cursor-boundary crossing; (3) statistical smoke —
monobit z, byte/bounded-int chi², thresholds set at ≥5σ so false failures are
~impossible while real bugs (which shift statistics by orders of magnitude)
are caught. These smoke tests are explicitly NOT a substitute for the full
batteries (open item #3).

### 6b. Byte streams for the external batteries (2026-08-18)

`rng_stream` (tools/stream.cpp) exposes each byte-producing code path as a raw
stdout stream for NIST SP 800-22 / Dieharder / TestU01 / PractRand. Three
decisions worth defending in the report:

* **Stream `Random<Engine>::NextBytes`, not the raw engine.** That is the call
  a consumer makes, so the mapping layer and the DRBG adapters' 4 KiB
  buffering sit inside the tested path. CAVP validates the DRBG *core* only —
  a buffering fault would pass every official vector while making the real
  stream repeat every 4 KiB. This is why the crypto tier gets shallow runs
  rather than no runs: that defect class is gross and dies in the first
  megabyte, while a subtle statistical flaw there would be a break of
  SHA-256/AES, not a laptop finding.
* **Sources are byte-buffered.** `NextBytes` draws a whole 64-bit word for a
  partial tail and discards the remainder, so an unbuffered source would emit
  different bytes depending on how the caller chunked its reads — and the tool
  writes in fixed blocks. A ragged-split test pins the invariant.
* **The Provably Fair source advances the nonce**, not just the cursor.
  Correlation between adjacent nonces is the defect that would matter for real
  bets; a single nonce's cursor stream never reaches it.

RANDU is the negative control: it must fail, or the harness cannot detect
failure and the whole matrix is void. It emits the top 16 bits of each 31-bit
output rather than the raw top-aligned word (33 constant zero bits), so it
fails for its lattice structure rather than for stuck bits — the distinction
between a control that proves something and one that does not.

Cross-platform determinism is pinned in
`docs/statistical_results/fingerprints.txt` and asserted by the suite, so a
mismatch between the macOS/clang run machine and the Windows/MSVC development
build surfaces in thirty seconds rather than after two days of runs. Both are
little-endian (including Apple Silicon), so the fingerprints apply unchanged
and any mismatch is a real portability bug, not a platform difference.

Portability note recorded while building this: `NextBytes` `memcpy`s a
`uint64` in **native** byte order, so its stream differs on a big-endian host.
`pf::ByteStream` is unaffected (HMAC output has a defined byte order), which
is the half that matters — cross-platform Provably Fair verification is
byte-stable.

## 7. Monte Carlo validation (spec "additional task", parts 1, 3, 4)

`rng_pi`: 2D quarter-disc (π = 4A) and 3D sphere octant (π = 6V), N = 10^4…
10^7, reporting abs/rel error, 95% CI, err·√N. Five sound engines are
compared per spec 10.3 — our xoshiro256++, PCG64 and HMAC-DRBG plus
MT19937-64 and C `rand()` — and all five track O(1/√N).

The correlation study (spec 10.4) uses **two** deliberately broken controls,
because the contrast between their failure modes is the finding:

* **RANDU** (x ← 65539x mod 2^31) largely *passes* the smooth π integrals;
  the serial 3D box test (16³ cells over consecutive triples) fails it
  instantly, chi²/df growing 10 → 93 with N (its triples lie on 15 planes;
  structure ≠ noise, so more sampling makes it *worse* relative to CI).
* **LCG5** (x ← 5x + 1 mod 2^31) fails the π *estimate itself*: its
  consecutive pairs lie on five lines, so the 2D estimator sees the defect
  directly (abs_err is a floor — 7.3e-2 at N=10^4, still 5.3e-2 at N=10^7),
  and its 3D estimate **converges to 3.2644, not π**, ~66 CI half-widths off
  at N=10^7.

So a bad RNG can pass an easy task (RANDU) *or* silently wreck the headline
number (LCG5), and neither case is detected by looking at one estimate. That
asymmetry is the strongest argument in the report for running TestU01/
PractRand before licensing. Results: `docs/pi_results.csv`.

**Scope note (added 2026-08-27).** "RANDU largely passes smooth integrals" is
a statement about *single runs* of *this* task, and it does not generalise:
docs/ODE_MONTE_CARLO.md §7 retracts the corresponding claim for the ODE task,
where RANDU's ~4e-4 error floor emerges once N ≥ 10^6 and coverage collapses
to 3/8 at N=10^7. The honest formulation in both places is a *sensitivity
threshold*, not a pass/fail: a floor of size ε is resolved once N is large
enough that σ/√N falls below it. See the stability run below — with repeats,
π's 3D estimator resolves RANDU too.

### 7a. Stability and fitted convergence exponent (spec 10.3, 10.1)

`rng_pi --repeats R` re-estimates each cell at R distinct seeds
(`tools/stability_stats.hpp`), reporting the run-to-run `sd` against the
*theoretical* prediction `prefactor·√(p(1−p)/N)` — a prediction, not a fit, so
`sd_ratio ≈ 1` is an independent check rather than a restatement. It also fits
the log–log slope of `rms_err` vs `N` with a 95% CI (df = 2, t = 4.303).
Committed at **R = 25**: `docs/pi_stability.csv`,
`docs/pi_convergence_fit.csv`.

**Stability.** Across all 40 sound-engine cells (5 engines × 2 dimensions ×
4 N), `sd_ratio` lies in **[0.75, 1.36]**. At R = 25 the sample SD carries
±14.4% of its own sampling uncertainty (95% interval for `s/σ` is
[0.72, 1.28]), so three cells sitting just outside is the expected count, not
a signal. **No engine is separable from another on stability**, and the report
must not rank them on this axis — the metric's own resolution does not support
it.

**Convergence exponent.** Every sound engine's CI covers −0.50 in both
dimensions (slopes −0.504 … −0.553). The controls separate sharply:

| Engine | 2D slope [95% CI] | 3D slope [95% CI] |
|---|---|---|
| sound (5 engines) | all cover −0.50 | all cover −0.50 |
| `RANDU(bad)` | −0.499 [−0.637, −0.362] — covers | **−0.335 [−0.477, −0.194] — excludes** |
| `LCG5(bad)` | **−0.011 [−0.035, +0.014]** | **−0.022 [−0.073, +0.030]** |

`LCG5` is flat in both: its error does not shrink at all, which is what an
error floor *is*. **`RANDU` is the interesting row** — it covers −0.50 in 2D
and excludes it in 3D, which is exactly its own defining defect (pairs are
fine, consecutive *triples* lie on 15 planes) recovered from the π estimate
alone. Its 3D bias also stops shrinking: −1.3e-3 at N=10⁶ and −2.0e-3 at
N=10⁷, while `sd` falls 3.4e-3 → 8.7e-4.

**Two limits on how hard that RANDU result may be pushed.** First, RANDU is
single-orbit, so at N=10⁷ its 25 "repeats" are offsets on one cycle and
overlap heavily; the nominal `sd/√R` therefore understates the true standard
error by an unknown factor, and the naive z ≈ 11 on that bias is not
defensible. Second, df = 2. So the claim this supports is **"π's 3D estimator
resolves RANDU once you take repeats, consistent with a three-dimensional
defect"** — not "π convicts RANDU". The serial box test (χ²/df 10 → 93)
remains the diagnostic that convicts it outright, and the external batteries
remain mandatory for the reason §7 already gives.

The RANDU rows were regenerated once, after a non-injective `RanduBad::Seed`
was found and fixed; only those rows moved (OPEN_RESEARCH #3).

## 8. Performance snapshot (single core, g++ 11 -O2, Linux sandbox)

| generator            | uint64/s | doubles/s |
|----------------------|----------|-----------|
| xoshiro256++ (ours)  | 6.4e8    | 5.2e8     |
| PCG64 (ours)         | 3.4e8    | 2.7e8     |
| HMAC-DRBG (ours)     | 2.3e6    | 1.6e6     |
| std::mt19937_64      | 1.3e8    | —         |
| std::minstd_rand     | 2.1e8    | —         |

Fast tier beats Mersenne Twister ~2.5–5×. DRBG's ~280× gap vs fast tier is
inherent (two SHA-256 compressions per 32 bytes) and is the price of
computational security; per-bet Provably Fair usage needs ~1 HMAC per bet, so
this is nowhere near a bottleneck for gaming workloads.

### 8b. Windows/MSVC Release, with CTR-DRBG (2026-08-15)

Measured on the target Windows box (MSVC 19.37, Release, single core),
OpenSSL 3.6.3 via vcpkg. **Both backends were run**, because the MAC backend
turns out to change the HMAC-DRBG baseline by 2×:

| generator                   | uint64/s | doubles/s | backend |
|-----------------------------|----------|-----------|---------|
| xoshiro256++ (ours)         | 6.77e8   | 3.92e8    | —       |
| PCG64 (ours)                | 3.95e8   | 2.75e8    | —       |
| **CTR-DRBG AES-256 (ours)** | **3.13e7** | **2.87e7** | OpenSSL |
| HMAC-DRBG (ours)            | 2.31e6   | 2.00e6    | bundled |
| HMAC-DRBG (ours)            | 1.13e6   | 1.14e6    | OpenSSL |
| std::mt19937_64             | 2.04e8   | —         | —       |
| std::minstd_rand            | 1.89e8   | —         | —       |

**CTR-DRBG is ~13× faster than HMAC-DRBG** when both are measured fairly —
i.e. against the *faster* HMAC baseline (bundled, 2.31e6 in this table). That
is inside the 5–20× band predicted for AES-NI, not above it. Quoting the
OpenSSL-backend HMAC row instead yields a flattering 27.8×, which would be a
measurement artifact rather than a property of the algorithms; the SDK does
not cite it. (Same discipline applied to the teammate's Python "886×", which
was a NumPy-vectorisation artifact.)

**Quote it as "~13×", not to three figures.** This table gives 13.6×; the
2026-08-25 idle medians gave 12.9×; two median-of-N sessions an hour apart on
2026-08-27 gave 13.6× and 12.9× *from the same CTR numerator*, the whole
difference being the bundled-HMAC denominator (2.357e6 vs 2.485e6). All of
these are one result measured repeatedly, not competing results. A third
significant figure is not measurable on this hardware, and earlier drafts of
`benchmark_results.txt` that appeared to disagree (12.9 vs an unsupported
"14.6") were reconciled on 2026-08-27 — see that file's THE CORRECTION
section.

> **Independently re-measured 2026-08-25 and corroborated.** Four idle runs per
> build on the same box: bundled HMAC 2.025–2.257e6, OpenSSL HMAC 9.14e5–1.18e6,
> CTR-DRBG 2.536–2.863e7, xoshiro 6.025–6.538e8 — per-row spread 1.08–1.29×.
> From the medians, **CTR / bundled HMAC ≈ 12.9× against the recorded 13.6×**,
> and OpenSSL-vs-bundled HMAC ≈ 2.0×, reproducing #11. §8b stands.
>
> (2026-08-27: those two figures are *the same measurement*, not a near-miss.
> Re-measured that day at median-of-7 and median-of-5, an hour apart, the ratio
> read 13.6× and 12.9× from an identical CTR numerator — the denominator alone
> moved. Hence the "~13×" guidance above. Spread that session: 1.05–1.38×.)
>
> (Single runs are not enough for the CTR row specifically: individual readings
> ranged 1.67e7–2.96e7 across the day, so a lone sample can yield a ratio
> anywhere from ~8× to ~15× even idle. Quote the median of ≥4.)
>
> One methodological caveat learned the hard way that day, recorded because it
> nearly produced a false retraction of this section. Benchmarks taken *while
> builds and test suites were running* on the same 2-core box spanned 2.6–7.9×
> depending on the row, and yielded CTR-vs-HMAC ratios of 7.4× and 18.5× ten
> minutes apart — which briefly looked like evidence that this hardware could
> not benchmark at all. Four consecutive runs on the **idle** machine spanned
> only 1.08–1.29× (the per-row figures quoted above). The hardware was never
> the problem; concurrent load was.
>
> Standing rule: run `rng_bench` on an idle machine, ≥4 times, and report
> median + spread. `docs/benchmark_results.txt` records the idle/loaded
> comparison as evidence. The remaining genuine gap is architectural coverage,
> not repeatability — spec §6 asks for multiple CPU architectures, so the
> ARM64 row is still delegated to the partner's box alongside OPEN_RESEARCH #3.

The genuinely surprising result is the HMAC row itself: **OpenSSL's one-shot
`HMAC()` is ~2× slower than our bundled reference implementation** at this
call pattern (one MAC per 32-byte DRBG block). OpenSSL 3.x re-runs provider
fetch and MAC-context setup on every call; the fix is to cache an
`EVP_MAC_CTX` in `HmacSha256` — logged as OPEN_RESEARCH #11. Until then, the
production (OpenSSL) build is the *slower* one for HMAC-DRBG, which is worth
knowing before quoting throughput to a licensee.

> **Superseded 2026-09-13, x86_64 only.** That fix was made: `HmacSha256`
> now holds a per-thread `EVP_MAC_CTX` with the digest bound once. On
> x86_64 the OpenSSL HMAC-DRBG row went 3.681e6 → 1.327e7 u64/s and the
> production build became the *faster* one, 2.75× over bundled rather than
> 1.30× slower, so the paragraph above describes pre-fix builds only. The
> ban on the 27.8× figure survives on its own merits but no longer has a
> measurement behind it: the like-for-like OpenSSL-to-OpenSSL CTR ratio is
> now 6.8×, the conservative one. Output bytes are unchanged (suite at
> 895,577, its pre-change count). ARM64 is not re-measured; see
> OPEN_RESEARCH #11.

Interpretation for the report: CTR-DRBG sits ~22× below the fast tier while
retaining full SP 800-90A security, versus ~290× for HMAC-DRBG. Recommend
CTR-DRBG as the default crypto engine wherever AES-NI and OpenSSL are
available; HMAC-DRBG remains the zero-dependency fallback.

Cross-platform caveat: the Linux figures in §8 and these Windows figures are
different machines and compilers; compare rows within a table, not across.
