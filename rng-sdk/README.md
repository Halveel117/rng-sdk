# RNG-SDK, prototype 0.1.0

C++17, header-only prototype of the licensable RNG-SDK with a
Provably Fair scheme (per the commissioned spec). Two generator modes behind
one API, a commit–reveal fairness protocol, an independent console verifier,
a known-answer + statistical test suite, and Monte Carlo validation.

## Layout

```
include/rngsdk/          the SDK (header-only, MIT, no third-party deps;
                         Windows builds link the system bcrypt library)
  splitmix64.hpp         seed expander
  xoshiro256pp.hpp       fast engine #1 (canonical port, jump/long-jump)
  pcg64.hpp              fast engine #2 (XSL-RR 128/64, NumPy-compatible)
  crypto/sha256.hpp      SHA-256 (FIPS 180-4) + OpenSSL backend switch
  crypto/hmac_sha256.hpp HMAC (RFC 2104)
  crypto/hmac_drbg.hpp   HMAC_DRBG (NIST SP 800-90A §10.1.2)
  crypto/ctr_drbg.hpp    AES-256-CTR_DRBG (SP 800-90A §10.2.1, OpenSSL only)
  crypto/drbg_engine.hpp DRBG -> engine adapter + entropy helper
  random.hpp             mapping layer: doubles/floats/unbiased bounded ints
  provably_fair.hpp      commit–reveal, HMAC byte stream, sessions
  detail/uint128.hpp     portable 128-bit math (MSVC/GCC/Clang)
c_api/                   C ABI wrapper: public header, shared + static targets
bindings/python/         ctypes binding over the C ABI, plus cross_check.py
tests/                   rng_tests, 672k checks, golden values from
                         independent implementations (Python/NumPy)
tools/                   rng_verifier, rng_pi, rng_ode, rng_bench,
                         rng_thread_bench (scalability), rng_memory
                         (footprint), rng_stream,
                         plot_monte_carlo.py (spec 10.1/10.2 plots)
examples/quickstart.cpp  the whole API in one page
examples/integration_demo.cpp  commissioning walkthrough backing INTEGRATION_GUIDE.md
web/verifier.html        independent web verifier, single file, offline, no deps
docs/                    design notes, open research items, results
```

## Build & run (VSCode or CLI)

Open `rng-sdk/` in VSCode → the default build task (`Ctrl+Shift+B`) configures
and builds; "Run tests" is the default test task. CLI:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

Production crypto backend: `-DRNGSDK_USE_OPENSSL=ON` (bit-for-bit identical
output; the bundled reference implementation is the zero-setup default).
This also enables the second crypto engine, AES-256-CTR-DRBG
(`rngsdk::CtrRandom`), which needs OpenSSL's AES and runs **~13x** faster than
HMAC-DRBG on x86-64 where AES-NI is available (DESIGN_NOTES §8b). On ARM64 the
same ratio measures ~31x; both figures are correct for their own platform, so
neither travels as "the" speedup. Example, using vcpkg for OpenSSL:

```bash
cmake -S . -B build-openssl -DRNGSDK_USE_OPENSSL=ON \
      -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
```

## API (spec-conformant)

```cpp
rngsdk::FastRandom   fast(seed);     // xoshiro256++, simulations, game logic
rngsdk::Pcg64Random  pcg(seed);      // PCG64, same tier, NumPy-compatible
rngsdk::CryptoRandom sec(seed);      // HMAC-DRBG, SP 800-90A, fairness-grade

x = rng.NextUInt32();  rng.NextUInt64();          // raw words
d = rng.NextDouble();  f = rng.NextFloat();       // top 53 / 24 bits, exact uniform grid
k = rng.NextUInt64(n); rng.NextUInt32(n);         // [0,n), Lemire rejection, ZERO modulo bias
rng.NextBytes(buf, len);
auto v = rng.NextBytes(len);                      // same bytes, owning vector

// Provably Fair
auto commit = rngsdk::pf::Commitment(server_seed);            // publish BEFORE play
auto vals   = rngsdk::pf::Generator::NextFloats(server_seed, client_seed, nonce, k);
float one   = rngsdk::pf::Generate(server_seed, client_seed, nonce);
bool ok     = rngsdk::pf::VerifyCommitment(revealed, commit); // player-side
```

### Using the SDK from another language

The C++ library is header-only, which is the right shape for a C++ integrator
and unusable from C#, Java, Node, Go or Python. For those, build the C ABI
wrapper, which is one shared library and one header:

```
cmake --build build --config Release --target rngsdk_c
```

`c_api/include/rngsdk_c.h` is the whole public surface, and
`bindings/python/` is a complete worked example. See §4 of
`docs/INTEGRATION_GUIDE.md` for which flavour to ship, the batching rule, and
the memory contract.

## Verifier (independent, 3 forms)

The spec requires the verifier in three independent forms, console, web
page, and integrator library, so that checking a result never depends on
trusting our toolchain.

**Console** (`rng_verifier`, 1 file):

```
rng_verifier commit  <server_seed>
rng_verifier verify  <server_seed> <commitment> <client_seed> <nonce> [count]
rng_verifier ints    <server_seed> <client_seed> <nonce> <bound> [count] [--unbiased]
```

**Web** (`web/verifier.html`, 1 file): open it directly from disk (double-click
or a `file://` URL), with no server, no build step, and no network request of
any kind. WebCrypto is used when the browser exposes `crypto.subtle` in that
context; a hand-rolled, KAT-validated pure-JS SHA-256/HMAC fallback covers the
case where it does not, so the page still works offline years from now, email-
to-a-regulator style. A visible banner names the active backend. Beyond the
commitment/result check, it shows the full derivation (HMAC message, key in
both interpretations of the hex-string-as-ASCII convention, block bytes) and
includes a client-seed generator, so a player never has to trust the operator
to produce their seed. Its self-test (`node tools/web_selftest.js` for a
headless run, or the in-page button) checks both crypto backends against the
same vectors the C++ suite checks. See `docs/pf_test_vectors.json` and
`tests/golden/generate_pf_vectors.py`, which emit the vector set from one
independent (Python) computation shared by both. Backend selection was
confirmed by hand in Brave and Chrome on Windows (both chose WebCrypto from
`file://`, self-test green); Safari and Firefox remain untested and are
recorded as an open, non-blocking gap in the design spec.

**Library** (for third-party integrators embedding verification in their own
code): `docs/INTEGRATION_GUIDE.md` carries the API reference, the five security
obligations the library cannot enforce on its own (each with failure mode,
wrong code, right code, and a `SECURITY_ANALYSIS.md` cross-reference), and a
pre-launch checklist, backed by the compiled, warning-free
`examples/integration_demo.cpp`. Non-C++ callers reach the same verification
through the C ABI wrapper described above.

## Scalability under threads (rng_thread_bench)

Spec §6's "scalability (multithreading)" axis. `rng_bench` measures one engine
on one core; this measures aggregate throughput as thread count rises, one
engine per thread, no shared mutable state:

```
rng_thread_bench [words_per_thread] [--repeats R] [--csv FILE]
```

Thread counts are 1, 2, 4 … up to `hardware_concurrency`, then a deliberately
oversubscribed 2× row. Stream separation is per-engine: xoshiro256++ thread *t*
takes *t* `Jump()`s (disjoint 2^128 subsequences), PCG64 takes a distinct seed
(2^127 selectable streams), and each DRBG is a wholly independent instance.

**A self-check runs before any timing** and aborts if two threads' first words
coincide. Without it a seeding slip that handed every thread the same stream
would still print a textbook-perfect linear curve, which is the one failure
mode no timing assertion can catch.

Read `efficiency` (speedup ÷ threads), not raw speedup: 100% is linear. The 2×
row is *expected* near 50% (scheduler time-slicing, not contention); a collapse
there, or sag well before the core count, is the finding worth chasing.
Heterogeneous-core machines (Apple/Intel P+E) sag once E-cores fill, so report
the core split alongside. Results: `docs/scalability_results.txt`.

## Memory footprint (rng_memory)

Spec §6's "memory consumption" axis. Prints `sizeof` for every engine, wrapper
and Provably Fair object, plus the four things `sizeof` cannot see. Takes no
arguments:

```
rng_memory
```

| | per engine | of which state |
|---|---|---|
| Fast tier (xoshiro256++, PCG64) | **32 B** | 32 B, no heap, ever |
| Crypto tier (HMAC-DRBG / CTR-DRBG) | **4184 / 4176 B** | 80 / 72 B |
| PF session (`ByteStream`, `ServerSession`) | **120 B** | + 1 heap alloc per seed string |

The crypto tier is ~98% output buffer rather than DRBG state: `drbg_engine.hpp`
buffers 4 KiB per `Generate` to make `NextUInt64` ~128× cheaper. That is a speed
trade, and it is the knob to turn if you hold very many concurrent sessions.

Nothing grows with the number of values drawn, since the generate path is
arithmetic over fixed state, so the multithreaded cost is exactly one engine
per thread. `sizeof` is ABI-dependent, so the committed tables in
`docs/memory_results.txt` carry the provenance block of the build that
produced them, both backends.

## Statistical batteries (rng_stream)

Raw byte streams for NIST SP 800-22 / Dieharder / TestU01 / PractRand:

```
rng_stream --source xoshiro|pcg64|hmac|ctr|pf|randu [--seed N] [--bytes 125M]
rng_stream --source xoshiro | RNG_test stdin64        # PractRand
```

Engine sources stream `Random<Engine>::NextBytes`, the consumer-facing call,
so the mapping layer and the DRBG 4 KiB buffering are inside the tested path
(CAVP vectors validate the DRBG core only). `pf` streams the Provably Fair
HMAC bytes, advancing the nonce. `randu` is the deliberately broken negative
control and **must fail**: if it passes, the harness cannot detect failure.

Install steps, exact commands and p-value adjudication rules:
`docs/statistical_testing_runbook.md`. Cross-platform determinism handshake:
`docs/statistical_results/fingerprints.txt`.

## Validation status (what this prototype proves)

- **Correctness by independent cross-check.** SHA-256/HMAC match FIPS/RFC
  vectors and Python hashlib; HMAC-DRBG matches an independent Python
  SP 800-90A implementation; PCG64 matches NumPy word-for-word; xoshiro256++
  matches the canonical reference. 672,299 checks pass (895,577 with
  `-DRNGSDK_USE_OPENSSL=ON`, which adds the CTR-DRBG tier).
- **No mapping bias.** Doubles are exactly uniform on the 2^53 grid; bounded
  ints use Lemire rejection (provably exact, see docs/DESIGN_NOTES.md); the
  test suite demonstrates the modulo bias it eliminates (chi² 252 vs 5).
- **Avalanche.** 1-bit seed flip → 50.0% output bits flip (all engines).
- **Monte Carlo π** (2D + 3D): errors track O(1/√N) inside 95% CIs for all
  five sound engines compared (our two + HMAC-DRBG + Mersenne Twister + C
  `rand()`, spec 10.3). Two deliberately broken controls fail *differently*,
  which is the spec's correlation study: RANDU passes the smooth integrals and
  is convicted only by the serial box test (chi²/df 10→93 in N), while `LCG5`
  wrecks the estimate itself, its 3D result **converging to 3.2644, not π**,
  landing ~66 CI half-widths off at N=10⁷. More samples buy precision around
  the wrong answer. Results: docs/pi_results.{txt,csv}, docs/plots/pi_*.png.
- **Monte Carlo ODE** (y″+y=0, exact y=sin x, item #7): von Neumann–Ulam
  walk over the Volterra form is exactly unbiased; sound engines' error
  tracks O(1/√N), RANDU's ~4e-4 floor only resolves at N≥10⁶, isolated by a
  depth-decomposition diagnostic to bias in triples of consecutive draws,
  matching RANDU's own defining defect. Full derivation and results:
  docs/ODE_MONTE_CARLO.md, docs/ode_results.{txt,csv}, docs/plots/ode_*.png.
- **Throughput** (1 core, MSVC Release, 2-core laptop, idle, median of ≥5 runs,
  in `docs/benchmark_results.txt`): xoshiro256++ ~7.0e8 u64/s, PCG64 ~4.6e8,
  CTR-DRBG ~3.2e7 (OpenSSL build), HMAC-DRBG ~2.5e6; the spec 10.3 comparators
  are std::mt19937_64 ~2.2e8 and C `rand()` ~1.6e7 (five `rand()` calls per
  64-bit word, as the Monte Carlo tools consume it). CTR-DRBG is **~13×**
  HMAC-DRBG on this machine, quoted to two figures rather than three: the
  bundled-HMAC denominator moves the ratio between 12.9× and 13.6× across
  sessions on one box.
  Always benchmark on an **idle** machine via `tools/bench_median.py`, which
  runs one binary at a time: under concurrent load this box's spread blows out
  from ~1.1× to ~8×.
- **Second CPU architecture** (spec §6): ARM64 / macOS / Apple clang on an
  Apple M4 Pro, taken by the partner 2026-09-12, same median-of-5 protocol.
  Both suites are green there at the same counts as x86-64, so determinism
  holds across architectures and not only across builds. The CTR-vs-HMAC ratio
  measures ~31× on that machine, and OpenSSL's HMAC is ~1.2× *faster* than the
  bundled reference where on x86-64 it is ~2× slower. Recorded as a
  measurement, with no cause asserted (docs/benchmark_results.txt, MACHINE 2).

## What this prototype is NOT yet

See docs/OPEN_RESEARCH.md for the full gap list with effort estimates, and
#7c there for a clause-by-clause traceability matrix against the source spec.
Done since the first prototype: OS-CSPRNG entropy sourcing (#1),
AES-CTR-DRBG (#2), NIST CAVP validation of both crypto engines (#4),
Provably Fair reveal-lock (#5b), the statistical-battery harness (#3, meaning
`rng_stream` + runbook, while the battery *runs themselves* are still pending),
the mathematical justification (docs/MATH_JUSTIFICATION.md), the security
analysis and the four fixes it produced (docs/SECURITY_ANALYSIS.md), the
ODE Monte Carlo task (#7, with plots), the Monte Carlo stability metric
and fitted convergence exponent (#7c(c),(d), via `--repeats`, R=25 per cell),
the web and library verifiers with the C ABI wrapper and Python binding (#8),
and the memory, multithreading and second-architecture measurements (#9).
Still open: the battery runs and their pass/fail matrix, and the final report.
Those are the remaining licensing-grade work items.

License: MIT (LICENSE). No third-party code except public-domain algorithms.
