// ode_monte_carlo.cpp — spec additional task #2: solve y'' + y = 0,
// y(0)=0, y'(0)=1 (exact solution sin x) by Monte Carlo, and compare
// engines on it.
//
// Method: the Volterra form y(x) = x − ∫₀ˣ(x−t)y(t)dt evaluated by a
// von Neumann–Ulam random walk over its Neumann series. Estimator and
// derivation live in ode_solver.hpp; the design rationale, including why
// the estimator is exactly unbiased and why that matters, is in
// docs/design/2026-08-24-ode-monte-carlo-design.md.
//
// What to look for in the output is documented in the footer the tool
// prints, so a reader of the raw log does not need this file.
//
// Usage: rng_ode [max_exponent=7] [--q 0.5] [--csv out.csv]
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "rngsdk/rngsdk.hpp"
#include "ode_solver.hpp"
#include "randu_bad.hpp"
#include "lcg_smallmul_bad.hpp"
#include "std_engine_adapters.hpp"
#include "stability_stats.hpp"   // spec 10.3 stability + 10.1 fitted exponent
#include "write_csv.hpp"         // shared 17-sig-fig + flush-checked CSV writer

// Two broken controls with error floors three orders of magnitude apart,
// because the CONTRAST is the finding: this task resolves a floor only once
// N is large enough that sigma/sqrt(N) drops below it. LCG5's ~7e-2 floor is
// obvious at N=1e4; RANDU's ~4e-4 floor needs N=1e6-1e7. Both fail in the
// end. See lcg_smallmul_bad.hpp for why a second control was added at all.
using RanduBad = rngtools::RanduBad;
using SmallMulLcg = rngtools::SmallMultiplierLcg;

static const double kPi = 3.14159265358979323846;

// Eight points on (0, π/2] — the spec's domain — plus x = π kept separate.
// π is NOT folded into the RMSE: the estimator's weight is W(x) = −x²/2, so
// variance climbs sharply with x and averaging the two regimes together
// would hide both. It is reported on its own to show that growth honestly.
static const double kGrid[] = {
    kPi / 16, 2 * kPi / 16, 3 * kPi / 16, 4 * kPi / 16,
    5 * kPi / 16, 6 * kPi / 16, 7 * kPi / 16, 8 * kPi / 16,
};
static constexpr int kGridN = 8;
static const double kStressX = kPi;

struct Cell {
    const char* engine;
    std::uint64_t n;
    double x, estimate, exact, abs_err, stddev, stderr_mean, ci95;
    int inside_ci;
    bool sound;   // false for the deliberately broken controls
};

struct Summary {
    const char* engine;
    std::uint64_t n;
    double rmse, max_err, rmse_sqrt_n;
    double rms_sigma;   // RMS over the grid of the per-point single-walk sigma
    double ratio;       // rmse_sqrt_n / rms_sigma — expectation ~1 if the CIs are honest
    int inside, total;
};

template <class Engine>
static void RunEngine(const char* name, bool sound, double q, int max_exp,
                      std::vector<Summary>& summaries,
                      std::vector<Cell>& cells,
                      std::vector<Cell>& stress) {
    for (int e = 4; e <= max_exp; ++e) {
        std::uint64_t n = 1;
        for (int i = 0; i < e; ++i) n *= 10;

        // A fresh seed per N, so the N=10^4 row is not literally the first
        // slice of the N=10^7 row — which would make the convergence trend an
        // artefact of nesting rather than a measurement.
        //
        // For the two LCG controls this buys separation, NOT independence:
        // both are full-period (or full-odd-period) generators with a single
        // orbit, so distinct seeds are distinct offsets on one shared cycle.
        // At N=10^7 the RANDU row consumes a large fraction of its 2^29-long
        // cycle and overlap with the shorter rows is likely. Acceptable for a
        // control whose purpose is to fail; stated so the failure is not
        // mistaken for something it is not. (RanduBad::Seed is injective since
        // 2026-08-18; before that fix consecutive seeds here silently collided.)
        rngsdk::Random<Engine> rng(static_cast<std::uint64_t>(20260824 + 1000 * e));
        auto u01 = [&rng] { return rng.NextDouble(); };

        double sse = 0.0, max_err = 0.0, ssigma = 0.0;
        int inside = 0;
        for (int g = 0; g < kGridN; ++g) {
            const double x = kGrid[g];
            const auto est = rngtools::EstimateY(u01, x, n, q);
            const double exact = std::sin(x);
            const double err = std::fabs(est.mean - exact);
            const double ci = 1.959964 * est.stderr_mean;
            const int in = err < ci ? 1 : 0;
            sse += err * err;
            ssigma += est.stddev * est.stddev;
            if (err > max_err) max_err = err;
            inside += in;
            cells.push_back({name, n, x, est.mean, exact, err, est.stddev,
                             est.stderr_mean, ci, in, sound});
        }

        // RMSE*sqrtN alone is a poor criterion: the per-point sigmas span
        // ~450x across the grid, so its effective degrees of freedom is ~2.4
        // and its relative scatter is ~45%. Dividing by RMS(sigma) — the value
        // it is *predicted* to equal — turns an eyeball trend into a
        // calibrated number whose expectation is 1 regardless of engine or N.
        const double rmse = std::sqrt(sse / kGridN);
        const double rms_sigma = std::sqrt(ssigma / kGridN);
        const double rmse_sqrt_n = rmse * std::sqrt(static_cast<double>(n));
        summaries.push_back({name, n, rmse, max_err, rmse_sqrt_n, rms_sigma,
                             rms_sigma > 0.0 ? rmse_sqrt_n / rms_sigma : 0.0,
                             inside, kGridN});

        // The x = π stress point, same engine and N.
        const auto se = rngtools::EstimateY(u01, kStressX, n, q);
        const double sx = std::sin(kStressX);
        const double serr = std::fabs(se.mean - sx);
        const double sci = 1.959964 * se.stderr_mean;
        stress.push_back({name, n, kStressX, se.mean, sx, serr, se.stddev,
                          se.stderr_mean, sci, serr < sci ? 1 : 0, sound});
    }
}

static void PrintSummary(const std::vector<Summary>& s) {
    std::printf("%-14s %10s %12s %12s %12s %10s %8s %8s\n",
                "engine", "N", "RMSE", "max_err", "RMSE*sqrtN", "RMS(sigma)",
                "ratio", "in95%CI");
    for (const auto& r : s)
        std::printf("%-14s %10llu %12.3e %12.3e %12.4f %10.4f %8.2f %6d/%d\n",
                    r.engine, static_cast<unsigned long long>(r.n),
                    r.rmse, r.max_err, r.rmse_sqrt_n, r.rms_sigma, r.ratio,
                    r.inside, r.total);
}

// Spec §7 step 2, skipped in the first pass: a targeted diagnostic on the
// within-walk uniforms, added after review disproved the original "pairs
// only see 2-D structure" explanation for why RANDU fails here (it fails
// worst at LOW q, where walks almost never survive twice).
//
// This tests a different, still-open hypothesis: sigma_hat's confidence
// intervals assume the N walk scores are i.i.d. If RANDU's low-dimensional
// lattice makes consecutive WALKS correlated with each other — not biased
// individually, but correlated across the outer loop — the true variance of
// the mean exceeds sigma_hat^2/N even with zero per-walk bias, which alone
// would explain collapsing coverage. Reports the sample lag-1/lag-2
// autocorrelation of the walk-score sequence; draws no conclusion beyond
// what the numbers show, per the same discipline as the retracted claim.
template <class Engine>
static void SerialCorrelationDiagnostic(const char* name, double x, double q, std::uint64_t n) {
    rngsdk::Random<Engine> rng(20260824);
    auto u01 = [&rng] { return rng.NextDouble(); };
    std::vector<double> s(n);
    for (std::uint64_t i = 0; i < n; ++i) s[i] = rngtools::OdeWalkScore(u01, x, q);

    double mean = 0.0;
    for (double v : s) mean += v;
    mean /= static_cast<double>(n);

    auto autocorr = [&](std::uint64_t lag) {
        double num = 0.0, den = 0.0;
        for (std::uint64_t i = 0; i < n; ++i) den += (s[i] - mean) * (s[i] - mean);
        for (std::uint64_t i = 0; i + lag < n; ++i) num += (s[i] - mean) * (s[i + lag] - mean);
        return den > 0.0 ? num / den : 0.0;
    };
    // Under i.i.d., autocorrelation at any lag is asymptotically N(0, 1/n).
    const double se = 1.0 / std::sqrt(static_cast<double>(n));
    const double a1 = autocorr(1), a2 = autocorr(2);
    std::printf("%-16s lag1=%+8.5f (%.1f se)   lag2=%+8.5f (%.1f se)\n",
                name, a1, a1 / se, a2, a2 / se);
}

// Localizes WHERE in the Neumann series an RNG defect's bias concentrates,
// by estimating each term Kᵈf(x) in isolation (ForcedWalkTerm — d forced
// hops, no roulette) and comparing against the analytic NeumannTerm.
//
// Motivation: randu_bad.hpp documents RANDU's own defining defect as a
// relation over CONSECUTIVE TRIPLES (x_{n+2} = 6x_{n+1} - 9x_n mod 2^31).
// The walk consumes uniforms strictly consecutively, so every triple of walk
// draws sits on that lattice -- which is exactly the structure a depth-2 term
// (three draws: two roulette + related position draws) would expose. This
// replaces an earlier, weaker attempt to localize the mechanism via a q-sweep
// and a lag-1/2 autocorrelation check, neither of which isolates depth.
template <class Engine>
static void DepthDecomposition(const char* name, double x, std::uint64_t n) {
    rngsdk::Random<Engine> rng(20260824);
    auto u01 = [&rng] { return rng.NextDouble(); };
    std::printf("%-16s", name);
    // Each hop consumes exactly one uniform (SampleT; no roulette in
    // ForcedWalkTerm), so d=3 is the first depth spanning THREE consecutive
    // draws -- the width of RANDU's own plane relation. d=1/d=2 only span
    // one and two draws respectively, and RANDU's PAIRS are known-good (its
    // failure is specifically 3-dimensional), so they are a necessary
    // negative control for d=3, not the test itself.
    for (int d = 1; d <= 3; ++d) {
        double mean = 0.0, m2 = 0.0;
        for (std::uint64_t i = 1; i <= n; ++i) {
            const double s = rngtools::ForcedWalkTerm(u01, x, d);
            const double delta = s - mean;
            mean += delta / static_cast<double>(i);
            m2 += delta * (s - mean);
        }
        const double sd = std::sqrt(m2 / static_cast<double>(n - 1));
        const double se = sd / std::sqrt(static_cast<double>(n));
        const double exact = rngtools::NeumannTerm(d, x);
        const double z = se > 0.0 ? (mean - exact) / se : 0.0;
        std::printf("  d=%d: est=%+.6e exact=%+.6e z=%+6.2f", d, mean, exact, z);
    }
    std::printf("\n");
}

static void PrintStress(const std::vector<Cell>& c) {
    std::printf("%-14s %10s %12s %12s %12s %12s\n",
                "engine", "N", "estimate", "abs_err", "sigma_hat", "err*sqrtN");
    for (const auto& r : c)
        std::printf("%-14s %10llu %12.6f %12.3e %12.4f %12.4f\n",
                    r.engine, static_cast<unsigned long long>(r.n), r.estimate,
                    r.abs_err, r.stddev,
                    r.abs_err * std::sqrt(static_cast<double>(r.n)));
}

// atoi/atof map unparseable input to 0 and stop at the first bad character,
// so `rng_ode 1e7` would silently run N=10 and `--q 0.5x` would silently pass
// validation. That is the same defect class code review caught in stream.cpp's
// --seed on 2026-08-18: a mis-typed argument that produces a plausible-looking
// results file instead of an error. Both parsers below reject trailing junk.
static bool ParseInt(const char* s, int* out) {
    char* end = nullptr;
    errno = 0;
    const long v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0' || errno == ERANGE || v < INT_MIN || v > INT_MAX)
        return false;
    *out = static_cast<int>(v);
    return true;
}

static bool ParseDouble(const char* s, double* out) {
    char* end = nullptr;
    errno = 0;
    const double v = std::strtod(s, &end);
    if (end == s || *end != '\0' || errno == ERANGE || !std::isfinite(v)) return false;
    *out = v;
    return true;
}

// ==================================================== stability (10.3/10.1) ==
//
// As in rng_pi: every cell above is ONE run, so spec 10.3's "stability of
// results" was unmeasured and 10.1's convergence exponent unfitted. Repeats
// fix both (OPEN_RESEARCH #7c(c),(d)). Additive -- default output unchanged.
//
// Repeats are taken at TWO grid points rather than all eight. The eight points
// are eight DIFFERENT quantities, so repeating all of them costs 8x for no
// extra information about stability, which is a property of re-estimating the
// SAME quantity. Index 7 (x = pi/2) is the highest-variance point in the spec
// domain -- the conservative choice -- and index 3 (x = pi/4) is included so
// the result cannot be dismissed as holding only at the hardest point.
//
// That last clause was FALSE as originally implemented, and the fix is why
// each slot now takes its base from GridSlotBase. Both points were seeded
// RepeatSeed(20260824, r, e) -- no x term -- and the walk's roulette test
// (u01() >= q) is x-independent as well, so for a given (engine, N, repeat)
// the two points consumed a bit-identical uniform stream: same draws, same
// walk lengths, only the deterministic scoring differed. Correlation of
// bias/predicted_sd between them measured 1.00. The second point could not
// corroborate the first because it was not a second measurement.
static const int kStabilityIdx[] = {3, 7};
static constexpr int kStabilityIdxN = 2;

struct OdeStabRow {
    const char* engine;
    double x;
    std::uint64_t n;
    int repeats;
    double mean, sd, predicted_sd, sd_ratio, rms_err, bias;
};

struct OdeFitRow {
    const char* engine;
    double x;
    double slope, ci_lo, ci_hi;
    bool valid;
};

template <class Engine>
static void RunOdeStability(const char* name, double x, int slot, double q,
                            int max_exp, int repeats,
                            std::vector<OdeStabRow>& rows,
                            std::vector<OdeFitRow>& fits) {
    const double exact = std::sin(x);
    // Distinct seed base per grid point, so the two points are two independent
    // measurements rather than one stream scored twice (see kStabilityIdx).
    const std::uint64_t base = rngtools::GridSlotBase(20260824ULL, slot);
    std::vector<double> ns, rms_errs;

    for (int e = 4; e <= max_exp; ++e) {
        std::uint64_t n = 1;
        for (int i = 0; i < e; ++i) n *= 10;

        std::vector<double> est;
        double sigma_sum = 0.0;
        est.reserve(repeats);
        for (int r = 0; r < repeats; ++r) {
            rngsdk::Random<Engine> rng(rngtools::RepeatSeed(base, r, e));
            auto u01 = [&rng] { return rng.NextDouble(); };
            const auto s = rngtools::EstimateY(u01, x, n, q);
            est.push_back(s.mean);
            sigma_sum += s.stddev;
        }

        const auto s = rngtools::Aggregate(est, exact);
        // The estimator's OWN variance estimate, averaged over repeats, is what
        // the observed spread should equal. Comparing them tests whether
        // sigma_hat is honestly calibrated -- the same question section 6.1's
        // coverage column answers, but measured directly rather than inferred
        // from how often the CI covers.
        const double predicted =
            (sigma_sum / repeats) / std::sqrt(static_cast<double>(n));
        rows.push_back({name, x, n, s.repeats, s.mean, s.sd, predicted,
                        predicted > 0.0 ? s.sd / predicted : 0.0, s.rms_err, s.bias});
        ns.push_back(static_cast<double>(n));
        rms_errs.push_back(s.rms_err);
    }

    const auto f = rngtools::FitLogLogSlope(ns, rms_errs);
    fits.push_back({name, x, f.slope, f.ci_lo, f.ci_hi, f.valid});
}

static void PrintOdeStability(const std::vector<OdeStabRow>& rows,
                              const std::vector<OdeFitRow>& fits, double x) {
    std::printf("\nx = %.6f (sin x = %.6f) -- stability over repeats (spec 10.3):\n",
                x, std::sin(x));
    std::printf("%-14s %10s %6s %12s %12s %12s %9s %12s\n",
                "engine", "N", "R", "mean", "sd", "predicted_sd", "sd_ratio", "bias");
    for (const auto& r : rows) {
        if (r.x != x) continue;
        std::printf("%-14s %10llu %6d %12.6f %12.3e %12.3e %9.2f %+12.3e\n",
                    r.engine, static_cast<unsigned long long>(r.n), r.repeats,
                    r.mean, r.sd, r.predicted_sd, r.sd_ratio, r.bias);
    }
    std::printf("convergence exponent (spec 10.1; theory -0.50):\n");
    for (const auto& f : fits) {
        if (f.x != x) continue;
        if (!f.valid) { std::printf("  %-14s %10s\n", f.engine, "n/a"); continue; }
        std::printf("  %-14s %8.3f   [%+.3f, %+.3f]\n",
                    f.engine, f.slope, f.ci_lo, f.ci_hi);
    }
}

int main(int argc, char** argv) {
    // 10^8 walks per grid point already costs ~20 minutes on the crypto tier;
    // the cap exists so a typo like `rng_ode 77` fails immediately instead of
    // appearing to hang forever.
    const int kMaxExp = 8;
    int max_exp = 7;
    double q = 0.5;
    int repeats = 0;
    std::string csv_path, stab_csv, fit_csv;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (std::strcmp(argv[i], "--stability-csv") == 0 && i + 1 < argc) {
            stab_csv = argv[++i];
        } else if (std::strcmp(argv[i], "--fit-csv") == 0 && i + 1 < argc) {
            fit_csv = argv[++i];
        } else if (std::strcmp(argv[i], "--repeats") == 0 && i + 1 < argc) {
            // >= 3 so the sample SD has at least 2 degrees of freedom; the
            // upper bound keeps the seed span inside the stride GridSlotBase
            // uses to separate grid points. The slope fit's df comes from the
            // number of N values (max_exp - 5), not from R.
            if (!ParseInt(argv[++i], &repeats) || repeats < 3 ||
                repeats > rngtools::kMaxRepeats) {
                std::fprintf(stderr,
                             "--repeats must be an integer in [3,%d] (>=3 so the "
                             "sample SD has df>=2); got %s\n",
                             rngtools::kMaxRepeats, argv[i]);
                return 2;
            }
        } else if (std::strcmp(argv[i], "--q") == 0 && i + 1 < argc) {
            if (!ParseDouble(argv[++i], &q)) {
                std::fprintf(stderr, "bad --q value: %s\n", argv[i]);
                return 2;
            }
        } else if (!ParseInt(argv[i], &max_exp)) {
            std::fprintf(stderr, "bad argument: %s\n", argv[i]);
            std::fprintf(stderr, "usage: rng_ode [max_exponent=7] [--q 0.5] [--csv out.csv]\n");
            return 2;
        }
    }
    if (max_exp < 4 || max_exp > kMaxExp) {
        std::fprintf(stderr, "max_exponent must lie in [4,%d]; got %d\n", kMaxExp, max_exp);
        return 2;
    }
    if (!(q > 0.0 && q < 1.0)) {
        std::fprintf(stderr, "--q must lie strictly in (0,1); got %g\n", q);
        return 2;
    }

    // --repeats runs a different experiment and returns early, so a --csv
    // passed alongside it would be silently discarded, leaving a stale file
    // the caller believes is fresh. Refuse instead.
    if (repeats > 0 && !csv_path.empty()) {
        std::fprintf(stderr,
                     "--csv writes the single-run tables, which --repeats does "
                     "not produce; use --stability-csv / --fit-csv, or run the "
                     "two invocations separately\n");
        return 2;
    }

    if (repeats > 0) {
        std::vector<OdeStabRow> srows;
        std::vector<OdeFitRow> sfits;
        for (int gi = 0; gi < kStabilityIdxN; ++gi) {
            const double x = kGrid[kStabilityIdx[gi]];
            RunOdeStability<rngsdk::Xoshiro256pp>("xoshiro256++", x, gi, q, max_exp, repeats, srows, sfits);
            RunOdeStability<rngsdk::Pcg64>("pcg64", x, gi, q, max_exp, repeats, srows, sfits);
            RunOdeStability<rngsdk::crypto::HmacDrbgEngine>("hmac-drbg", x, gi, q, max_exp, repeats, srows, sfits);
            RunOdeStability<rngtools::Mt19937_64Adapter>("mt19937_64", x, gi, q, max_exp, repeats, srows, sfits);
            RunOdeStability<rngtools::RandBuiltin>("rand()-builtin", x, gi, q, max_exp, repeats, srows, sfits);
            RunOdeStability<RanduBad>("RANDU(bad)", x, gi, q, max_exp, repeats, srows, sfits);
            RunOdeStability<SmallMulLcg>("LCG5(bad)", x, gi, q, max_exp, repeats, srows, sfits);
        }
        std::printf("y'' + y = 0 -- stability and convergence exponent\n");
        std::printf("R = %d independent repeats per (engine, N), distinct seeds, q=%.2f\n",
                    repeats, q);
        std::printf("Two grid points: x = pi/4 (mid-domain) and x = pi/2 "
                    "(highest variance in domain)\n");
        for (int gi = 0; gi < kStabilityIdxN; ++gi)
            PrintOdeStability(srows, sfits, kGrid[kStabilityIdx[gi]]);

        std::puts("\nCAVEAT on the single-orbit generators: RANDU, LCG5 and C rand()");
        std::puts("each have ONE cycle, so distinct seeds give distinct OFFSETS on that");
        std::puts("cycle, not independent streams; at large N their repeats overlap and");
        std::puts("their sd is weaker evidence than the other engines'.");
        std::puts("");
        std::puts("rand() is the notable case, because it is not a deliberate control.");
        std::puts("MSVC's rand() has an output period of 2^31 ~ 2.15e9 and this adapter");
        std::puts("draws 5 calls per 64-bit word, so at N=1e7 the 25 repeats consume");
        std::puts("~3.75e9 draws -- 1.75x the entire period. Its repeats at that row are");
        std::puts("not merely correlated, they WRAP. That is itself a spec 10.3 finding:");
        std::puts("the language built-in cannot supply 25 independent runs at this scale.");

        if (!stab_csv.empty()) {
            const bool ok = rngtools::WriteCsv(
                stab_csv,
                "x,engine,n,repeats,mean,exact,sd,predicted_sd,sd_ratio,rms_err,bias\n",
                [&](std::ostream& f) {
                    for (const auto& r : srows)
                        f << r.x << ',' << r.engine << ',' << r.n << ',' << r.repeats << ','
                          << r.mean << ',' << std::sin(r.x) << ',' << r.sd << ','
                          << r.predicted_sd << ',' << r.sd_ratio << ',' << r.rms_err << ','
                          << r.bias << "\n";
                });
            if (!ok) return 1;
            std::printf("\nstability csv written: %s\n", stab_csv.c_str());
        }
        if (!fit_csv.empty()) {
            const bool ok = rngtools::WriteCsv(fit_csv, "x,engine,slope,ci_lo,ci_hi\n",
                                               [&](std::ostream& f) {
                                                   for (const auto& r : sfits)
                                                       if (r.valid)
                                                           f << r.x << ',' << r.engine << ','
                                                             << r.slope << ',' << r.ci_lo << ','
                                                             << r.ci_hi << "\n";
                                               });
            if (!ok) return 1;
            std::printf("fit csv written: %s\n", fit_csv.c_str());
        }
        return 0;
    }

    std::vector<Summary> summaries;
    std::vector<Cell> cells, stress;
    RunEngine<rngsdk::Xoshiro256pp>("xoshiro256++", true, q, max_exp, summaries, cells, stress);
    RunEngine<rngsdk::Pcg64>("pcg64", true, q, max_exp, summaries, cells, stress);
    RunEngine<rngsdk::crypto::HmacDrbgEngine>("hmac-drbg", true, q, max_exp, summaries, cells, stress);
    // Spec 10.3: compare against Mersenne Twister and the language built-in,
    // not just our own engines and the broken controls.
    RunEngine<rngtools::Mt19937_64Adapter>("mt19937_64", true, q, max_exp, summaries, cells, stress);
    RunEngine<rngtools::RandBuiltin>("rand()-builtin", true, q, max_exp, summaries, cells, stress);
    RunEngine<RanduBad>("RANDU(bad)", false, q, max_exp, summaries, cells, stress);
    RunEngine<SmallMulLcg>("LCG5(bad)", false, q, max_exp, summaries, cells, stress);

    std::printf("y'' + y = 0, y(0)=0, y'(0)=1   exact: y = sin x\n");
    std::printf("von Neumann-Ulam walk over the Volterra form, q=%.2f, "
                "%d grid points on (0, pi/2]\n", q, kGridN);
    // Provenance, so a committed log is reproducible without guessing the
    // invocation that produced it.
    std::printf("rng_ode %d --q %g   (N = 1e4 .. 1e%d)   rngsdk %s, %s backend\n\n",
                max_exp, q, max_exp, rngsdk::kVersion,
#if defined(RNGSDK_USE_OPENSSL)
                "OpenSSL"
#else
                "bundled"
#endif
    );
    PrintSummary(summaries);

    std::printf("\nStress point x = pi (outside the spec domain; shows variance "
                "growth in x):\n");
    PrintStress(stress);

    std::printf("\nSerial correlation of walk scores (spec 7 diagnostic, N=1e6, "
                "x=pi/4; detects only SHORT-lag correlation -- see the depth\n"
                "decomposition below for a diagnostic with resolving power at "
                "the sample sizes where RANDU actually fails):\n");
    SerialCorrelationDiagnostic<rngsdk::Xoshiro256pp>("xoshiro256++", kPi / 4, q, 1000000);
    SerialCorrelationDiagnostic<RanduBad>("RANDU(bad)", kPi / 4, q, 1000000);
    SerialCorrelationDiagnostic<SmallMulLcg>("LCG5(bad)", kPi / 4, q, 1000000);

    std::printf("\nDepth decomposition (N=2e7 per depth, x=pi/2): isolates a "
                "SINGLE Neumann term Kdf(x) via forced d-hop walks (no\n"
                "roulette). d=3 is the first depth spanning THREE consecutive "
                "draws, the width of RANDU's own plane relation:\n");
    DepthDecomposition<rngsdk::Xoshiro256pp>("xoshiro256++", kPi / 2, 20000000);
    DepthDecomposition<RanduBad>("RANDU(bad)", kPi / 2, 20000000);
    DepthDecomposition<SmallMulLcg>("LCG5(bad)", kPi / 2, 20000000);

    // Reported split. Pooling sound engines with deliberately broken ones
    // would drag the aggregate away from 95% and destroy the only number here
    // that validates the estimator itself.
    int sound_in = 0, sound_tot = 0, bad_in = 0, bad_tot = 0;
    for (const auto& c : cells) {
        if (c.sound) { sound_in += c.inside_ci; ++sound_tot; }
        else         { bad_in   += c.inside_ci; ++bad_tot; }
    }
    std::printf("\n95%% CI coverage, sound engines: %d/%d = %.1f%%   (theory: 95%%)\n",
                sound_in, sound_tot, 100.0 * sound_in / (sound_tot ? sound_tot : 1));
    std::printf("95%% CI coverage, broken controls: %d/%d = %.1f%%\n",
                bad_in, bad_tot, 100.0 * bad_in / (bad_tot ? bad_tot : 1));

    std::puts("\nReading the results. The estimator is exactly unbiased (design");
    std::puts("spec 2.4), so there is no acceptable-error threshold to compare");
    std::puts("against: every deviation from sin x is variance or RNG defect.");
    std::puts("");
    std::puts("The column to read is `ratio` = RMSE*sqrtN / RMS(sigma). It");
    std::puts("compares the error actually observed against the error the run's");
    std::puts("own measured variance predicts, so its expectation is 1 for any");
    std::puts("sound engine at any N. RMSE*sqrtN on its own is far noisier than");
    std::puts("it looks (the per-point sigmas span ~450x, giving it ~2.4");
    std::puts("effective degrees of freedom), which is why the ratio and the");
    std::puts("coverage column, not the raw RMSE trend, carry the verdict.");
    std::puts("");
    std::puts("A defective generator does not fail by being wildly wrong. It");
    std::puts("fails by having error that STOPS shrinking: ratio climbs above 1");
    std::puts("with N, and coverage falls away from 95%.");
    std::puts("");
    std::puts("Both controls fail, at DIFFERENT sample sizes, and that contrast");
    std::puts("is the main result. LCG5's error floor is ~7e-2 and is obvious by");
    std::puts("N=1e4. RANDU's floor is ~4e-4: it is invisible through N=1e5,");
    std::puts("emerges by N=1e6, and is unambiguous at N=1e7 where coverage");
    std::puts("collapses. So this task DOES detect RANDU - it simply needs about");
    std::puts("a thousand times more samples to do it. What the report can claim");
    std::puts("is a sensitivity threshold, not a binary pass/fail: an error");
    std::puts("floor of size e is resolved once N is large enough that the");
    std::puts("statistical error sigma/sqrtN falls below it.");
    std::puts("");
    std::puts("Consequence for the SDK: a Monte Carlo task that a generator");
    std::puts("passes at small N says little, because the floor may simply not");
    std::puts("have emerged yet. That is why the external batteries");
    std::puts("(NIST/TestU01/PractRand), which test structure directly rather");
    std::puts("than through a smooth functional, remain mandatory.");
    std::puts("");
    std::puts("Note the x = pi rows carry a much larger sigma_hat - the walk");
    std::puts("weight is -x^2/2, so variance climbs with x. That is a genuine");
    std::puts("limitation of the method, not an RNG result.");

    if (!csv_path.empty()) {
        // The `regime` column is load-bearing: the grid and stress rows are
        // deliberately different regimes (see kStressX), and without it a
        // reader aggregating the CSV would pool them and silently undo the
        // separation the tool maintains.
        const bool ok = rngtools::WriteCsv(
            csv_path, "regime,engine,n,x,estimate,exact,abs_err,stddev,stderr,ci95,inside_ci\n",
            [&](std::ostream& f) {
                auto emit = [&f](const char* regime, const std::vector<Cell>& v) {
                    for (const auto& c : v)
                        f << regime << ',' << c.engine << ',' << c.n << ',' << c.x << ','
                          << c.estimate << ',' << c.exact << ',' << c.abs_err << ','
                          << c.stddev << ',' << c.stderr_mean << ',' << c.ci95 << ','
                          << c.inside_ci << "\n";
                };
                emit("grid", cells);
                emit("stress", stress);
            });
        if (!ok) return 1;
        std::printf("csv written: %s\n", csv_path.c_str());
    }
    return 0;
}
