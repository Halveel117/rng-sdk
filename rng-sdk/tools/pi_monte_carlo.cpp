// pi_monte_carlo.cpp — spec task "validate the RNG on real computations":
// estimate π by uniform points in [0,1)^2, π ≈ 4·N_inside/N, plus a 3D
// variant (sphere octant, π/6) that serves as the correlation study.
//
// For each engine and N in {10^4..10^7} we report:
//   estimate, absolute & relative error, 95% CI half-width, and err·√N.
// Theory: the indicator 1{x²+y²<1} is Bernoulli(p=π/4), so the estimator
// 4·p̂ has std-dev 4·sqrt(p(1-p)/N) ≈ 1.642/√N. A healthy RNG shows
// |err|·√N fluctuating around ~O(1) and errors INSIDE the CI ~95% of the
// time; a correlated RNG shows systematic error that does not shrink.
//
// Usage: rng_pi [max_exponent=7] [--csv out.csv]
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "rngsdk/rngsdk.hpp"
#include "randu_bad.hpp"   // shared with rng_stream's negative control
#include "lcg_smallmul_bad.hpp"      // second bad control, shared with rng_ode
#include "std_engine_adapters.hpp"   // spec 10.3: MT19937-64 + language built-in
#include "stability_stats.hpp"       // spec 10.3 stability + 10.1 fitted exponent
#include "write_csv.hpp"             // shared 17-sig-fig + flush-checked CSV writer

// Deliberately bad generator for the correlation study: RANDU, the infamous
// IBM LCG (x *= 65539 mod 2^31). Consecutive triples lie on 15 planes in
// 3-space. Definition and seeding rationale in randu_bad.hpp.
using RanduBad = rngtools::RanduBad;

// Second bad control, added 2026-08-25 (OPEN_RESEARCH #7c(e)). RANDU's defect
// is three-dimensional, so it largely PASSES the 2D π estimate — which left
// spec 10.4's "systematic error that does not vanish as N grows" demonstrated
// on the π side only by the serial box test, never by a π estimate itself.
// LCG5 (x <- 5x+1 mod 2^31) puts consecutive PAIRS on five lines, so it is
// visible in the 2D estimator directly. Definition in lcg_smallmul_bad.hpp.
using SmallMultiplierLcg = rngtools::SmallMultiplierLcg;

struct Row {
    const char* engine;
    std::uint64_t n;
    double estimate, abs_err, rel_err, ci95, err_sqrt_n;
};

template <class Engine>
static void RunEngine2D(const char* name, std::vector<Row>& rows, int max_exp) {
    const double kPi = 3.14159265358979323846;
    for (int e = 4; e <= max_exp; ++e) {
        std::uint64_t n = 1;
        for (int i = 0; i < e; ++i) n *= 10;
        rngsdk::Random<Engine> rng(static_cast<std::uint64_t>(20260702 + e));
        std::uint64_t inside = 0;
        for (std::uint64_t i = 0; i < n; ++i) {
            const double x = rng.NextDouble();
            const double y = rng.NextDouble();
            if (x * x + y * y < 1.0) ++inside;
        }
        const double est = 4.0 * static_cast<double>(inside) / static_cast<double>(n);
        const double err = std::fabs(est - kPi);
        const double p = static_cast<double>(inside) / n;
        const double ci = 4.0 * 1.959964 * std::sqrt(p * (1.0 - p) / n);
        rows.push_back({name, n, est, err, err / kPi, ci, err * std::sqrt(static_cast<double>(n))});
    }
}

// 3D variant: volume of the unit-sphere octant in [0,1)^3 is π/6.
// This is the honest correlation study: RANDU can PASS the 2D test above
// (its defect is 3-dimensional — consecutive triples lie on 15 planes),
// so only the 3D estimator exposes it. Lesson for the report: a bad RNG's
// hidden correlations survive N -> ∞ and only targeted tests find them.
template <class Engine>
static void RunEngine3D(const char* name, std::vector<Row>& rows, int max_exp) {
    const double kPi = 3.14159265358979323846;
    for (int e = 4; e <= max_exp; ++e) {
        std::uint64_t n = 1;
        for (int i = 0; i < e; ++i) n *= 10;
        rngsdk::Random<Engine> rng(static_cast<std::uint64_t>(777 + e));
        std::uint64_t inside = 0;
        for (std::uint64_t i = 0; i < n; ++i) {
            const double x = rng.NextDouble();
            const double y = rng.NextDouble();
            const double z = rng.NextDouble();
            if (x * x + y * y + z * z < 1.0) ++inside;
        }
        const double est = 6.0 * static_cast<double>(inside) / static_cast<double>(n);
        const double err = std::fabs(est - kPi);
        const double p = static_cast<double>(inside) / n;
        const double ci = 6.0 * 1.959964 * std::sqrt(p * (1.0 - p) / n);
        rows.push_back({name, n, est, err, err / kPi, ci, err * std::sqrt(static_cast<double>(n))});
    }
}

static void PrintTable(const std::vector<Row>& rows) {
    std::printf("%-14s %10s %12s %12s %12s %12s %10s\n",
                "engine", "N", "estimate", "abs_err", "rel_err", "95%CI(+/-)", "err*sqrtN");
    for (const auto& r : rows)
        std::printf("%-14s %10llu %12.8f %12.2e %12.2e %12.2e %10.3f\n",
                    r.engine, static_cast<unsigned long long>(r.n), r.estimate,
                    r.abs_err, r.rel_err, r.ci95, r.err_sqrt_n);
}

// Serial 3D box test — the statistic RANDU actually fails. Partition
// [0,1)^3 into 16^3 = 4096 cells; N consecutive non-overlapping triples
// (d_{3i}, d_{3i+1}, d_{3i+2}) should fill cells ~uniformly (chi2/df ~ 1).
// RANDU's triples lie on 15 planes, leaving most cells starved: chi2/df
// explodes and, crucially, GROWS with N — bias, not noise.
template <class Engine>
static void SerialBoxTest(const char* name) {
    const int k = 16, cells = k * k * k;
    rngsdk::Random<Engine> rng(static_cast<std::uint64_t>(31337));
    for (std::uint64_t n : {100000ULL, 1000000ULL}) {
        std::vector<std::uint64_t> count(cells, 0);
        for (std::uint64_t i = 0; i < n; ++i) {
            const int cx = static_cast<int>(rng.NextDouble() * k);
            const int cy = static_cast<int>(rng.NextDouble() * k);
            const int cz = static_cast<int>(rng.NextDouble() * k);
            ++count[(cx * k + cy) * k + cz];
        }
        const double expected = static_cast<double>(n) / cells;
        double chi2 = 0;
        for (auto c : count) {
            const double d = c - expected;
            chi2 += d * d / expected;
        }
        std::printf("%-14s N=%8llu   chi2/df = %10.2f   %s\n", name,
                    static_cast<unsigned long long>(n), chi2 / (cells - 1),
                    chi2 / (cells - 1) < 1.2 ? "OK" : "FAIL (structured!)");
    }
}

// ==================================================== stability (10.3/10.1) ==
//
// Everything above runs each (engine, N) cell ONCE. That measures error but
// cannot measure spread, so spec 10.3's third metric -- "stability of results"
// -- was unmeasured, and 10.1's "agreement with the theoretical convergence
// rate" was shown only as a picture. Both need repeats (OPEN_RESEARCH #7c).
//
// Deliberately additive: this path writes its own CSV and the default
// invocation is byte-for-byte unchanged, so every number already transcribed
// into the docs and the four committed figures stays valid.

struct StabRow {
    const char* engine;
    int dim;
    std::uint64_t n;
    int repeats;
    double mean, sd, predicted_sd, sd_ratio, rms_err, bias;
};

struct FitRow {
    const char* engine;
    int dim;
    double slope, ci_lo, ci_hi;
    bool valid;
};

// One pi estimate. Intentionally a separate function from RunEngine2D/3D
// rather than a refactor of them: those produce the committed pi_results.*,
// and any accidental change to draw ORDER would silently change every number
// in an artifact that is already cross-checked against the docs.
template <class Engine>
static double EstimatePiOnce(int dim, std::uint64_t n, std::uint64_t seed) {
    rngsdk::Random<Engine> rng(seed);
    std::uint64_t inside = 0;
    if (dim == 2) {
        for (std::uint64_t i = 0; i < n; ++i) {
            const double x = rng.NextDouble();
            const double y = rng.NextDouble();
            if (x * x + y * y < 1.0) ++inside;
        }
        return 4.0 * static_cast<double>(inside) / static_cast<double>(n);
    }
    for (std::uint64_t i = 0; i < n; ++i) {
        const double x = rng.NextDouble();
        const double y = rng.NextDouble();
        const double z = rng.NextDouble();
        if (x * x + y * y + z * z < 1.0) ++inside;
    }
    return 6.0 * static_cast<double>(inside) / static_cast<double>(n);
}

template <class Engine>
static void RunStability(const char* name, int dim, int max_exp, int repeats,
                         std::vector<StabRow>& rows, std::vector<FitRow>& fits) {
    const double kPi = 3.14159265358979323846;
    // The indicator is Bernoulli(p) with p = pi/4 (2D) or pi/6 (3D), so the
    // estimator prefactor*p_hat has sd = prefactor*sqrt(p(1-p)/n). That is a
    // THEORETICAL prediction, not a fit, which is what makes the observed/
    // predicted ratio an independent check rather than a restatement.
    // Constants live in stability_stats.hpp so they are unit-tested; inline
    // literals here survived a mutation that mismatched the 3D pair.
    const auto pp = rngtools::PiStabilityParams(dim);
    const double p = pp.p;
    const double prefactor = pp.prefactor;
    const std::uint64_t base = pp.base;

    std::vector<double> ns, rms_errs;
    for (int e = 4; e <= max_exp; ++e) {
        std::uint64_t n = 1;
        for (int i = 0; i < e; ++i) n *= 10;

        std::vector<double> est;
        est.reserve(repeats);
        for (int r = 0; r < repeats; ++r)
            est.push_back(EstimatePiOnce<Engine>(dim, n, rngtools::RepeatSeed(base, r, e)));

        const auto s = rngtools::Aggregate(est, kPi);
        const double predicted =
            prefactor * std::sqrt(p * (1.0 - p) / static_cast<double>(n));
        rows.push_back({name, dim, n, s.repeats, s.mean, s.sd, predicted,
                        predicted > 0.0 ? s.sd / predicted : 0.0, s.rms_err, s.bias});
        ns.push_back(static_cast<double>(n));
        rms_errs.push_back(s.rms_err);
    }

    // RMS error over the repeats equals the empirical standard error only when
    // the estimator is unbiased; in general rms_err^2 = bias^2 + sd^2*(R-1)/R,
    // so it is total error, not spread. That is the RIGHT quantity to fit here
    // precisely because it does not discard bias: its slope against N is the
    // convergence exponent spec 10.1 asks about -- -1/2 for a sound engine,
    // flattening toward 0 for one whose bias term stops shrinking.
    const auto f = rngtools::FitLogLogSlope(ns, rms_errs);
    fits.push_back({name, dim, f.slope, f.ci_lo, f.ci_hi, f.valid});
}

static void PrintStability(const std::vector<StabRow>& rows,
                           const std::vector<FitRow>& fits, int dim) {
    std::printf("\n%s stability over repeats (spec 10.3) "
                "-- sd_ratio ~ 1 means the spread matches theory:\n",
                dim == 2 ? "2D" : "3D");
    std::printf("%-14s %10s %6s %12s %12s %12s %9s %12s\n",
                "engine", "N", "R", "mean", "sd", "predicted_sd", "sd_ratio", "bias");
    for (const auto& r : rows) {
        if (r.dim != dim) continue;
        std::printf("%-14s %10llu %6d %12.8f %12.3e %12.3e %9.2f %+12.3e\n",
                    r.engine, static_cast<unsigned long long>(r.n), r.repeats,
                    r.mean, r.sd, r.predicted_sd, r.sd_ratio, r.bias);
    }
    std::printf("\n%s convergence exponent (spec 10.1) "
                "-- theory is -0.50; a floor flattens toward 0:\n",
                dim == 2 ? "2D" : "3D");
    std::printf("%-14s %10s %28s\n", "engine", "slope", "95% CI");
    for (const auto& f : fits) {
        if (f.dim != dim) continue;
        if (!f.valid) { std::printf("%-14s %10s\n", f.engine, "n/a"); continue; }
        std::printf("%-14s %10.3f   [%+.3f, %+.3f]\n", f.engine, f.slope, f.ci_lo, f.ci_hi);
    }
}

// Strict integer parse. std::atoi silently reads "7abc" as 7 and "-1" as -1,
// which is how a mistyped exponent could quietly run the wrong experiment --
// the same class of defect the --seed flag had in rng_stream (fixed 2026-08-18).
static bool ParseIntStrict(const char* s, int* out) {
    if (s == nullptr || *s == '\0') return false;
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0') return false;
    if (v < 0 || v > 1000000) return false;
    *out = static_cast<int>(v);
    return true;
}

static void Usage() {
    std::fprintf(stderr,
                 "usage: rng_pi [max_exponent=7] [--csv out.csv]\n"
                 "       rng_pi [max_exponent=7] --repeats R "
                 "--stability-csv out.csv [--fit-csv fit.csv]\n"
                 "\n--repeats runs the stability/convergence experiment INSTEAD of\n"
                 "the single-run tables, since those are already committed.\n");
}

int main(int argc, char** argv) {
    int max_exp = 7;
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
            // >= 3 so the sample SD has at least 2 degrees of freedom (with
            // R=2 a single pair sets the whole spread); <= kMaxRepeats so the
            // seed span stays inside the stride GridSlotBase relies on. The
            // slope fit's df comes from the NUMBER OF N VALUES (max_exp - 5),
            // not from R -- an earlier message claimed otherwise.
            if (!ParseIntStrict(argv[++i], &repeats) || repeats < 3 ||
                repeats > rngtools::kMaxRepeats) {
                std::fprintf(stderr,
                             "--repeats must be an integer in [3,%d] (>=3 so the "
                             "sample SD has df>=2); got %s\n",
                             rngtools::kMaxRepeats, argv[i]);
                return 2;
            }
        } else if (!ParseIntStrict(argv[i], &max_exp)) {
            std::fprintf(stderr, "bad argument: %s\n", argv[i]);
            Usage();
            return 2;
        }
    }
    if (max_exp < 4 || max_exp > 8) {
        std::fprintf(stderr, "max_exponent must lie in [4,8]; got %d\n", max_exp);
        return 2;
    }

    // --repeats runs a different experiment and returns early, so a --csv
    // passed alongside it would be silently discarded and the caller would
    // find a stale file with a fresh timestamp on it. Refuse instead.
    if (repeats > 0 && !csv_path.empty()) {
        std::fprintf(stderr,
                     "--csv writes the single-run tables, which --repeats does "
                     "not produce; use --stability-csv / --fit-csv, or run the "
                     "two invocations separately\n");
        return 2;
    }

    if (repeats > 0) {
        std::vector<StabRow> srows;
        std::vector<FitRow> sfits;
        for (int dim : {2, 3}) {
            RunStability<rngsdk::Xoshiro256pp>("xoshiro256++", dim, max_exp, repeats, srows, sfits);
            RunStability<rngsdk::Pcg64>("pcg64", dim, max_exp, repeats, srows, sfits);
            RunStability<rngsdk::crypto::HmacDrbgEngine>("hmac-drbg", dim, max_exp, repeats, srows, sfits);
            RunStability<rngtools::Mt19937_64Adapter>("mt19937_64", dim, max_exp, repeats, srows, sfits);
            RunStability<rngtools::RandBuiltin>("rand()-builtin", dim, max_exp, repeats, srows, sfits);
            RunStability<RanduBad>("RANDU(bad)", dim, max_exp, repeats, srows, sfits);
            RunStability<SmallMultiplierLcg>("LCG5(bad)", dim, max_exp, repeats, srows, sfits);
        }
        std::printf("Monte Carlo pi -- stability and convergence exponent\n");
        std::printf("R = %d independent repeats per (engine, N), distinct seeds\n", repeats);
        std::printf("N = 1e4 .. 1e%d\n", max_exp);
        PrintStability(srows, sfits, 2);
        PrintStability(srows, sfits, 3);

        std::puts("\nCAVEAT on the SINGLE-ORBIT generators -- RANDU, LCG5 and C rand().");
        std::puts("Each has one cycle, so distinct seeds are distinct OFFSETS on that");
        std::puts("cycle, not independent streams. At N=1e7 their repeats overlap, so");
        std::puts("their sd is a weaker quantity than the other engines'. For the two");
        std::puts("deliberate controls it is still informative: a tight sd around a");
        std::puts("badly wrong mean is precisely the 'stable but wrong' signature spec");
        std::puts("10.4 asks for.");
        std::puts("");
        std::puts("rand() is the case that matters, because it is a spec 10.3 comparator");
        std::puts("rather than a control. MSVC's rand() has an output period of 2^31");
        std::puts("(~2.147e9) and this adapter spends 5 rand() calls per 64-bit word, so");
        std::puts("at N=1e7 the 25 repeats consume 2.5e9 draws in 2D and 3.75e9 in 3D --");
        std::puts("1.16x and 1.75x the ENTIRE period. Those repeats do not merely");
        std::puts("overlap, they wrap. Its N=1e7 sd is therefore not a spread over");
        std::puts("independent streams and is excluded from the stability conclusions.");
        std::puts("That exclusion is itself a 10.3 result: the language built-in cannot");
        std::puts("supply 25 independent runs at this scale. xoshiro256++'s period is");
        std::puts("2^256-1 and pcg64's is 2^128, so neither is near any limit here.");

        if (!stab_csv.empty()) {
            const bool ok = rngtools::WriteCsv(
                stab_csv, "dim,engine,n,repeats,mean,sd,predicted_sd,sd_ratio,rms_err,bias\n",
                [&](std::ostream& f) {
                    for (const auto& r : srows)
                        f << r.dim << ',' << r.engine << ',' << r.n << ',' << r.repeats << ','
                          << r.mean << ',' << r.sd << ',' << r.predicted_sd << ','
                          << r.sd_ratio << ',' << r.rms_err << ',' << r.bias << "\n";
                });
            if (!ok) return 1;
            std::printf("\nstability csv written: %s\n", stab_csv.c_str());
        }
        if (!fit_csv.empty()) {
            const bool ok = rngtools::WriteCsv(fit_csv, "dim,engine,slope,ci_lo,ci_hi\n",
                                               [&](std::ostream& f) {
                                                   for (const auto& r : sfits)
                                                       if (r.valid)
                                                           f << r.dim << ',' << r.engine << ','
                                                             << r.slope << ',' << r.ci_lo << ','
                                                             << r.ci_hi << "\n";
                                               });
            if (!ok) return 1;
            std::printf("fit csv written: %s\n", fit_csv.c_str());
        }
        return 0;
    }

    std::vector<Row> rows;
    RunEngine2D<rngsdk::Xoshiro256pp>("xoshiro256++", rows, max_exp);
    RunEngine2D<rngsdk::Pcg64>("pcg64", rows, max_exp);
    RunEngine2D<rngsdk::crypto::HmacDrbgEngine>("hmac-drbg", rows, max_exp);
    RunEngine2D<rngtools::Mt19937_64Adapter>("mt19937_64", rows, max_exp);
    RunEngine2D<rngtools::RandBuiltin>("rand()-builtin", rows, max_exp);
    RunEngine2D<RanduBad>("RANDU(bad)", rows, max_exp);
    RunEngine2D<SmallMultiplierLcg>("LCG5(bad)", rows, max_exp);

    std::printf("2D (quarter disc, pi = 4*A):\n");
    PrintTable(rows);

    std::vector<Row> rows3;
    RunEngine3D<rngsdk::Xoshiro256pp>("xoshiro256++", rows3, max_exp);
    RunEngine3D<rngsdk::Pcg64>("pcg64", rows3, max_exp);
    RunEngine3D<rngsdk::crypto::HmacDrbgEngine>("hmac-drbg", rows3, max_exp);
    RunEngine3D<rngtools::Mt19937_64Adapter>("mt19937_64", rows3, max_exp);
    RunEngine3D<rngtools::RandBuiltin>("rand()-builtin", rows3, max_exp);
    RunEngine3D<RanduBad>("RANDU(bad)", rows3, max_exp);
    RunEngine3D<SmallMultiplierLcg>("LCG5(bad)", rows3, max_exp);

    std::printf("\n3D (sphere octant, pi = 6*V): consecutive-triple correlations show here\n");
    PrintTable(rows3);

    std::printf("\nSerial 3D box test (16^3 cells, chi2/df; ~1.0 = uniform):\n");
    SerialBoxTest<rngsdk::Xoshiro256pp>("xoshiro256++");
    SerialBoxTest<rngsdk::Pcg64>("pcg64");
    SerialBoxTest<rngsdk::crypto::HmacDrbgEngine>("hmac-drbg");
    SerialBoxTest<rngtools::Mt19937_64Adapter>("mt19937_64");
    SerialBoxTest<rngtools::RandBuiltin>("rand()-builtin");
    SerialBoxTest<RanduBad>("RANDU(bad)");
    SerialBoxTest<SmallMultiplierLcg>("LCG5(bad)");

    std::puts("\nReading the results: for a sound RNG, abs_err ~ O(1/sqrt(N)) (last");
    std::puts("column O(1), errors inside the 95% CI ~95% of the time).");
    std::puts("");
    std::puts("The two bad controls fail DIFFERENTLY, which is the point of having");
    std::puts("both (spec 10.4).");
    std::puts("");
    std::puts("RANDU largely PASSES the smooth pi integrals - low-dimensional volume");
    std::puts("estimates are forgiving - and only the serial box test exposes its");
    std::puts("planar structure, with chi2/df growing 10 -> 93 in N. Its 3D err*sqrtN");
    std::puts("does drift upward (0.96 -> 3.62 -> 2.30 -> 6.68), but no single row of");
    std::puts("the pi table would convict it.");
    std::puts("");
    std::puts("LCG5 fails the pi ESTIMATE ITSELF, and that is what makes the spec's");
    std::puts("point without needing a separate diagnostic. Its consecutive PAIRS lie");
    std::puts("on five lines, so the 2D estimator sees the defect directly: abs_err is");
    std::puts("a FLOOR, not noise - 7.3e-2 at N=1e4 and still 5.3e-2 at N=1e7, while a");
    std::puts("sound engine falls ~31.6x over those three decades. err*sqrtN therefore");
    std::puts("grows without bound (7.3 -> 168.7), the signature of a fixed error");
    std::puts("against a shrinking CI.");
    std::puts("");
    std::puts("The 3D row states it most sharply: LCG5's estimate CONVERGES - to");
    std::puts("3.2644, not to pi. By N=1e7 its 95% CI is +/-1.85e-3 while it sits");
    std::puts("0.123 away from the true value, i.e. ~66 CI half-widths off. More");
    std::puts("samples buy precision around the WRONG answer. That is bias, and no");
    std::puts("amount of sampling removes it.");
    std::puts("");
    std::puts("Moral: passing one Monte Carlo task is weak evidence (RANDU nearly");
    std::puts("does); targeted batteries (TestU01/PractRand) are mandatory.");

    if (!csv_path.empty()) {
        const bool ok = rngtools::WriteCsv(
            csv_path, "dim,engine,n,estimate,abs_err,rel_err,ci95,err_sqrt_n\n",
            [&](std::ostream& f) {
                for (const auto& r : rows)
                    f << "2," << r.engine << ',' << r.n << ',' << r.estimate << ',' << r.abs_err
                      << ',' << r.rel_err << ',' << r.ci95 << ',' << r.err_sqrt_n << "\n";
                for (const auto& r : rows3)
                    f << "3," << r.engine << ',' << r.n << ',' << r.estimate << ',' << r.abs_err
                      << ',' << r.rel_err << ',' << r.ci95 << ',' << r.err_sqrt_n << "\n";
            });
        if (!ok) return 1;
        std::printf("csv written: %s\n", csv_path.c_str());
    }
    return 0;
}
