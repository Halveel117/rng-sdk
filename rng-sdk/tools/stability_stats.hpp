// stability_stats.hpp — the statistics behind spec 10.3's "stability of
// results" and 10.1's "agreement with the theoretical convergence rate".
//
// Both need something neither rng_pi nor rng_ode had until 2026-08-25: more
// than one run per cell. Every committed cell in pi_results.csv and
// ode_results.csv is a SINGLE run at one seed, which measures error but says
// nothing about spread, and a convergence exponent fitted through single noisy
// runs would be false precision (OPEN_RESEARCH #7c(c),(d)).
//
// Shared by rng_pi and rng_ode so the two tools compute stability identically,
// and unit-tested against hand-computed values in tests/test_main.cpp.
//
// License: MIT.
#pragma once
#include <cmath>
#include <cstdint>
#include <vector>

namespace rngtools {

// ---------------------------------------------------------------- seeds ----

// Seed for one repeat of one N. Must be injective over (repeat, exponent) or
// two "independent" repeats silently become the same sequence -- the exact bug
// RanduBad::Seed had before 2026-08-18. The stride dwarfs the exponent range
// (4..8), so distinct (repeat, exponent) give distinct seeds; the +1 on repeat
// keeps repeat 0 clear of the baseline single-run seed base+exponent, so a
// stability run never re-runs the already-committed trial.
inline std::uint64_t RepeatSeed(std::uint64_t base, int repeat, int exponent) {
    return base + 1000003ULL * static_cast<std::uint64_t>(repeat + 1) +
           static_cast<std::uint64_t>(exponent);
}

// Repeat cap enforced by both drivers. It exists so the span RepeatSeed can
// occupy is BOUNDED and grid slots can be separated by a provably larger
// stride; without a cap, "how far apart must two bases be" has no answer.
inline constexpr int kMaxRepeats = 10000;

// Strictly greater than any offset RepeatSeed adds for repeat < kMaxRepeats
// and exponent <= 8 (max offset = 1000003*kMaxRepeats + 8).
inline constexpr std::uint64_t kRepeatSeedSpan =
    1000003ULL * static_cast<std::uint64_t>(kMaxRepeats + 1) + 8ULL;

// Seed base for one "slot" of an experiment that repeats the SAME estimator at
// several settings -- rng_ode's two grid points, x = pi/4 and x = pi/2.
//
// This is not cosmetic. Until 2026-08-27 rng_ode seeded both grid points with
// RepeatSeed(base, r, e), which has no x term, and the walk's roulette test
// (u01() >= q) is x-independent too: the two points therefore consumed a
// BIT-IDENTICAL uniform stream and differed only in deterministic scoring.
// Measured correlation of bias/predicted_sd between them was 1.00, and bias
// sign agreed in 26 of 28 cells. The second point corroborated nothing.
//
// Slot 0 keeps the caller's base unchanged, so it stays comparable with any
// earlier single-slot run; higher slots step by more than the whole
// RepeatSeed span, so no two (slot, repeat, exponent) triples can collide.
inline std::uint64_t GridSlotBase(std::uint64_t base, int slot) {
    return base + kRepeatSeedSpan * static_cast<std::uint64_t>(slot);
}

// ------------------------------------------------------------ pi params ----

// The pi experiment's per-dimension constants, lifted out of rng_pi's driver
// so they can be unit-tested. The indicator is Bernoulli(p) with p = pi/4 in
// 2D and pi/6 in 3D, and the estimator is prefactor*p_hat; mismatching the
// pair silently rescales every sd_ratio while the table still looks
// calibrated (forcing the 2D values into the 3D branch inflates 3D sd_ratio
// by ~1.216x -- a mutation that survived the suite while these were bare
// literals inside a function template).
struct PiParams {
    double p;                // Bernoulli success probability
    double prefactor;        // pi = prefactor * p
    std::uint64_t base;      // seed base; distinct per dimension
};

inline PiParams PiStabilityParams(int dim) {
    const double kPi = 3.14159265358979323846;
    if (dim == 2) return {kPi / 4.0, 4.0, 20260702ULL};
    return {kPi / 6.0, 6.0, 777ULL};
}

// ------------------------------------------------------------ aggregate ----

struct StabilityStats {
    int repeats = 0;
    double mean = 0.0;      // mean of the repeat estimates
    double sd = 0.0;        // sample SD of the estimates (Bessel-corrected) -- THE stability metric
    double rms_err = 0.0;   // sqrt(mean((est - exact)^2)) -- total error
    double bias = 0.0;      // mean(est) - exact  (signed)
};

// rms_err^2 = bias^2 + sd^2*(R-1)/R, so reporting all three separates a
// generator that scatters around the right answer from one that clusters
// tightly around the wrong one. That decomposition is the whole point of
// repeats and is what spec 10.4 asks to be demonstrated.
inline StabilityStats Aggregate(const std::vector<double>& estimates, double exact) {
    StabilityStats s;
    s.repeats = static_cast<int>(estimates.size());
    if (s.repeats == 0) return s;

    double sum = 0.0;
    for (double v : estimates) sum += v;
    s.mean = sum / s.repeats;
    s.bias = s.mean - exact;

    double sse = 0.0, sq_err = 0.0;
    for (double v : estimates) {
        const double d = v - s.mean;
        sse += d * d;
        const double e = v - exact;
        sq_err += e * e;
    }
    s.sd = s.repeats > 1 ? std::sqrt(sse / (s.repeats - 1)) : 0.0;
    s.rms_err = std::sqrt(sq_err / s.repeats);
    return s;
}

// ------------------------------------------------------------ slope fit ----

struct SlopeFit {
    bool valid = false;
    int df = 0;
    double slope = 0.0, ci_lo = 0.0, ci_hi = 0.0;
};

// Two-sided 95% t critical values, df 1..10; 1.96 beyond. Small table rather
// than a dependency: the fits here have df = 2 (four N values), where using
// the normal 1.96 instead of 4.303 would understate the interval by >2x.
inline double TCritical95(int df) {
    static const double kT[] = {12.706, 4.303, 3.182, 2.776, 2.571,
                                2.447,  2.365, 2.306, 2.262, 2.228};
    if (df < 1) return 0.0;
    if (df <= 10) return kT[df - 1];
    return 1.959964;
}

// OLS of log10(y) on log10(x). For error-vs-N the expected slope is -1/2;
// a generator with an error FLOOR flattens toward 0 instead, which is how
// this distinguishes "converging" from "converged to the wrong answer".
inline SlopeFit FitLogLogSlope(const std::vector<double>& xs,
                               const std::vector<double>& ys) {
    SlopeFit f;
    const int n = static_cast<int>(xs.size());
    if (n < 3 || static_cast<int>(ys.size()) != n) return f;

    std::vector<double> lx(n), ly(n);
    for (int i = 0; i < n; ++i) {
        if (!(xs[i] > 0.0) || !(ys[i] > 0.0)) return f;   // log of <=0 is undefined
        lx[i] = std::log10(xs[i]);
        ly[i] = std::log10(ys[i]);
    }

    double mx = 0.0, my = 0.0;
    for (int i = 0; i < n; ++i) { mx += lx[i]; my += ly[i]; }
    mx /= n; my /= n;

    double sxy = 0.0, sxx = 0.0;
    for (int i = 0; i < n; ++i) {
        sxy += (lx[i] - mx) * (ly[i] - my);
        sxx += (lx[i] - mx) * (lx[i] - mx);
    }
    if (!(sxx > 0.0)) return f;              // all x identical -- slope undefined

    f.slope = sxy / sxx;
    f.df = n - 2;

    double sse = 0.0;
    const double intercept = my - f.slope * mx;
    for (int i = 0; i < n; ++i) {
        const double r = ly[i] - (intercept + f.slope * lx[i]);
        sse += r * r;
    }
    // Zero residual (a perfect power law) gives a zero-width interval, which
    // is the correct answer for noiseless input rather than a degenerate case.
    const double se = std::sqrt((sse / f.df) / sxx);
    const double half = TCritical95(f.df) * se;
    f.ci_lo = f.slope - half;
    f.ci_hi = f.slope + half;
    f.valid = true;
    return f;
}

} // namespace rngtools
