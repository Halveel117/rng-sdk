// ode_solver.hpp: von Neumann–Ulam Monte Carlo for y'' + y = 0, y(0)=0,
// y'(0)=1, whose exact solution is sin(x).
//
// Full derivation in docs/design/2026-08-24-ode-monte-carlo-design.md.
// In brief: integrating the IVP twice gives the Volterra equation
//
//     y(x) = x − ∫₀ˣ (x−t) y(t) dt                                      (1)
//
// whose Neumann series Σ Kⁿf, with f(x)=x and (Kg)(x) = −∫₀ˣ(x−t)g(t)dt,
// is exactly the Taylor series of sin. We evaluate that series stochastically
// rather than analytically: a random walk from x toward 0, one term of the
// series per step.
//
// Two design choices carry the whole item:
//
//   * Importance sampling. Drawing t from p(t|x) = 2(x−t)/x² instead of
//     uniformly makes the kernel's (x−t) factor cancel exactly, so the
//     per-step weight collapses to the CONSTANT W(x) = −x²/2. Lower variance,
//     and the sampler stays closed-form.
//   * Russian roulette rather than fixed-depth truncation. This makes the
//     estimator exactly unbiased, so every observed deviation from sin(x) is
//     variance or RNG defect, nothing else. Truncating instead would add a
//     bias of our own making and destroy that attribution, which is the only
//     reason the experiment is worth running.
//
// Guarantees below are bound to tests; none is asserted only here
// (docs/COMMENT_AUDIT.md convention):
//
//   Kⁿf matches the closed form, partial sums → sin  -> TestOdeNeumannSeries
//   SampleT inverts its own CDF                      -> TestOdeSampler
//   E[walk] equals the analytic partial sums         -> TestOdeExpectationMatchesSeries
//   walk arithmetic, incl. the weight PRODUCT        -> TestOdeWalkScripted
//   sigma_hat matches a naive two-pass variance      -> TestOdeWelfordMatchesTwoPass
//   sample mean converges to sin(x)                  -> TestOdeConvergence
//
// Those six were verified by mutation testing rather than inspection:
// breaking the weight product, the 1/q compensation, W(x)'s factor of 2, or
// the Welford update each fails at least one. That sweep mattered: before
// it, the first four passed against a walk with no product structure at all.
//
// Deliberately NOT in include/rngsdk/: this is a validation instrument for
// the report, not shipped SDK surface. Same rationale as randu_bad.hpp.
//
// License: MIT.
#pragma once
#include <cmath>
#include <cstdint>
#include <stdexcept>

namespace rngtools {

// Kⁿf(x) = (−1)ⁿ x^(2n+1)/(2n+1)!, computed by the ratio between successive
// terms so no factorial ever overflows.
inline double NeumannTerm(int n, double x) {
    double term = x;
    for (int k = 1; k <= n; ++k)
        term *= -(x * x) / ((2.0 * k) * (2.0 * k + 1.0));
    return term;
}

// Σ_{k=0..n} Kᵏf(x), the depth-n truncation of (1), i.e. sin's Taylor
// polynomial of degree 2n+1. This is the analytic value the Monte Carlo
// estimator targets, and the reference Layer-1 tests check against.
inline double NeumannPartialSum(int n, double x) {
    double sum = 0.0, term = x;
    for (int k = 0; k <= n; ++k) {
        sum += term;
        const double j = 2.0 * (k + 1);
        term *= -(x * x) / (j * (j + 1.0));
    }
    return sum;
}

// Inverse CDF of p(t|x) = 2(x−t)/x² on (0,x), where F(t) = (2xt − t²)/x².
// Substituting t = x(1−√(1−u)) gives F(t) = u identically, so the round trip
// is exact in REAL arithmetic (TestOdeSampler checks it to 1e-12 in doubles,
// which is a weaker statement).
//
// The form below is that expression multiplied through by its conjugate:
// identical in exact arithmetic, but stable in floating point. The direct
// form cancels catastrophically as u → 0 and returns exactly 0 for
// u ≲ 2^-52, silently collapsing the walk to the origin.
inline double SampleT(double x, double u) {
    return x * u / (1.0 + std::sqrt(1.0 - u));
}

// W(x) = −x²/2, the per-step weight left over after p(t|x)'s (x−t) factor
// cancels the kernel's. Exposed rather than inlined into OdeWalkScore so the
// deterministic depth test (TestOdeExpectationMatchesSeries) can integrate
// over the SAME weight the walk applies, instead of a copy of it that could
// drift.
inline double WalkWeight(double x) { return -(x * x) / 2.0; }

// Shared cap: no walk in this file may run unbounded. A defective u01()
// that cannot produce a terminating draw must fail loudly rather than hang.
// RandBuiltin's original construction did exactly this, found by the tool
// hanging rather than by review (std_engine_adapters.hpp).
inline constexpr int kMaxWalkDepth = 200000;

// One random-walk realisation. E[score] = y(x) = sin(x) exactly (spec §2.4).
//
// Consumption order per step is roulette-then-position, and survival is
// u < q. Both are load-bearing for TestOdeWalkScripted's hand-computed
// values, and the order is what a lattice-structured generator would see.
//
// u01 must be a callable returning uniform doubles in [0,1). It is taken by
// forwarding reference so a stateful source (a scripted vector, an engine
// wrapper) mutates in place rather than being copied per step.
template <class UniformFn>
double OdeWalkScore(UniformFn&& u01, double x, double q) {
    double score = x;      // f(x) = x, the n=0 term
    double weight = 1.0;   // running ∏ W(xᵢ)/q
    double cur = x;
    // Capped rather than unconditional; see kMaxWalkDepth above.
    for (int steps = 0; steps < kMaxWalkDepth; ++steps) {
        if (u01() >= q) return score;            // roulette terminates the walk
        weight *= WalkWeight(cur) / q;           // the 1/q is what removes the bias
        cur = SampleT(cur, u01());
        score += weight * cur;                   // f(cur) = cur
    }
    throw std::runtime_error("OdeWalkScore: exceeded kMaxWalkDepth without "
                              "terminating -- u01() is likely defective");
}

// Unbiased Monte Carlo estimator of a SINGLE Neumann term Kᵈf(x), via d
// FORCED hops (no roulette, whose job is choosing which depth to stop
// at when summing the whole series; isolating one term needs every sample to
// go exactly d deep). No division by q appears here: q only enters through
// the roulette survival/termination trade-off in OdeWalkScore, and there is
// no roulette in this function.
//
// Exists to localize WHERE in the series an RNG defect's bias concentrates
// (docs/ODE_MONTE_CARLO.md §7.1), e.g. whether it appears at d=1 (pair
// structure) or d=2 (triple structure), since RANDU's own defining defect is
// a relation over CONSECUTIVE TRIPLES (randu_bad.hpp).
//
// depth is bounded by kMaxWalkDepth as a sanity check on the caller, not
// because this function can hang (it always runs exactly `depth` hops).
template <class UniformFn>
double ForcedWalkTerm(UniformFn&& u01, double x, int depth) {
    if (depth < 0 || depth > kMaxWalkDepth)
        throw std::invalid_argument("ForcedWalkTerm: depth out of range");
    double weight = 1.0;
    double cur = x;
    for (int i = 0; i < depth; ++i) {
        weight *= WalkWeight(cur);
        cur = SampleT(cur, u01());
    }
    return weight * cur;
}

struct OdeEstimate {
    double mean;          // estimate of y(x)
    double stddev;        // sample std-dev of a single walk score
    double stderr_mean;   // stddev/√n, the quantity every CI is built from
    std::uint64_t n;
};

// Mean of n independent walks, accumulated by Welford's algorithm rather
// than a running sum of squares. σ̂ is not a diagnostic here. It is the
// denominator of every acceptance criterion in the spec (§3), so at n = 10^7
// with heavy-tailed scores it must not be the least accurate number in the
// table. Checked by TestOdeConvergence.
// Preconditions are checked rather than assumed: n = 0 would return NaN for
// stderr_mean, and a negative x violates the derivation, which assumes the
// walk moves toward the origin on (0,x). Neither is reachable from rng_ode.
template <class UniformFn>
OdeEstimate EstimateY(UniformFn&& u01, double x, std::uint64_t n, double q) {
    if (n == 0) throw std::invalid_argument("EstimateY: n must be positive");
    if (!(x >= 0.0)) throw std::invalid_argument("EstimateY: x must be >= 0");
    if (!(q > 0.0 && q < 1.0)) throw std::invalid_argument("EstimateY: q must lie in (0,1)");
    double mean = 0.0, m2 = 0.0;
    for (std::uint64_t i = 1; i <= n; ++i) {
        const double s = OdeWalkScore(u01, x, q);
        const double d = s - mean;
        mean += d / static_cast<double>(i);
        m2 += d * (s - mean);
    }
    const double var = n > 1 ? m2 / static_cast<double>(n - 1) : 0.0;
    const double sd = std::sqrt(var);
    return {mean, sd, sd / std::sqrt(static_cast<double>(n)), n};
}

} // namespace rngtools
