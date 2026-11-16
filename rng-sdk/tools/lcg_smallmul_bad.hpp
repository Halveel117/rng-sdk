// lcg_smallmul_bad.hpp: a deliberately broken generator with a coarse defect,
// the second of the two controls behind spec task #4.
//
//     x <- (5x + 1) mod 2^31
//
// A small multiplier was a real early-LCG mistake, not an invented strawman.
// With a = 5, successive pairs (x_n, x_n+1) lie on just five lines in the unit
// square: x_n+1 = 5x_n + 1 - k*2^31, and 5x+1 spans [1, 5*2^31), so k is one of
// {0,...,4}. Full period for any seed by Hull-Dobell (1962); see Seed().
//
// Each output is marginally uniform, so a test reading one value at a time
// cannot see the defect. TestSmallMultiplierLcgPairSkew checks both halves:
// marginal uniformity holds (to a 0.01 tolerance, so it excludes bias above
// ~1%, not to binomial precision), while the PAIR conditioned on u1 < 0.5 is
// skewed 60/40.
//
// Why there are two controls. RANDU and this generator both fail the ODE
// task, at error floors of ~4e-4 and ~7e-2 respectively. A Monte Carlo
// experiment resolves an error floor of size e only once sigma/sqrt(N) falls
// below e, so LCG5 is caught at N=1e4 while RANDU needs N~1e6-1e7. Reporting
// that sensitivity threshold is more defensible than reporting a pass/fail
// verdict, and it takes two controls at different scales to exhibit one.
//
// The mechanism here is direct and measured (TestSmallMultiplierLcgPairSkew):
// conditioned on a walk surviving its roulette draw (u1 < q), the next uniform
// is u2 = frac(5*u1 + 2^-31), which at q = 0.5 puts 60% of its mass below 0.5
// instead of 50%, since three of the five lattice lines land there. Every
// jump target is biased small in the same direction, so averaging more walks
// cannot remove it. RANDU's defect is a different shape, a relation over
// consecutive triples; docs/ODE_MONTE_CARLO.md 7.1 measures both.
//
// Deliberately NOT in include/rngsdk/, for the same reason as randu_bad.hpp:
// a knowingly broken generator must not be reachable from a shipped header.
//
// License: MIT.
#pragma once
#include <cstdint>

namespace rngtools {

class SmallMultiplierLcg {
public:
    using result_type = std::uint64_t;

    explicit SmallMultiplierLcg(std::uint64_t seed = 1) { Seed(seed); }

    // Every residue mod 2^31 is a valid state: the recurrence is affine and
    // has full period for any seed by Hull-Dobell (gcd(c,m) = 1 and 4 | a-1),
    // unlike RANDU, which is multiplicative and needs an odd state.
    //
    // Full period means a SINGLE orbit, so distinct seeds are distinct
    // starting offsets on one shared cycle, not distinct sequences. Runs
    // seeded differently can overlap, and over long runs they do. Acceptable
    // for a generator that exists to fail; disqualifying for a real engine.
    void Seed(std::uint64_t seed) { state_ = seed % 0x80000000ull; }

    std::uint32_t NextRaw31() {
        state_ = (5ull * state_ + 1ull) % 0x80000000ull;
        return static_cast<std::uint32_t>(state_);
    }

    // Top-aligned exactly as RanduBad packs, so Random<>::NextDouble() returns
    // x_k/2^31 and consecutive doubles are consecutive LCG outputs, which is
    // what preserves the pair lattice the demonstration depends on. Packing
    // into the LOW bits would leave NextDouble reading the top 53 bits of a
    // mostly-zero word: the lattice survives, scaled into a range the walk
    // never resolves.
    std::uint64_t Next() { return static_cast<std::uint64_t>(NextRaw31()) << 33; }

    static constexpr std::uint64_t min() { return 0; }
    static constexpr std::uint64_t max() { return ~0ULL; }
    std::uint64_t operator()() { return Next(); }

private:
    std::uint64_t state_ = 1;
};

} // namespace rngtools
