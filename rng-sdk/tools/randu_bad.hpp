// randu_bad.hpp: RANDU, the deliberately broken generator.
//
// IBM's infamous 1968 LCG: x <- 65539*x mod 2^31. Its consecutive triples lie
// on just 15 planes in 3-space, which makes it the standard illustration of a
// generator that passes easy tests and fails targeted ones.
//
// Period: 65539 ≡ 3 (mod 8), so 3 is not a primitive root mod 2^31 and the
// odd residues split into cycles of length 2^29, not 2^31. That matters for
// rng_ode, whose N=10^7 row consumes a noticeable fraction of one cycle,
// recorded so a reader can rule period exhaustion in or out. It is not the
// mechanism behind rng_ode's finding: tools/ode_monte_carlo.cpp's
// DepthDecomposition diagnostic isolates the bias to depth-3 walk terms
// specifically (three consecutive draws), matching the triple relation two
// lines up, not to exhaustion of the state space. See
// docs/ODE_MONTE_CARLO.md §7.1.
//
// Two tools use it for that contrast:
//   * rng_pi:     the spec's correlation study. RANDU largely PASSES the
//                smooth volume integrals and fails the serial 3D box test.
//   * rng_stream: the negative control for the external batteries. If RANDU
//                passes them, the harness cannot detect failure and every
//                other result in the report is void.
//
// Deliberately NOT in include/rngsdk/: a knowingly broken generator must not
// be reachable from the shipped SDK headers.
//
// License: MIT.
#pragma once
#include <cstdint>

namespace rngtools {

class RanduBad {
public:
    using result_type = std::uint64_t;

    explicit RanduBad(std::uint64_t seed = 1) { Seed(seed); }

    // RANDU is multiplicative mod 2^31, so the state must stay odd: an even
    // seed loses a factor of two each step until the sequence collapses.
    // Doubling keeps that parity requirement and is a bijection onto the 2^30
    // odd residues, so distinct seeds give distinct states. (Injectivity is
    // the point. The obvious `(seed % 0x7FFFFFFF) | 1` also keeps parity but
    // collapses each adjacent even/odd pair to one state, which silently made
    // runs intended to be independent share a sequence.)
    void Seed(std::uint64_t seed) { state_ = 2 * (seed % 0x40000000ull) + 1; }

    // One raw 31-bit RANDU output.
    std::uint32_t NextRaw31() {
        state_ = (state_ * 65539ull) % 0x80000000ull;
        return static_cast<std::uint32_t>(state_);
    }

    // Top-aligned in a 64-bit word, so Random<RanduBad>::NextDouble() returns
    // exactly x_k / 2^31 and consecutive doubles are consecutive RANDU
    // outputs, so the lattice structure survives for the π study.
    std::uint64_t Next() { return static_cast<std::uint64_t>(NextRaw31()) << 33; }

    static constexpr std::uint64_t min() { return 0; }
    static constexpr std::uint64_t max() { return ~0ULL; }
    std::uint64_t operator()() { return Next(); }

private:
    std::uint64_t state_ = 1;
};

} // namespace rngtools
