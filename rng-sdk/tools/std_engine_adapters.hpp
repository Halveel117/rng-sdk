// std_engine_adapters.hpp: wraps two C++ standard-library generators to fit
// the rngsdk::Random<Engine> shape (Seed(uint64_t), Next() -> uint64_t), so
// they run through the same rng_pi/rng_ode driver code as xoshiro256++,
// PCG64, and the DRBG engines.
//
// Exists for spec 10.3, which names five comparators: the proprietary RNG,
// Mersenne Twister, PCG64, xoshiro256++, and the language built-in. The first
// three were already covered; these two close the gap.
//
// License: MIT.
#pragma once
#include <cstdint>
#include <cstdlib>
#include <random>

namespace rngtools {

// std::mt19937_64 IS Mersenne Twister, the spec's own second bullet, so
// this is the direct comparison point, distinct from RandBuiltin below.
class Mt19937_64Adapter {
public:
    using result_type = std::uint64_t;
    explicit Mt19937_64Adapter(std::uint64_t seed = 5489ULL) { Seed(seed); }
    void Seed(std::uint64_t seed) { engine_.seed(seed); }
    std::uint64_t Next() { return engine_(); }
    static constexpr std::uint64_t min() { return std::mt19937_64::min(); }
    static constexpr std::uint64_t max() { return std::mt19937_64::max(); }
    std::uint64_t operator()() { return Next(); }

private:
    std::mt19937_64 engine_;
};

// The actual C-library "language built-in": rand()/srand(), distinct from
// std::mt19937_64 above (that is a STANDARD LIBRARY algorithm the spec lists
// separately, not "the language").
//
// rand()/srand() hold C PROCESS-GLOBAL state. Constructing two instances of
// this adapter does not give two independent streams, it reseeds and reads
// the same global generator. That is an honest fact about what "the language
// built-in" means in C++, not a bug in this wrapper, and it is why this
// adapter must never be used from more than one thread or with overlapping
// lifetimes. Both rng_ode and rng_pi run engines strictly sequentially, so
// this holds for both, but it would NOT hold under the multithreading of
// item #9, and this adapter should not be reused there.
class RandBuiltin {
public:
    using result_type = std::uint64_t;
    explicit RandBuiltin(std::uint64_t seed = 1) { Seed(seed); }
    void Seed(std::uint64_t seed) { std::srand(static_cast<unsigned>(seed)); }

    // Assembles 64 bits from five draws rescaled through RAND_MAX, rather
    // than by slicing an assumed bit width out of each call. That avoids two
    // traps, both of which this file hit:
    //
    //   * Assuming 16 bits per call fixes the top bit of every slice to 0 on
    //     MSVC's 15-bit rand(). NextDouble() reads the top bits first, so
    //     u01() < 0.5 unconditionally, which hangs OdeWalkScore's roulette
    //     check at q=0.5 forever rather than merely biasing it. Found by
    //     rng_ode hanging; TestRandBuiltinSpansAboveHalf now pins it.
    //   * Taking the low bits instead is safe on MSVC and glibc but not
    //     guaranteed: a plain (ax+c) mod 2^31 generator has low bits of far
    //     shorter period, which would quietly make this comparator
    //     meaningless while still passing a variance-only test.
    //
    // Multiply-and-divide against the platform's actual RAND_MAX is agnostic
    // to which bits are weak: it uses rand()'s full stated range, not an
    // assumed width or position.
    std::uint64_t Next() {
        constexpr std::uint64_t kBits = 13;
        constexpr std::uint64_t kRange = std::uint64_t{1} << kBits;
        std::uint64_t v = 0;
        for (int i = 0; i < 5; ++i) {
            const std::uint64_t r = static_cast<std::uint64_t>(std::rand()) * kRange /
                                     (static_cast<std::uint64_t>(RAND_MAX) + 1);
            v = (v << kBits) | (r & (kRange - 1));   // mask only guards the r==kRange edge
        }
        return v;
    }

    static constexpr std::uint64_t min() { return 0; }
    static constexpr std::uint64_t max() { return ~0ULL; }
    std::uint64_t operator()() { return Next(); }
};

} // namespace rngtools
