// rngsdk/splitmix64.hpp — SplitMix64 (Steele, Lea, Vigna 2014).
//
// Role in this SDK: *seed expander only*. xoshiro256++ requires 256 bits of
// state that must not be all-zero and should look "random"; feeding it four
// raw counters (0,1,2,3) puts it in a low-entropy region with slow escape.
// The xoshiro authors' own recommendation is to expand a 64-bit seed through
// SplitMix64 — every distinct 64-bit seed yields a full, well-mixed state.
//
// It is also a bijection on uint64, so distinct seeds never collide: the
// state advances by an odd constant (invertible mod 2^64), and the finalizer
// composes xor-shifts with odd multiplies, each invertible. This is relied on
// by MATH_JUSTIFICATION Prop 4.2 to show the forbidden all-zero xoshiro state
// is unreachable from Seed(). Sampling cannot prove a bijection, so
// TestSplitMix64Injective checks the falsifiable consequence instead: zero
// collisions across 200k seeds and no all-zero expansion.
//
// License: MIT. Algorithm is public domain (Vigna's reference C).
#pragma once
#include <cstdint>

namespace rngsdk {

class SplitMix64 {
public:
    explicit SplitMix64(std::uint64_t seed = 0) : state_(seed) {}

    void Seed(std::uint64_t seed) { state_ = seed; }

    std::uint64_t Next() {
        std::uint64_t z = (state_ += 0x9E3779B97F4A7C15ULL);      // golden-ratio increment
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

private:
    std::uint64_t state_;
};

} // namespace rngsdk
