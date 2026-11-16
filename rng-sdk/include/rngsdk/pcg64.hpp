// rngsdk/pcg64.hpp — PCG64 (PCG XSL-RR 128/64, "setseq" variant; O'Neill 2014).
//
// This is the same variant NumPy ships as its default BitGenerator, which is
// exactly why we chose it: our implementation is cross-validated word-for-word
// against numpy.random.PCG64 by injecting identical (state, inc) — see tests.
//
// Structure: 128-bit LCG state advanced by
//     state = state * PCG_MULT + inc          (mod 2^128)
// with output permutation XSL-RR: rotr64(hi ^ lo, hi >> 58).
// The 128-bit arithmetic goes through detail::u128 so MSVC (no __int128)
// builds identically. Period 2^128 per stream; 2^127 selectable streams.
// NOT cryptographically secure — fast-mode only.
//
// License: MIT (this implementation); PCG algorithm Apache-2.0/MIT dual.
#pragma once
#include <cstdint>

#include "detail/uint128.hpp"
#include "splitmix64.hpp"

namespace rngsdk {

class Pcg64 {
public:
    using result_type = std::uint64_t;

    explicit Pcg64(std::uint64_t seed = 0xDEFA017DEFA017ULL) { Seed(seed); }

    // Convenience 64-bit seed: expand to 256 bits via SplitMix64
    // (128 for initstate, 128 for the stream selector).
    void Seed(std::uint64_t seed) {
        SplitMix64 sm(seed);
        detail::u128 initstate{sm.Next(), sm.Next()};
        detail::u128 initseq{sm.Next(), sm.Next()};
        SeedState(initstate, initseq);
    }

    // Reference pcg_setseq_128_srandom_r seeding discipline.
    void SeedState(detail::u128 initstate, detail::u128 initseq) {
        state_ = {0, 0};
        inc_ = detail::shl1_or1(initseq);   // stream selector must be odd
        Step();
        state_ = detail::add128(state_, initstate);
        Step();
    }

    std::uint64_t Next() {
        Step();  // 128/64 variants output from the *post-step* state (matches reference & NumPy)
        const unsigned rot = static_cast<unsigned>(state_.hi >> 58);
        return detail::rotr64(state_.hi ^ state_.lo, rot);
    }

    std::uint64_t operator()() { return Next(); }
    static constexpr std::uint64_t min() { return 0; }
    static constexpr std::uint64_t max() { return ~0ULL; }

    detail::u128 State() const { return state_; }
    detail::u128 Inc() const { return inc_; }

private:
    void Step() {
        // PCG 128-bit default multiplier 0x2360ed051fc65da44385df649fccf645
        constexpr detail::u128 kMult{0x2360ed051fc65da4ULL, 0x4385df649fccf645ULL};
        state_ = detail::add128(detail::mul128(state_, kMult), inc_);
    }

    detail::u128 state_{};
    detail::u128 inc_{};
};

} // namespace rngsdk
