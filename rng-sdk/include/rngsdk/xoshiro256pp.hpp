// rngsdk/xoshiro256pp.hpp — xoshiro256++ 1.0 (Blackman & Vigna, 2019).
//
// Faithful C++17 port of the canonical reference C from
// https://prng.di.unimi.it/xoshiro256plusplus.c (public domain), verified
// in this repo against an independent transcription (see tests).
//
// Properties: period 2^256 - 1, passes BigCrush and PractRand per the
// authors; sub-ns per output. NOT cryptographically secure. Use only for the
// "Fast RNG" mode (simulations, non-fairness game logic), never for Provably
// Fair.
//
// On the strength of that warning: the state update is F2-linear, so an
// adversary who recovers the 256-bit state gets every past and future output
// in closed form. Four consecutive outputs carry 256 bits — exactly the state
// size — so the state is information-theoretically determined by them.
// Note the widely repeated "recoverable from 4 outputs" figure is exact for
// xoshiro256**, whose output rotl(s1*5,7)*9 is a bijection (odd multipliers
// and rotation all invert mod 2^64), so ONE output yields s1 outright. Our
// ++ scrambler, rotl(s0+s3,23)+s0, is one 64-bit equation in two unknowns and
// is NOT invertible from a single output, so recovery means solving a system
// mixing mod-2^64 addition with the F2-linear update rather than a plain
// linear solve. This project has not verified a concrete attack cost for ++,
// and none is claimed here — treat the generator as offering ZERO
// cryptographic security, which is the authors' own position.
//
// Jump()/LongJump() advance the state by 2^128 / 2^192 steps, so streams
// taken from successive jumps do not overlap until that many outputs have
// been drawn — the correct multithreading story for the fast engine (one
// jumped copy per thread).
//
// That non-overlap is a property of the published jump polynomials (Blackman
// & Vigna) AND of this port being faithful. The port is checked against an
// independent Python transcription of the reference C — kXoshiroSeed7Jump /
// kXoshiroSeed7LongJump in TestXoshiro. Before those vectors existed the
// header asserted "guaranteed non-overlap" while the only test compared a
// single post-jump word for inequality, which a wholly incorrect jump would
// also have passed, and LongJump had no coverage at all.
//
// License: MIT (this port); algorithm public domain.
#pragma once
#include <array>
#include <cstdint>

#include "detail/uint128.hpp"
#include "splitmix64.hpp"

namespace rngsdk {

class Xoshiro256pp {
public:
    using result_type = std::uint64_t;

    explicit Xoshiro256pp(std::uint64_t seed = 0xDEFA017DEFA017ULL) { Seed(seed); }

    // 64-bit seed, expanded through SplitMix64 per the authors' guidance.
    void Seed(std::uint64_t seed) {
        SplitMix64 sm(seed);
        for (auto& w : s_) w = sm.Next();
    }

    // Full 256-bit state seeding (must not be all zero).
    void SeedState(const std::array<std::uint64_t, 4>& state) {
        s_ = state;
        if ((s_[0] | s_[1] | s_[2] | s_[3]) == 0) s_[0] = 1;  // all-zero is the one forbidden state
    }

    std::uint64_t Next() {
        const std::uint64_t result = detail::rotl64(s_[0] + s_[3], 23) + s_[0];
        const std::uint64_t t = s_[1] << 17;
        s_[2] ^= s_[0];
        s_[3] ^= s_[1];
        s_[1] ^= s_[2];
        s_[0] ^= s_[3];
        s_[2] ^= t;
        s_[3] = detail::rotl64(s_[3], 45);
        return result;
    }

    void Jump()     { DoJump({0x180ec6d33cfd0abaULL, 0xd5a61266f0c9392cULL, 0xa9582618e03fc9aaULL, 0x39abdc4529b1661cULL}); }
    void LongJump() { DoJump({0x76e15d3efefdcbbfULL, 0xc5004e441c522fb3ULL, 0x77710069854ee241ULL, 0x39109bb02acbe635ULL}); }

    // C++ UniformRandomBitGenerator interface (std::shuffle etc.)
    std::uint64_t operator()() { return Next(); }
    static constexpr std::uint64_t min() { return 0; }
    static constexpr std::uint64_t max() { return ~0ULL; }

    const std::array<std::uint64_t, 4>& State() const { return s_; }

private:
    void DoJump(const std::array<std::uint64_t, 4>& table) {
        std::uint64_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;
        for (std::uint64_t word : table)
            for (int b = 0; b < 64; ++b) {
                if (word & (1ULL << b)) { r0 ^= s_[0]; r1 ^= s_[1]; r2 ^= s_[2]; r3 ^= s_[3]; }
                Next();
            }
        s_ = {r0, r1, r2, r3};
    }

    std::array<std::uint64_t, 4> s_{};
};

} // namespace rngsdk
