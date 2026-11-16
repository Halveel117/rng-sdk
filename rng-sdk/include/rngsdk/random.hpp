// rngsdk/random.hpp — the unified mapping layer: Random<Engine>.
//
// This is where the spec's "distribution uniformity" requirements live, and
// every choice here is about *provable* absence of bias:
//
//  * NextDouble(): (Next() >> 11) * 2^-53. Takes exactly the top 53 bits —
//    the full significand of an IEEE-754 double — so the result is uniform
//    on the 2^53-point grid {k * 2^-53} in [0,1). A naive x/2^64 division
//    would round through values with unequal preimage counts. Top bits (not
//    bottom) also protects against engines with weaker low bits.
//  * NextFloat(): same construction with 24 bits (single-precision significand).
//  * NextUInt64(bound) / NextUInt32(bound): Lemire's "nearly divisionless"
//    multiply-shift with rejection (Lemire 2018, arXiv:1805.10941) — the
//    algorithm adopted by libstdc++, MSVC STL, Go, Swift, Julia, and the
//    Linux kernel. Widening multiply m = x*N splits [0,2^64) into N lanes;
//    rejecting m.lo < (2^64 mod N) trims every lane to identical width
//    floor(2^64/N), which *eliminates* modulo bias exactly (proof in
//    docs/DESIGN_NOTES.md). The expensive % only executes on the rare
//    rejection path.
//  * NextUInt32(): top 32 bits of a 64-bit word, for the same
//    weak-low-bits reason.
//
// Works over any engine exposing Next() -> uint64_t (both SDK modes and any
// future engine). Also satisfies UniformRandomBitGenerator.
//
// License: MIT.
#pragma once
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>
#include <vector>

#include "detail/uint128.hpp"

namespace rngsdk {

template <class Engine>
class Random {
public:
    using result_type = std::uint64_t;

    Random() = default;
    explicit Random(Engine engine) : engine_(std::move(engine)) {}
    // Forwarding ctor, SFINAE-guarded so it can't outbid the copy constructor
    // for a non-const lvalue (Args deduces to Random&, which beats const
    // Random& — the classic perfect-forwarding trap; without this,
    // `CryptoRandom b(a);` fails to compile deep inside the member init).
    template <class... Args,
              class = std::enable_if_t<
                  !(sizeof...(Args) == 1 &&
                    (std::is_same_v<std::decay_t<Args>, Random> && ...))>>
    explicit Random(Args&&... args) : engine_(std::forward<Args>(args)...) {}

    void Seed(std::uint64_t seed) { engine_.Seed(seed); }

    // ---- raw words -------------------------------------------------------
    std::uint64_t NextUInt64() { return engine_.Next(); }
    std::uint32_t NextUInt32() { return static_cast<std::uint32_t>(engine_.Next() >> 32); }

    // ---- floating point --------------------------------------------------
    // Uniform on {k * 2^-53 : 0 <= k < 2^53} ⊂ [0, 1). Every value has
    // exactly 2^11 preimages among 64-bit words -> exactly uniform.
    double NextDouble() {
        return static_cast<double>(engine_.Next() >> 11) * 0x1.0p-53;
    }
    // Uniform on {k * 2^-24 : 0 <= k < 2^24} ⊂ [0, 1).
    float NextFloat() {
        return static_cast<float>(engine_.Next() >> 40) * 0x1.0p-24f;
    }

    // ---- unbiased bounded integers in [0, bound) -------------------------
    std::uint64_t NextUInt64(std::uint64_t bound) {
        if (bound == 0) return 0;   // degenerate; document as caller error
        std::uint64_t x = engine_.Next();
        detail::u128 m = detail::mul64x64(x, bound);
        if (m.lo < bound) {                                  // possible bias zone
            const std::uint64_t t = (0 - bound) % bound;     // = 2^64 mod bound
            while (m.lo < t) {
                x = engine_.Next();
                m = detail::mul64x64(x, bound);
            }
        }
        return m.hi;
    }

    std::uint32_t NextUInt32(std::uint32_t bound) {
        if (bound == 0) return 0;
        std::uint64_t x = engine_.Next() >> 32;
        std::uint64_t m = x * bound;                         // 32x32 fits in 64
        if (static_cast<std::uint32_t>(m) < bound) {
            const std::uint32_t t = (0u - bound) % bound;    // = 2^32 mod bound
            while (static_cast<std::uint32_t>(m) < t) {
                x = engine_.Next() >> 32;
                m = x * bound;
            }
        }
        return static_cast<std::uint32_t>(m >> 32);
    }

    // Inclusive integer range [lo, hi].
    std::int64_t NextInt(std::int64_t lo, std::int64_t hi) {
        const std::uint64_t span = static_cast<std::uint64_t>(hi) - static_cast<std::uint64_t>(lo) + 1;
        if (span == 0)   // full 64-bit range requested
            return static_cast<std::int64_t>(engine_.Next());
        return static_cast<std::int64_t>(static_cast<std::uint64_t>(lo) + NextUInt64(span));
    }

    // ---- bytes -----------------------------------------------------------
    void NextBytes(std::uint8_t* out, std::size_t n) {
        while (n >= 8) {
            const std::uint64_t x = engine_.Next();
            std::memcpy(out, &x, 8);
            out += 8;
            n -= 8;
        }
        if (n > 0) {
            const std::uint64_t x = engine_.Next();
            std::memcpy(out, &x, n);
        }
    }

    // The spec's NextBytes(n). Delegates, so there is only ever one copy of
    // the chunking above to go wrong.
    std::vector<std::uint8_t> NextBytes(std::size_t n) {
        std::vector<std::uint8_t> out(n);
        NextBytes(out.data(), n);
        return out;
    }

    // ---- URBG interface ---------------------------------------------------
    std::uint64_t operator()() { return engine_.Next(); }
    static constexpr std::uint64_t min() { return 0; }
    static constexpr std::uint64_t max() { return ~0ULL; }

    Engine& Inner() { return engine_; }
    const Engine& Inner() const { return engine_; }

private:
    Engine engine_{};
};

} // namespace rngsdk
