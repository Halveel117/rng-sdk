// rngsdk/detail/uint128.hpp — portable 128-bit helpers.
//
// Why this exists: PCG64 needs a 128-bit LCG step and Lemire's bounded-integer
// method needs a 64x64->128 widening multiply. GCC/Clang have __int128 but
// MSVC does not, and this SDK must build with all three. We wrap the three
// cases (builtin __int128, MSVC _umul128 intrinsic, pure 32-bit-limb fallback)
// behind one tiny struct so the rest of the code is compiler-agnostic.
//
// License: MIT (see LICENSE).
#pragma once
#include <cstdint>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
#include <intrin.h>
#endif

namespace rngsdk {
namespace detail {

struct u128 {
    std::uint64_t hi = 0;
    std::uint64_t lo = 0;
};

// 64x64 -> full 128-bit product.
inline u128 mul64x64(std::uint64_t a, std::uint64_t b) {
#if defined(__SIZEOF_INT128__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    unsigned __int128 p = static_cast<unsigned __int128>(a) * b;
#pragma GCC diagnostic pop
    return { static_cast<std::uint64_t>(p >> 64), static_cast<std::uint64_t>(p) };
#elif defined(_MSC_VER) && defined(_M_X64)
    std::uint64_t hi;
    std::uint64_t lo = _umul128(a, b, &hi);
    return { hi, lo };
#elif defined(_MSC_VER) && defined(_M_ARM64)
    return { __umulh(a, b), a * b };
#else
    // Portable schoolbook multiply on 32-bit limbs.
    const std::uint64_t a_lo = a & 0xffffffffULL, a_hi = a >> 32;
    const std::uint64_t b_lo = b & 0xffffffffULL, b_hi = b >> 32;
    const std::uint64_t p0 = a_lo * b_lo;
    const std::uint64_t p1 = a_lo * b_hi;
    const std::uint64_t p2 = a_hi * b_lo;
    const std::uint64_t p3 = a_hi * b_hi;
    const std::uint64_t mid = p1 + (p0 >> 32) + (p2 & 0xffffffffULL);
    u128 r;
    r.lo = (mid << 32) | (p0 & 0xffffffffULL);
    r.hi = p3 + (p2 >> 32) + (mid >> 32);
    return r;
#endif
}

inline u128 add128(u128 a, u128 b) {
    u128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1 : 0);
    return r;
}

// Low 128 bits of a*b (exactly what a 128-bit LCG step needs).
inline u128 mul128(u128 a, u128 b) {
    u128 r = mul64x64(a.lo, b.lo);
    r.hi += a.hi * b.lo + a.lo * b.hi;   // cross terms, mod 2^64
    return r;
}

inline u128 shl1_or1(u128 a) {          // (a << 1) | 1  — PCG stream setup
    u128 r;
    r.hi = (a.hi << 1) | (a.lo >> 63);
    r.lo = (a.lo << 1) | 1;
    return r;
}

inline std::uint64_t rotr64(std::uint64_t x, unsigned k) {
    return (x >> (k & 63)) | (x << ((64 - k) & 63));
}

inline std::uint64_t rotl64(std::uint64_t x, unsigned k) {
     return (x << (k & 63)) | (x >> ((64 - k) & 63));
}

} // namespace detail
} // namespace rngsdk
