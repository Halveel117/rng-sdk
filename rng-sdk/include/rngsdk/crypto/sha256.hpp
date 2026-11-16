// rngsdk/crypto/sha256.hpp — SHA-256 (FIPS 180-4), self-contained reference
// implementation.
//
// BACKEND POLICY (agreed for the prototype): the SDK talks to hashing through
// this one header. Define RNGSDK_USE_OPENSSL at build time to route
// Sha256::Hash / Hmac through OpenSSL's EVP instead; the reference code below
// is the zero-dependency default so the prototype compiles anywhere (MSVC,
// GCC, Clang) with no package manager. The reference path is validated
// against FIPS 180-4 known-answer vectors and cross-checked against Python's
// hashlib (OpenSSL-backed) in the test suite, so both backends are
// interchangeable bit-for-bit. For a production/licensed build, switch to
// OpenSSL/libsodium for side-channel-hardened, FIPS-validated primitives.
//
// License: MIT.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#if defined(RNGSDK_USE_OPENSSL)
#include <openssl/evp.h>
#endif

namespace rngsdk {
namespace crypto {

using Bytes = std::vector<std::uint8_t>;

class Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;
    static constexpr std::size_t kBlockSize = 64;

    Sha256() { Reset(); }

    void Reset() {
        h_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        buf_len_ = 0;
        total_len_ = 0;
    }

    void Update(const void* data, std::size_t len) {
        const auto* p = static_cast<const std::uint8_t*>(data);
        total_len_ += len;
        while (len > 0) {
            const std::size_t take = (kBlockSize - buf_len_ < len) ? kBlockSize - buf_len_ : len;
            std::memcpy(buf_.data() + buf_len_, p, take);
            buf_len_ += take;
            p += take;
            len -= take;
            if (buf_len_ == kBlockSize) {
                Compress(buf_.data());
                buf_len_ = 0;
            }
        }
    }

    std::array<std::uint8_t, kDigestSize> Finish() {
        const std::uint64_t bit_len = total_len_ * 8;
        // Padding: 0x80, zeros, 64-bit big-endian bit length.
        const std::uint8_t pad_start = 0x80;
        Update(&pad_start, 1);
        const std::uint8_t zero = 0;
        while (buf_len_ != 56) Update(&zero, 1);
        std::uint8_t len_be[8];
        for (int i = 0; i < 8; ++i) len_be[i] = static_cast<std::uint8_t>(bit_len >> (56 - 8 * i));
        // Bypass total_len_ bookkeeping (it's already captured in bit_len).
        std::memcpy(buf_.data() + buf_len_, len_be, 8);
        Compress(buf_.data());
        std::array<std::uint8_t, kDigestSize> out{};
        for (int i = 0; i < 8; ++i) {
            out[4 * i + 0] = static_cast<std::uint8_t>(h_[i] >> 24);
            out[4 * i + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
            out[4 * i + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
            out[4 * i + 3] = static_cast<std::uint8_t>(h_[i]);
        }
        Reset();
        return out;
    }

    // One-shot convenience.
    static std::array<std::uint8_t, kDigestSize> Hash(const void* data, std::size_t len) {
#if defined(RNGSDK_USE_OPENSSL)
        std::array<std::uint8_t, kDigestSize> out{};
        unsigned int out_len = 0;
        EVP_Digest(data, len, out.data(), &out_len, EVP_sha256(), nullptr);
        return out;
#else
        Sha256 s;
        s.Update(data, len);
        return s.Finish();
#endif
    }

    static std::array<std::uint8_t, kDigestSize> Hash(const std::string& s) {
        return Hash(s.data(), s.size());
    }
    static std::array<std::uint8_t, kDigestSize> Hash(const Bytes& b) {
        return Hash(b.data(), b.size());
    }

private:
    static std::uint32_t Rotr(std::uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }

    void Compress(const std::uint8_t* block) {
        static constexpr std::uint32_t K[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (std::uint32_t(block[4 * i]) << 24) | (std::uint32_t(block[4 * i + 1]) << 16) |
                   (std::uint32_t(block[4 * i + 2]) << 8) | std::uint32_t(block[4 * i + 3]);
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        std::uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
            const std::uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }

    std::array<std::uint32_t, 8> h_{};
    std::array<std::uint8_t, kBlockSize> buf_{};
    std::size_t buf_len_ = 0;
    std::uint64_t total_len_ = 0;
};

// Hex helpers used across the SDK (commitments, verifier output).
inline std::string ToHex(const std::uint8_t* data, std::size_t len) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0xF]);
    }
    return out;
}

template <std::size_t N>
inline std::string ToHex(const std::array<std::uint8_t, N>& a) { return ToHex(a.data(), N); }
inline std::string ToHex(const Bytes& b) { return ToHex(b.data(), b.size()); }

} // namespace crypto
} // namespace rngsdk
