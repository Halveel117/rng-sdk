// rngsdk/crypto/drbg_engine.hpp — adapts an SP 800-90A DRBG to the SDK's
// engine concept (Next() -> uint64), plus OS entropy for seeding.
//
// BufferedDrbgEngine is the one adapter both crypto engines share
// (HmacDrbgEngine here, CtrDrbgEngine in ctr_drbg_engine.hpp). They differ
// only in how a 64-bit convenience seed is expanded, which is the SeedFrom64
// parameter. The buffering lives in exactly one place on purpose: CAVP vectors
// validate the DRBG core one Generate() call at a time, so a refill defect in
// this adapter would pass every official vector. One copy means one place to
// get it right, and the fingerprint test pins its output.
//
// The adapter buffers one 4 KiB Generate() call at a time: DRBG output is a
// stream of blocks, and amortizing the per-request Update() over 4096 bytes
// costs nothing statistically (SP 800-90A allows up to 2^19 bits per request)
// while making NextUInt64 ~128x cheaper than one-Generate-per-word.
//
// Entropy: SecureEntropy() draws 48 bytes (entropy || nonce per SP 800-90A
// §8.6.7) straight from the OS CSPRNG — see os_entropy.hpp for the sourcing
// policy (consume the platform DRBG, no conditioning, no fallback, throw on
// failure). Default construction is OS-seeded; deterministic streams require
// an *explicit* seed argument, so "CryptoRandom rng;" can never silently mean
// "seed 0". (Resolves OPEN_RESEARCH #1.)
//
// License: MIT.
#pragma once
#include <cstdint>
#include <cstring>

#include "hmac_drbg.hpp"
#include "os_entropy.hpp"
#include "sha256.hpp"

namespace rngsdk {
namespace crypto {

// 48 bytes of OS entropy: 32 (256-bit strength) + 16 (nonce), SP 800-90A.
// Also exactly the CTR-DRBG no-df seedlen, so both engines take it as-is.
inline Bytes SecureEntropy() { return OsEntropy(48); }

// Drbg must provide Instantiate(entropy, nonce, personalization),
// Reseed(entropy) and Generate(out, n). Copyability follows Drbg's
// (HmacDrbg is copyable; CtrDrbg owns a cipher context and is move-only).
template <class Drbg, Bytes (*SeedFrom64)(std::uint64_t)>
class BufferedDrbgEngine {
public:
    using result_type = std::uint64_t;
    static constexpr std::size_t kBufBytes = 4096;

    // Deterministic instantiation from explicit seed bytes (reproducible
    // streams — what Seed(seed) requires of the API). CTR-DRBG requires
    // exactly 48 bytes and rejects anything else; see ctr_drbg.hpp.
    explicit BufferedDrbgEngine(const Bytes& seed_bytes, const Bytes& personalization = {}) {
        SeedBytes(seed_bytes, personalization);
    }

    // Convenience: 64-bit seed, expanded via SHA-256 with domain separation.
    // Deterministic — for tests and reproducible streams only.
    explicit BufferedDrbgEngine(std::uint64_t seed) { Seed(seed); }

    // SECURE DEFAULT: instantiate from the OS CSPRNG. Nondeterministic by
    // design; use the explicit-seed constructors for reproducible streams.
    BufferedDrbgEngine() { SeedBytes(SecureEntropy()); }

    void Seed(std::uint64_t seed) { SeedBytes(SeedFrom64(seed)); }

    void SeedBytes(const Bytes& seed_bytes, const Bytes& personalization = {}) {
        drbg_.Instantiate(seed_bytes, {}, personalization);
        pos_ = kBufBytes;   // force refill
    }

    void Reseed(const Bytes& entropy) {
        drbg_.Reseed(entropy);
        pos_ = kBufBytes;
    }

    std::uint64_t Next() {
        if (pos_ + 8 > kBufBytes) Refill();
        std::uint64_t x;
        std::memcpy(&x, buf_ + pos_, 8);
        pos_ += 8;
        return x;
    }

    std::uint64_t operator()() { return Next(); }
    static constexpr std::uint64_t min() { return 0; }
    static constexpr std::uint64_t max() { return ~0ULL; }

private:
    void Refill() {
        drbg_.Generate(buf_, kBufBytes);
        pos_ = 0;
    }

    Drbg drbg_;
    std::uint8_t buf_[kBufBytes] = {0};
    std::size_t pos_ = kBufBytes;
};

namespace detail {

// 64-bit seed -> 32 bytes: SHA-256("rngsdk-drbg-seed" || seed_le).
inline Bytes HmacSeedFrom64(std::uint64_t seed) {
    Bytes material(sizeof(seed) + 16);
    std::memcpy(material.data(), "rngsdk-drbg-seed", 16);
    std::memcpy(material.data() + 16, &seed, sizeof(seed));
    const auto h = Sha256::Hash(material);
    return Bytes(h.begin(), h.end());
}

} // namespace detail

using HmacDrbgEngine = BufferedDrbgEngine<HmacDrbg, &detail::HmacSeedFrom64>;

} // namespace crypto
} // namespace rngsdk
