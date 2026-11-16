// rngsdk/crypto/hmac_drbg.hpp — HMAC_DRBG with SHA-256 per NIST SP 800-90A
// Rev. 1, §10.1.2. This is the SDK's "Cryptographic RNG" core.
//
// Implementation follows the spec's function decomposition exactly:
//   HMAC_DRBG_Update (§10.1.2.2), Instantiate (§10.1.2.3),
//   Reseed (§10.1.2.4), Generate (§10.1.2.5)
// with SP 800-90A limits enforced: security strength 256 bits,
// reseed_interval 2^48 requests, max 2^19 bits (65536 bytes) per Generate
// call, entropy input >= 3/2 * security_strength / 8 = 48 bytes when a
// separate nonce is folded into the entropy input.
//
// Security note (why HMAC-DRBG over raw hashing): outputs are HMAC chains
// keyed by secret K; predicting the next output or recovering (K, V) from
// outputs reduces to breaking HMAC-SHA256 as a PRF. That is the property the
// Provably Fair and secret-generation use cases actually rest on, and it is
// unaffected by the caveat below.
//
// BACKTRACKING RESISTANCE — DO NOT CLAIM IT WHEN additional == {}.
// SP 800-90A asserts the NIST DRBGs are backtracking resistant. Woodage &
// Shumow (EUROCRYPT 2019, IACR ePrint 2018/349, §7.1) disprove this for
// HMAC-DRBG when additional input is omitted, and the reason is visible in
// Update() below: with provided == {} the second (0x01) pass is skipped, so
// the post-Generate state satisfies the checkable relation
//
//     V* == HMAC(K*, r*)      where r* is the LAST output block of the call.
//
// An adversary given output and then the state can simply test that relation,
// which is a forward-security distinguisher with advantage ~1 (their Thm. 3).
// It is a DISTINGUISHER, not a recovery of unseen past output — but the
// standard's claim is still false, so this header must not repeat it.
//
// Their §7.2 proves robustness (hence forward security) DOES hold when
// additional input is supplied on every Generate. Callers wanting the
// property must therefore pass a non-empty `additional`; the engine adapter
// in drbg_engine.hpp currently does not (see docs/MATH_JUSTIFICATION.md §7.2
// and OPEN_RESEARCH #12 for the reproducibility trade-off that decision
// carries).
//
// Cross-validated in the test suite against an independent Python
// implementation built on hashlib/hmac. CAVP .rsp vector validation is
// listed as an open item (docs/OPEN_RESEARCH.md).
//
// License: MIT.
#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "hmac_sha256.hpp"

namespace rngsdk {
namespace crypto {

class HmacDrbg {
public:
    static constexpr std::size_t kOutLen = Sha256::kDigestSize;          // 32
    static constexpr std::size_t kMaxBytesPerRequest = 1u << 16;          // 2^19 bits
    static constexpr std::uint64_t kReseedInterval = 1ULL << 48;
    static constexpr std::size_t kMinEntropyBytes = 32;                   // 256-bit strength
    // Spec: entropy(>=32) + nonce(>=16); we accept them combined or separate.

    HmacDrbg() = default;

    // Instantiate (SP 800-90A §10.1.2.3).
    // entropy: >= 32 bytes of real entropy (48+ recommended: entropy||nonce).
    // nonce / personalization: optional, concatenated into seed material.
    void Instantiate(const Bytes& entropy,
                     const Bytes& nonce = {},
                     const Bytes& personalization = {}) {
        if (entropy.size() < kMinEntropyBytes)
            throw std::invalid_argument("HmacDrbg: entropy input must be >= 32 bytes");
        Bytes seed_material = Concat(entropy, nonce, personalization);
        std::memset(key_, 0x00, kOutLen);   // K = 0x00...00
        std::memset(v_, 0x01, kOutLen);     // V = 0x01...01
        Update(seed_material);
        reseed_counter_ = 1;
        instantiated_ = true;
    }

    // Reseed (§10.1.2.4).
    void Reseed(const Bytes& entropy, const Bytes& additional = {}) {
        RequireInstantiated();
        if (entropy.size() < kMinEntropyBytes)
            throw std::invalid_argument("HmacDrbg: reseed entropy must be >= 32 bytes");
        Update(Concat(entropy, additional, {}));
        reseed_counter_ = 1;
    }

    // Generate (§10.1.2.5). Throws if a reseed is required — the caller must
    // decide where fresh entropy comes from; silently recycling state would
    // violate the standard.
    void Generate(std::uint8_t* out, std::size_t n, const Bytes& additional = {}) {
        RequireInstantiated();
        if (n > kMaxBytesPerRequest)
            throw std::invalid_argument("HmacDrbg: > 2^19 bits requested in one call");
        if (reseed_counter_ > kReseedInterval)
            throw std::runtime_error("HmacDrbg: reseed required (reseed_interval reached)");

        if (!additional.empty()) Update(additional);

        std::size_t produced = 0;
        while (produced < n) {
            auto t = HmacSha256(key_, kOutLen, v_, kOutLen);   // V = HMAC(K, V)
            std::memcpy(v_, t.data(), kOutLen);
            const std::size_t take = (n - produced < kOutLen) ? n - produced : kOutLen;
            std::memcpy(out + produced, v_, take);
            produced += take;
        }

        Update(additional);        // spec: update with additional input (may be empty)
        ++reseed_counter_;
    }

    Bytes Generate(std::size_t n, const Bytes& additional = {}) {
        Bytes out(n);
        Generate(out.data(), n, additional);
        return out;
    }

    std::uint64_t ReseedCounter() const { return reseed_counter_; }
    bool NeedsReseed() const { return reseed_counter_ > kReseedInterval; }

private:
    // HMAC_DRBG_Update (§10.1.2.2):
    //   K = HMAC(K, V || 0x00 || provided);  V = HMAC(K, V)
    //   if provided nonempty: K = HMAC(K, V || 0x01 || provided); V = HMAC(K, V)
    void Update(const Bytes& provided) {
        Bytes msg(kOutLen + 1 + provided.size());
        std::memcpy(msg.data(), v_, kOutLen);
        msg[kOutLen] = 0x00;
        if (!provided.empty()) std::memcpy(msg.data() + kOutLen + 1, provided.data(), provided.size());

        auto k = HmacSha256(key_, kOutLen, msg.data(), msg.size());
        std::memcpy(key_, k.data(), kOutLen);
        auto v = HmacSha256(key_, kOutLen, v_, kOutLen);
        std::memcpy(v_, v.data(), kOutLen);

        if (provided.empty()) return;

        std::memcpy(msg.data(), v_, kOutLen);
        msg[kOutLen] = 0x01;
        k = HmacSha256(key_, kOutLen, msg.data(), msg.size());
        std::memcpy(key_, k.data(), kOutLen);
        v = HmacSha256(key_, kOutLen, v_, kOutLen);
        std::memcpy(v_, v.data(), kOutLen);
    }

    void RequireInstantiated() const {
        if (!instantiated_) throw std::runtime_error("HmacDrbg: not instantiated");
    }

    static Bytes Concat(const Bytes& a, const Bytes& b, const Bytes& c) {
        Bytes r;
        r.reserve(a.size() + b.size() + c.size());
        r.insert(r.end(), a.begin(), a.end());
        r.insert(r.end(), b.begin(), b.end());
        r.insert(r.end(), c.begin(), c.end());
        return r;
    }

    std::uint8_t key_[kOutLen] = {0};
    std::uint8_t v_[kOutLen] = {0};
    std::uint64_t reseed_counter_ = 0;
    bool instantiated_ = false;
};

} // namespace crypto
} // namespace rngsdk
