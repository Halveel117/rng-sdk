// rngsdk/crypto/ctr_drbg.hpp — CTR_DRBG with AES-256, no derivation function,
// per NIST SP 800-90A Rev. 1 §10.2.1. The SDK's second "Cryptographic RNG".
//
// Requires OpenSSL (RNGSDK_USE_OPENSSL): AES is deliberately NOT hand-rolled.
// A textbook table-driven AES leaks the key through cache timing (Bernstein
// 2005 and successors), and OpenSSL's EVP layer dispatches to AES-NI, which
// is both constant-time and ~10x faster. "We wrote our own AES" is also the
// answer that fails a gaming-lab audit; EVP_aes_256_ecb is FIPS-validated.
//
// Why "no df": the derivation-function variant condenses arbitrary-length
// seed material. Ours arrives as exactly seedlen bytes of full-entropy OS
// output (crypto::SecureEntropy() -> 48 bytes = keylen 32 + blocklen 16), so
// the df would be pure overhead and one more construction to justify in the
// math doc. NIST publishes CAVP vectors for this exact configuration
// ([AES-256 no df]); the test suite runs them.
//
// State: Key (32B) + V (16B). Both operations below are the spec verbatim.
//
//   CTR_DRBG_Update(provided_data, Key, V)          §10.2.1.2
//     temp = empty
//     while len(temp) < seedlen:
//         V = (V + 1) mod 2^blocklen
//         temp = temp || AES-ECB-Encrypt(Key, V)
//     temp = leftmost seedlen bytes of temp
//     temp = temp XOR provided_data          (provided_data is exactly seedlen)
//     Key  = leftmost keylen bytes of temp
//     V    = rightmost blocklen bytes of temp
//
//   Generate(n)                                      §10.2.1.5
//     [reseed check] ; if additional_input: Update(additional_input)
//     while produced < n:
//         V = (V + 1) mod 2^blocklen
//         emit AES-ECB-Encrypt(Key, V)
//     Update(additional_input)      // zero-filled if none -> backtracking resistance
//     ++reseed_counter
//
// Note the counter is incremented BEFORE each encryption, in both operations —
// getting that order wrong still produces plausible-looking random bytes and
// fails only against known-answer vectors. That is why CAVP matters here.
//
// License: MIT.
#pragma once

#if !defined(RNGSDK_USE_OPENSSL)
#error "ctr_drbg.hpp requires -DRNGSDK_USE_OPENSSL=ON (AES comes from OpenSSL)"
#endif

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>

#include "sha256.hpp"   // Bytes

namespace rngsdk {
namespace crypto {

class CtrDrbg {
public:
    static constexpr std::size_t kKeyLen = 32;                    // AES-256
    static constexpr std::size_t kBlockLen = 16;                  // AES block
    static constexpr std::size_t kSeedLen = kKeyLen + kBlockLen;  // 48
    static constexpr std::size_t kMaxBytesPerRequest = 1u << 16;  // 2^19 bits
    static constexpr std::uint64_t kReseedInterval = 1ULL << 48;

    CtrDrbg() = default;
    ~CtrDrbg() { FreeCipher(); }

    // Copy is deleted deliberately: duplicating a DRBG silently forks its
    // output stream, and two "independent" generators emitting identical
    // bytes is a catastrophic failure mode in a gaming RNG.
    CtrDrbg(const CtrDrbg&) = delete;
    CtrDrbg& operator=(const CtrDrbg&) = delete;

    // Move IS supported: without it Random<CtrDrbgEngine> would not be
    // MoveInsertable, so `std::vector<CtrRandom>` (the natural one-engine-
    // per-thread pattern) would not compile. Steals the cipher context.
    CtrDrbg(CtrDrbg&& o) noexcept { MoveFrom(o); }
    CtrDrbg& operator=(CtrDrbg&& o) noexcept {
        if (this != &o) { FreeCipher(); MoveFrom(o); }
        return *this;
    }

    // Instantiate (§10.2.1.3.1, no df):
    //     personalization_string ||= 0^(seedlen - len)      [zero-PAD]
    //     seed_material = entropy_input XOR personalization_string
    //     Key = 0^keylen ; V = 0^blocklen ; Update(seed_material)
    //
    // Note the XOR: this is the no-df construction. Concatenating instead is
    // the *derivation-function* variant's seed material, and it agrees with
    // XOR whenever the personalization string is empty -- which is why only
    // the CAVP sections with a non-empty personalization can tell them apart.
    //
    // entropy MUST be exactly seedlen bytes of full-entropy input: no-df has
    // no conditioning stage, so the DRBG's security strength is exactly what
    // arrives here. Silently zero-padding a short entropy input would
    // instantiate a nominally 256-bit generator from less, which is precisely
    // the quiet degradation this SDK refuses to do anywhere else.
    // `nonce` exists only for signature symmetry with HmacDrbg; no-df has no
    // nonce (CAVP fixes NonceLen = 0), so a non-empty one is rejected rather
    // than silently folded in.
    void Instantiate(const Bytes& entropy,
                     const Bytes& nonce = {},
                     const Bytes& personalization = {}) {
        if (entropy.size() != kSeedLen)
            throw std::invalid_argument(
                "CtrDrbg: no-df entropy input must be exactly seedlen (48 bytes)");
        if (!nonce.empty())
            throw std::invalid_argument(
                "CtrDrbg: no-df takes no nonce (fold it into the 48-byte entropy input)");

        std::memset(key_, 0x00, kKeyLen);       // Key = 0^keylen
        std::memset(v_, 0x00, kBlockLen);       // V   = 0^blocklen
        key_valid_ = false;                     // key_ changed -> re-key the cipher ctx
        Update(XorSeedMaterial(entropy, personalization));
        reseed_counter_ = 1;
        instantiated_ = true;
    }

    // Reseed (§10.2.1.4.1, no df): same construction with additional_input.
    void Reseed(const Bytes& entropy, const Bytes& additional = {}) {
        RequireInstantiated();
        if (entropy.size() != kSeedLen)
            throw std::invalid_argument(
                "CtrDrbg: no-df reseed entropy must be exactly seedlen (48 bytes)");
        Update(XorSeedMaterial(entropy, additional));
        reseed_counter_ = 1;
    }

    // Generate (§10.2.1.5). Throws when a reseed is due rather than silently
    // recycling state, matching HmacDrbg's contract.
    void Generate(std::uint8_t* out, std::size_t n, const Bytes& additional = {}) {
        RequireInstantiated();
        if (n > kMaxBytesPerRequest)
            throw std::invalid_argument("CtrDrbg: > 2^19 bits requested in one call");
        if (reseed_counter_ > kReseedInterval)
            throw std::runtime_error("CtrDrbg: reseed required (reseed_interval reached)");

        Bytes add = additional;
        if (!add.empty()) {
            if (add.size() > kSeedLen)
                throw std::invalid_argument("CtrDrbg: additional input must be <= seedlen");
            add.resize(kSeedLen, 0x00);
            Update(add);
        }

        std::uint8_t block[kBlockLen];
        std::size_t produced = 0;
        while (produced < n) {
            IncrementV();
            EncryptBlock(v_, block);
            const std::size_t take = (n - produced < kBlockLen) ? n - produced : kBlockLen;
            std::memcpy(out + produced, block, take);
            produced += take;
        }

        // Spec: Update with additional_input (all-zero seedlen when absent).
        Update(add.empty() ? Bytes(kSeedLen, 0x00) : add);
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
    // seed_material = entropy XOR (extra zero-padded to seedlen). Caller has
    // already checked entropy.size() == kSeedLen.
    static Bytes XorSeedMaterial(const Bytes& entropy, const Bytes& extra) {
        if (extra.size() > kSeedLen)
            throw std::invalid_argument("CtrDrbg: no-df string must be <= seedlen (48 bytes)");
        Bytes out = entropy;
        for (std::size_t i = 0; i < extra.size(); ++i) out[i] ^= extra[i];
        return out;
    }

    // CTR_DRBG_Update (§10.2.1.2). provided must be exactly seedlen bytes.
    void Update(const Bytes& provided) {
        std::uint8_t temp[kSeedLen];
        std::size_t filled = 0;
        std::uint8_t block[kBlockLen];
        while (filled < kSeedLen) {
            IncrementV();
            EncryptBlock(v_, block);
            const std::size_t take = (kSeedLen - filled < kBlockLen) ? kSeedLen - filled : kBlockLen;
            std::memcpy(temp + filled, block, take);
            filled += take;
        }
        for (std::size_t i = 0; i < kSeedLen; ++i) temp[i] ^= provided[i];
        std::memcpy(key_, temp, kKeyLen);
        std::memcpy(v_, temp + kKeyLen, kBlockLen);
        key_valid_ = false;   // key changed -> cipher ctx must be re-keyed
    }

    // V = (V + 1) mod 2^blocklen, big-endian counter per the spec.
    void IncrementV() {
        for (int i = static_cast<int>(kBlockLen) - 1; i >= 0; --i)
            if (++v_[i] != 0) break;
    }

    // Single AES-256-ECB block encryption. ECB is correct here: the spec
    // applies the raw block cipher to a counter we manage ourselves.
    void EncryptBlock(const std::uint8_t in[kBlockLen], std::uint8_t out[kBlockLen]) {
        if (!ctx_) {
            ctx_ = EVP_CIPHER_CTX_new();
            if (!ctx_) throw std::runtime_error("CtrDrbg: EVP_CIPHER_CTX_new failed");
        }
        if (!key_valid_) {
            if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_ecb(), nullptr, key_, nullptr) != 1)
                throw std::runtime_error("CtrDrbg: EVP_EncryptInit_ex failed");
            EVP_CIPHER_CTX_set_padding(ctx_, 0);
            key_valid_ = true;
        }
        int len = 0;
        if (EVP_EncryptUpdate(ctx_, out, &len, in, static_cast<int>(kBlockLen)) != 1 ||
            len != static_cast<int>(kBlockLen))
            throw std::runtime_error("CtrDrbg: EVP_EncryptUpdate failed");
    }

    void FreeCipher() {
        if (ctx_) { EVP_CIPHER_CTX_free(ctx_); ctx_ = nullptr; }
    }

    void MoveFrom(CtrDrbg& o) noexcept {
        std::memcpy(key_, o.key_, kKeyLen);
        std::memcpy(v_, o.v_, kBlockLen);
        reseed_counter_ = o.reseed_counter_;
        instantiated_ = o.instantiated_;
        key_valid_ = o.key_valid_;
        ctx_ = o.ctx_;
        o.ctx_ = nullptr;            // sole owner; source must not free it
        o.instantiated_ = false;
        o.key_valid_ = false;
    }

    void RequireInstantiated() const {
        if (!instantiated_) throw std::runtime_error("CtrDrbg: not instantiated");
    }

    std::uint8_t key_[kKeyLen] = {0};
    std::uint8_t v_[kBlockLen] = {0};
    std::uint64_t reseed_counter_ = 0;
    bool instantiated_ = false;
    bool key_valid_ = false;
    EVP_CIPHER_CTX* ctx_ = nullptr;
};

} // namespace crypto
} // namespace rngsdk
