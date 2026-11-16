// rngsdk/crypto/hmac_sha256.hpp — HMAC-SHA256 (RFC 2104 / FIPS 198-1).
//
// Built on the Sha256 backend header, so it automatically follows the
// RNGSDK_USE_OPENSSL switch through Sha256's streaming core (reference path)
// or OpenSSL's HMAC one-shot. Validated against RFC 4231 test vectors and
// cross-checked against Python hmac/hashlib in the test suite.
//
// License: MIT.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "sha256.hpp"

#if defined(RNGSDK_USE_OPENSSL)
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdexcept>
#endif

namespace rngsdk {
namespace crypto {

#if defined(RNGSDK_USE_OPENSSL)
namespace detail {

// One EVP_MAC fetch and one EVP_MAC_CTX per thread, with the digest bound
// once at construction. OpenSSL 3.x's one-shot HMAC() re-runs the provider
// fetch and context setup on every call; the DRBG calls this once per 32-byte
// block, so that setup dominates, and the shared provider state it touches is
// also why the OpenSSL HMAC path scaled badly across threads. Per-thread
// state keeps both costs off the hot path. See OPEN_RESEARCH #11.
class HmacCtx {
public:
    HmacCtx() {
        mac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (mac_ == nullptr) throw std::runtime_error("rngsdk: EVP_MAC_fetch(HMAC) failed");
        ctx_ = EVP_MAC_CTX_new(mac_);
        if (ctx_ == nullptr) {
            EVP_MAC_free(mac_);
            throw std::runtime_error("rngsdk: EVP_MAC_CTX_new failed");
        }
        char digest[] = "SHA256";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
            OSSL_PARAM_construct_end()
        };
        if (EVP_MAC_CTX_set_params(ctx_, params) != 1) {
            EVP_MAC_CTX_free(ctx_);
            EVP_MAC_free(mac_);
            throw std::runtime_error("rngsdk: EVP_MAC_CTX_set_params(SHA256) failed");
        }
    }
    ~HmacCtx() {
        EVP_MAC_CTX_free(ctx_);
        EVP_MAC_free(mac_);
    }
    HmacCtx(const HmacCtx&) = delete;
    HmacCtx& operator=(const HmacCtx&) = delete;

    EVP_MAC_CTX* get() const { return ctx_; }

private:
    EVP_MAC* mac_;
    EVP_MAC_CTX* ctx_;
};

inline EVP_MAC_CTX* ThreadHmacCtx() {
    thread_local HmacCtx ctx;
    return ctx.get();
}

} // namespace detail
#endif

inline std::array<std::uint8_t, Sha256::kDigestSize>
HmacSha256(const void* key, std::size_t key_len, const void* msg, std::size_t msg_len) {
#if defined(RNGSDK_USE_OPENSSL)
    std::array<std::uint8_t, Sha256::kDigestSize> out{};
    EVP_MAC_CTX* ctx = detail::ThreadHmacCtx();
    const unsigned char dummy = 0;  // EVP_MAC_init wants a non-null key pointer
    const unsigned char* k = (key_len == 0) ? &dummy
                                            : static_cast<const unsigned char*>(key);
    std::size_t out_len = 0;
    if (EVP_MAC_init(ctx, k, key_len, nullptr) != 1 ||
        EVP_MAC_update(ctx, static_cast<const unsigned char*>(msg), msg_len) != 1 ||
        EVP_MAC_final(ctx, out.data(), &out_len, out.size()) != 1 ||
        out_len != out.size()) {
        throw std::runtime_error("rngsdk: HMAC-SHA256 computation failed");
    }
    return out;
#else
    constexpr std::size_t B = Sha256::kBlockSize;
    std::array<std::uint8_t, B> k_block{};   // zero-padded (or hashed) key

    if (key_len > B) {
        const auto kh = Sha256::Hash(key, key_len);
        std::memcpy(k_block.data(), kh.data(), kh.size());
    } else {
        std::memcpy(k_block.data(), key, key_len);
    }

    std::array<std::uint8_t, B> ipad{}, opad{};
    for (std::size_t i = 0; i < B; ++i) {
        ipad[i] = static_cast<std::uint8_t>(k_block[i] ^ 0x36);
        opad[i] = static_cast<std::uint8_t>(k_block[i] ^ 0x5c);
    }

    Sha256 inner;
    inner.Update(ipad.data(), B);
    inner.Update(msg, msg_len);
    const auto inner_digest = inner.Finish();

    Sha256 outer;
    outer.Update(opad.data(), B);
    outer.Update(inner_digest.data(), inner_digest.size());
    return outer.Finish();
#endif
}

inline std::array<std::uint8_t, Sha256::kDigestSize>
HmacSha256(const Bytes& key, const Bytes& msg) {
    return HmacSha256(key.data(), key.size(), msg.data(), msg.size());
}

inline std::array<std::uint8_t, Sha256::kDigestSize>
HmacSha256(const std::string& key, const std::string& msg) {
    return HmacSha256(key.data(), key.size(), msg.data(), msg.size());
}

} // namespace crypto
} // namespace rngsdk
