// rngsdk_c.cpp — the C ABI translator.
//
// Compiled as C++ (it calls C++ classes); everything it exports has C
// linkage. Every exported body has the same shape and must keep it:
//
//     null-check  ->  try  ->  ONE C++ call  ->  catch  ->  return status
//
// A body that re-derives a bound, re-does a mapping, or "improves" a
// calculation has stopped being a translation layer, and the SDK's security
// and statistical analyses stop transferring to it. The bit-identity tests in
// tests/test_main.cpp fail the moment that happens.
//
// License: MIT.
#include "rngsdk_c.h"

#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

#include "rngsdk/rngsdk.hpp"
#include "engine_box.hpp"

// The opaque handle. Declared as `typedef struct rngsdk_random rngsdk_random;`
// in the header and defined only here, so a caller can hold it but never
// depend on its layout.
struct rngsdk_random {
    std::unique_ptr<rngsdk_c_detail::EngineBox> box;
};

// ServerSession::Play's three failure modes all throw std::runtime_error with
// different MESSAGES, not different types, so a catch block cannot tell them
// apart and parsing the text would break on any rewording. The wrapper checks
// each precondition before calling Play(). Two of those preconditions are not
// observable through ServerSession's public interface, so they are mirrored
// here. This is bookkeeping, not generation.
struct rngsdk_pf_session {
    rngsdk::pf::ServerSession s;
    bool client_seed_set = false;
    bool revealed = false;

    rngsdk_pf_session(std::string server_seed, std::uint64_t start_nonce)
        : s(std::move(server_seed), start_nonce) {}
};

namespace {

using rngsdk_c_detail::EngineBox;
using rngsdk_c_detail::EngineBoxT;

/* Takes ownership immediately, so the box is released even if the handle
 * allocation below throws bad_alloc. */
rngsdk_random* WrapBox(EngineBox* box) {
    std::unique_ptr<EngineBox> owned(box);
    return new rngsdk_random{std::move(owned)};
}

template <class E>
rngsdk_status MakeSeeded(std::uint64_t seed, rngsdk_random** out) {
    *out = WrapBox(new EngineBoxT<E>(E(seed)));
    return RNGSDK_OK;
}

template <class E>
rngsdk_status MakeFromBytes(const rngsdk::crypto::Bytes& b, rngsdk_random** out) {
    *out = WrapBox(new EngineBoxT<E>(E(b)));
    return RNGSDK_OK;
}

// Four OS-entropy words, for full-state seeding of the fast tier.
std::array<std::uint64_t, 4> OsWords4() {
    const rngsdk::crypto::Bytes b = rngsdk::crypto::OsEntropy(32);
    std::array<std::uint64_t, 4> w{};
    std::memcpy(w.data(), b.data(), 32);
    return w;
}

rngsdk_status MakeSecureXoshiro(rngsdk_random** out) {
    std::array<std::uint64_t, 4> w = OsWords4();
    // The all-zero state is xoshiro's single forbidden state. SeedState()
    // would silently repair it to {1,0,0,0}; redrawing keeps the full 256
    // bits instead. (P[redraw] = 2^-256.)
    while ((w[0] | w[1] | w[2] | w[3]) == 0) w = OsWords4();
    rngsdk::Xoshiro256pp e;
    e.SeedState(w);
    *out = WrapBox(new EngineBoxT<rngsdk::Xoshiro256pp>(std::move(e)));
    return RNGSDK_OK;
}

rngsdk_status MakeSecurePcg64(rngsdk_random** out) {
    const std::array<std::uint64_t, 4> w = OsWords4();
    rngsdk::Pcg64 e;
    e.SeedState(rngsdk::detail::u128{w[0], w[1]},    // initstate
                rngsdk::detail::u128{w[2], w[3]});   // stream selector
    *out = WrapBox(new EngineBoxT<rngsdk::Pcg64>(std::move(e)));
    return RNGSDK_OK;
}

// Caller-owned buffers: copy the string plus its NUL, or refuse. Never a
// partial write — a truncated commitment that still looks like hex is worse
// than an error.
rngsdk_status CopyOut(const std::string& s, char* out, std::size_t cap) {
    if (cap < s.size() + 1) return RNGSDK_ERR_BUFFER_TOO_SMALL;
    std::memcpy(out, s.data(), s.size());
    out[s.size()] = '\0';
    return RNGSDK_OK;
}

} // namespace

extern "C" RNGSDK_C_API void rngsdk_build_info(rngsdk_build_info_t* out) {
    // No try/catch: nothing below can throw -- kVersion is a compile-time
    // constant with static storage duration, the two string literals are
    // likewise static, and there is no allocation and no other C++ call.
    if (!out) return;
    out->version = rngsdk::kVersion;
#if defined(RNGSDK_USE_OPENSSL)
    out->crypto_backend   = "openssl";
    out->has_aes_ctr_drbg = 1;
#else
    out->crypto_backend   = "bundled";
    out->has_aes_ctr_drbg = 0;
#endif
}

extern "C" RNGSDK_C_API const char* rngsdk_status_message(rngsdk_status s) {
    // No try/catch: nothing below can throw -- a switch over an enum
    // returning static string literals, no allocation, no C++ call.
    switch (s) {
    case RNGSDK_OK:                   return "ok";
    case RNGSDK_ERR_NULL_ARG:         return "a required pointer argument was NULL";
    case RNGSDK_ERR_INVALID_BOUND:    return "bound must be greater than 0";
    case RNGSDK_ERR_INVALID_ENGINE:   return "unknown engine identifier";
    case RNGSDK_ERR_INVALID_SEED_LEN: return "seed length is wrong for this engine";
    case RNGSDK_ERR_UNSUPPORTED:      return "not available in this build";
    case RNGSDK_ERR_BUFFER_TOO_SMALL: return "output buffer too small";
    case RNGSDK_ERR_WEAK_SEED:        return "server seed shorter than 32 characters";
    case RNGSDK_ERR_NO_CLIENT_SEED:   return "client seed not set";
    case RNGSDK_ERR_REVEALED:         return "session already revealed";
    case RNGSDK_ERR_NONCE_EXHAUSTED:  return "nonce space exhausted";
    case RNGSDK_ERR_ENTROPY:          return "OS entropy source failed";
    case RNGSDK_ERR_INTERNAL:         return "internal error";
    }
    return "unknown status";
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_random_create_seeded(rngsdk_engine kind, uint64_t seed, rngsdk_random** out) {
    if (!out) return RNGSDK_ERR_NULL_ARG;
    *out = nullptr;
    try {
        switch (kind) {
        case RNGSDK_ENGINE_XOSHIRO256PP: return MakeSeeded<rngsdk::Xoshiro256pp>(seed, out);
        case RNGSDK_ENGINE_PCG64:        return MakeSeeded<rngsdk::Pcg64>(seed, out);
        case RNGSDK_ENGINE_HMAC_DRBG:    return MakeSeeded<rngsdk::crypto::HmacDrbgEngine>(seed, out);
        case RNGSDK_ENGINE_AES_CTR_DRBG:
#if defined(RNGSDK_USE_OPENSSL)
            return MakeSeeded<rngsdk::crypto::CtrDrbgEngine>(seed, out);
#else
            return RNGSDK_ERR_UNSUPPORTED;
#endif
        }
        return RNGSDK_ERR_INVALID_ENGINE;
    } catch (...) {
        return RNGSDK_ERR_INTERNAL;
    }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_random_create_seeded_bytes(rngsdk_engine kind, const uint8_t* seed,
                                  size_t seed_len, rngsdk_random** out) {
    if (!out) return RNGSDK_ERR_NULL_ARG;
    *out = nullptr;
    if (!seed) return RNGSDK_ERR_NULL_ARG;
    try {
        const rngsdk::crypto::Bytes b(seed, seed + seed_len);
        switch (kind) {
        case RNGSDK_ENGINE_XOSHIRO256PP:
        case RNGSDK_ENGINE_PCG64:
            return RNGSDK_ERR_UNSUPPORTED;   // no byte-seed constructor exists
        case RNGSDK_ENGINE_HMAC_DRBG:
            // Length checked here rather than caught, so the caller gets a
            // specific code instead of RNGSDK_ERR_INTERNAL. The constant comes
            // from the C++ so the two cannot drift apart.
            if (seed_len < rngsdk::crypto::HmacDrbg::kMinEntropyBytes)
                return RNGSDK_ERR_INVALID_SEED_LEN;
            return MakeFromBytes<rngsdk::crypto::HmacDrbgEngine>(b, out);
        case RNGSDK_ENGINE_AES_CTR_DRBG:
#if defined(RNGSDK_USE_OPENSSL)
            if (seed_len != rngsdk::crypto::CtrDrbg::kSeedLen)
                return RNGSDK_ERR_INVALID_SEED_LEN;
            return MakeFromBytes<rngsdk::crypto::CtrDrbgEngine>(b, out);
#else
            return RNGSDK_ERR_UNSUPPORTED;
#endif
        }
        return RNGSDK_ERR_INVALID_ENGINE;
    } catch (...) {
        return RNGSDK_ERR_INTERNAL;
    }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_random_create_secure(rngsdk_engine kind, rngsdk_random** out) {
    if (!out) return RNGSDK_ERR_NULL_ARG;
    *out = nullptr;
    try {
        switch (kind) {
        case RNGSDK_ENGINE_XOSHIRO256PP: return MakeSecureXoshiro(out);
        case RNGSDK_ENGINE_PCG64:        return MakeSecurePcg64(out);
        case RNGSDK_ENGINE_HMAC_DRBG:
            // The DRBG default constructor IS the secure path (48 OS bytes).
            *out = WrapBox(new EngineBoxT<rngsdk::crypto::HmacDrbgEngine>());
            return RNGSDK_OK;
        case RNGSDK_ENGINE_AES_CTR_DRBG:
#if defined(RNGSDK_USE_OPENSSL)
            *out = WrapBox(new EngineBoxT<rngsdk::crypto::CtrDrbgEngine>());
            return RNGSDK_OK;
#else
            return RNGSDK_ERR_UNSUPPORTED;
#endif
        }
        return RNGSDK_ERR_INVALID_ENGINE;
    } catch (const std::runtime_error&) {
        // os_entropy.hpp throws std::runtime_error and never falls back to a
        // weaker source; this is the only place that failure can originate.
        return RNGSDK_ERR_ENTROPY;
    } catch (...) {
        return RNGSDK_ERR_INTERNAL;
    }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_random_seed(rngsdk_random* h, uint64_t seed) {
    if (!h) return RNGSDK_ERR_NULL_ARG;
    try {
        h->box->Seed(seed);
        return RNGSDK_OK;
    } catch (...) {
        return RNGSDK_ERR_INTERNAL;
    }
}

extern "C" RNGSDK_C_API void rngsdk_random_destroy(rngsdk_random* h) {
    // No try/catch: deleting NULL is well-defined, and every destructor in
    // the chain (including CtrDrbg::~CtrDrbg's EVP_CIPHER_CTX_free) is
    // implicitly noexcept, so nothing here can throw.
    delete h;   // deleting NULL is well-defined, so no guard is needed
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_u64_array(rngsdk_random* h, uint64_t* out, size_t n) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    try {
        h->box->FillU64(out, n);
        return RNGSDK_OK;
    } catch (...) {
        return RNGSDK_ERR_INTERNAL;
    }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_u64(rngsdk_random* h, uint64_t* out) {
    return rngsdk_next_u64_array(h, out, 1);
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_u32_array(rngsdk_random* h, uint32_t* out, size_t n) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    try { h->box->FillU32(out, n); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}
extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_u32(rngsdk_random* h, uint32_t* out) { return rngsdk_next_u32_array(h, out, 1); }

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_double_array(rngsdk_random* h, double* out, size_t n) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    try { h->box->FillDouble(out, n); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}
extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_double(rngsdk_random* h, double* out) { return rngsdk_next_double_array(h, out, 1); }

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_float_array(rngsdk_random* h, float* out, size_t n) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    try { h->box->FillFloat(out, n); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}
extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_float(rngsdk_random* h, float* out) { return rngsdk_next_float_array(h, out, 1); }

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_bounded_u64_array(rngsdk_random* h, uint64_t bound, uint64_t* out, size_t n) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    if (bound == 0) return RNGSDK_ERR_INVALID_BOUND;   // deliberate: see header
    try { h->box->FillBoundedU64(bound, out, n); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}
extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_bounded_u64(rngsdk_random* h, uint64_t bound, uint64_t* out) {
    return rngsdk_next_bounded_u64_array(h, bound, out, 1);
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_bounded_u32_array(rngsdk_random* h, uint32_t bound, uint32_t* out, size_t n) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    if (bound == 0) return RNGSDK_ERR_INVALID_BOUND;
    try { h->box->FillBoundedU32(bound, out, n); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}
extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_bounded_u32(rngsdk_random* h, uint32_t bound, uint32_t* out) {
    return rngsdk_next_bounded_u32_array(h, bound, out, 1);
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_int_range(rngsdk_random* h, int64_t lo, int64_t hi, int64_t* out) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    if (lo > hi) return RNGSDK_ERR_INVALID_BOUND;   // empty range; see header
    try { h->box->FillIntRange(lo, hi, out, 1); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_next_bytes(rngsdk_random* h, uint8_t* out, size_t n) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    try { h->box->FillBytes(out, n); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_commitment(const char* server_seed, char* out_hex, size_t out_cap) {
    if (!server_seed || !out_hex) return RNGSDK_ERR_NULL_ARG;
    try { return CopyOut(rngsdk::pf::Commitment(server_seed), out_hex, out_cap); }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_verify_commitment(const char* server_seed, const char* commitment_hex, int* out_ok) {
    if (!server_seed || !commitment_hex || !out_ok) return RNGSDK_ERR_NULL_ARG;
    try {
        *out_ok = rngsdk::pf::VerifyCommitment(server_seed, commitment_hex) ? 1 : 0;
        return RNGSDK_OK;
    } catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_generate_server_seed(char* out_hex, size_t out_cap) {
    if (!out_hex) return RNGSDK_ERR_NULL_ARG;
    try { return CopyOut(rngsdk::pf::GenerateServerSeed(), out_hex, out_cap); }
    catch (const std::runtime_error&) { return RNGSDK_ERR_ENTROPY; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_next_floats(const char* server_seed, const char* client_seed,
                      uint64_t nonce, size_t n, double* out) {
    if (!server_seed || !client_seed || !out) return RNGSDK_ERR_NULL_ARG;
    try {
        const std::vector<double> v =
            rngsdk::pf::Generator::NextFloats(server_seed, client_seed, nonce, n);
        if (n) std::memcpy(out, v.data(), n * sizeof(double));
        return RNGSDK_OK;
    } catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_generate(const char* server_seed, const char* client_seed,
                   uint64_t nonce, double* out) {
    if (!server_seed || !client_seed || !out) return RNGSDK_ERR_NULL_ARG;
    try {
        *out = rngsdk::pf::Generate(server_seed, client_seed, nonce);
        return RNGSDK_OK;
    } catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_next_ints(const char* server_seed, const char* client_seed,
                    uint64_t nonce, size_t n, uint64_t bound, uint64_t* out) {
    if (!server_seed || !client_seed || !out) return RNGSDK_ERR_NULL_ARG;
    if (bound == 0) return RNGSDK_ERR_INVALID_BOUND;
    try {
        const std::vector<std::uint64_t> v =
            rngsdk::pf::Generator::NextInts(server_seed, client_seed, nonce, n, bound);
        if (n) std::memcpy(out, v.data(), n * sizeof(std::uint64_t));
        return RNGSDK_OK;
    } catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_next_ints_unbiased(const char* server_seed, const char* client_seed,
                             uint64_t nonce, size_t n, uint64_t bound, uint64_t* out) {
    if (!server_seed || !client_seed || !out) return RNGSDK_ERR_NULL_ARG;
    // Checked here rather than caught: the C++ throws for bound == 0, and a
    // thrown exception must never be the mechanism by which a C caller learns
    // about a routine input error.
    if (bound == 0) return RNGSDK_ERR_INVALID_BOUND;
    try {
        const std::vector<std::uint64_t> v =
            rngsdk::pf::Generator::NextIntsUnbiased(server_seed, client_seed, nonce, n, bound);
        if (n) std::memcpy(out, v.data(), n * sizeof(std::uint64_t));
        return RNGSDK_OK;
    } catch (const std::invalid_argument&) { return RNGSDK_ERR_INVALID_BOUND; }
      catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_session_create(const char* server_seed, uint64_t start_nonce,
                         rngsdk_pf_session** out) {
    if (!out) return RNGSDK_ERR_NULL_ARG;
    *out = nullptr;
    if (!server_seed) return RNGSDK_ERR_NULL_ARG;
    try {
        // Checked here so the caller gets RNGSDK_ERR_WEAK_SEED rather than a
        // generic internal error. The constant comes from the C++.
        if (std::strlen(server_seed) < rngsdk::pf::ServerSession::kMinServerSeedChars)
            return RNGSDK_ERR_WEAK_SEED;
        *out = new rngsdk_pf_session(server_seed, start_nonce);
        return RNGSDK_OK;
    } catch (const std::invalid_argument&) { return RNGSDK_ERR_WEAK_SEED; }
      catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API void rngsdk_pf_session_destroy(rngsdk_pf_session* h) { delete h; }

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_session_commitment(rngsdk_pf_session* h, char* out_hex, size_t out_cap) {
    if (!h || !out_hex) return RNGSDK_ERR_NULL_ARG;
    try { return CopyOut(h->s.CommitmentHex(), out_hex, out_cap); }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_session_set_client_seed(rngsdk_pf_session* h, const char* client_seed) {
    if (!h || !client_seed) return RNGSDK_ERR_NULL_ARG;
    try {
        h->s.SetClientSeed(client_seed);
        h->client_seed_set = true;
        return RNGSDK_OK;
    } catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_session_play(rngsdk_pf_session* h, size_t n_floats, double* out) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    // Preconditions first, in the same order the C++ checks them, so the
    // status codes stay distinguishable without reading exception text.
    if (h->revealed) return RNGSDK_ERR_REVEALED;
    if (!h->client_seed_set) return RNGSDK_ERR_NO_CLIENT_SEED;
    if (h->s.NextNonce() == std::numeric_limits<std::uint64_t>::max())
        return RNGSDK_ERR_NONCE_EXHAUSTED;
    try {
        const std::vector<double> v = h->s.Play(n_floats);
        if (n_floats) std::memcpy(out, v.data(), n_floats * sizeof(double));
        return RNGSDK_OK;
    } catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_session_next_nonce(rngsdk_pf_session* h, uint64_t* out) {
    if (!h || !out) return RNGSDK_ERR_NULL_ARG;
    try { *out = h->s.NextNonce(); return RNGSDK_OK; }
    catch (...) { return RNGSDK_ERR_INTERNAL; }
}

extern "C" RNGSDK_C_API rngsdk_status
rngsdk_pf_session_reveal(rngsdk_pf_session* h, char* out_hex, size_t out_cap) {
    if (!h || !out_hex) return RNGSDK_ERR_NULL_ARG;
    try {
        const std::string& seed = h->s.Reveal();
        const rngsdk_status st = CopyOut(seed, out_hex, out_cap);
        // The C++ latches its own reveal flag inside Reveal(), so the mirror
        // must be set even if the copy-out failed — the session IS revealed.
        h->revealed = true;
        return st;
    } catch (...) { return RNGSDK_ERR_INTERNAL; }
}
