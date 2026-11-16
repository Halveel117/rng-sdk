/* rngsdk_c.h — C ABI for the RNG-SDK.
 *
 * WHAT THIS IS. The SDK itself is a header-only C++17 library. This header
 * is a thin C-linkage facade over it, so the SDK can be consumed as a binary
 * from any language with a C FFI (ctypes/cffi, DllImport, JNI/Panama, cgo,
 * N-API). The implementation file behind it is compiled as C++ — it has to
 * be, since it calls C++ classes — but everything declared here has C
 * linkage. The file is C++; only its interface is C.
 *
 * CONVENTIONS.
 *   * Every function returns rngsdk_status. Results come back through
 *     out-parameters. RNGSDK_OK is 0, so `if (rngsdk_...(...)) { ... }` is a
 *     valid error check.
 *   * All buffers are CALLER-OWNED. This library never returns a pointer you
 *     must free, so there is no rngsdk_free_* and a cross-heap
 *     allocate/free mismatch is impossible by construction.
 *   * Handles are NOT thread-safe, exactly like the C++ objects underneath.
 *     Use one handle per thread. This is documented, not enforced: adding a
 *     mutex would misrepresent the library's real threading story.
 *   * No exception can escape any function here.
 *   * Calling convention is the platform default (cdecl). 32-bit Windows
 *     stdcall callers are not supported.
 *
 * License: MIT.
 */
#ifndef RNGSDK_C_H
#define RNGSDK_C_H

#include <stddef.h>
#include <stdint.h>

/* Symbol visibility. RNGSDK_C_BUILDING is defined only while building the
 * shared library; RNGSDK_C_STATIC is defined by consumers of the static
 * library (CMake sets it PUBLIC on the static target). */
#if defined(_WIN32) && !defined(RNGSDK_C_STATIC)
#  if defined(RNGSDK_C_BUILDING)
#    define RNGSDK_C_API __declspec(dllexport)
#  else
#    define RNGSDK_C_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define RNGSDK_C_API __attribute__((visibility("default")))
#else
#  define RNGSDK_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Bytes needed for a 64-character hex string plus its NUL terminator.
 * Use this rather than hard-coding 65. */
#define RNGSDK_HEX_BUF 65

/* Status codes. APPEND-ONLY: a future version may add codes but must never
 * renumber these, because a compiled caller holds the numeric values. */
typedef enum {
    RNGSDK_OK = 0,
    RNGSDK_ERR_NULL_ARG,          /* a required pointer argument was NULL     */
    RNGSDK_ERR_INVALID_BOUND,     /* bound == 0                               */
    RNGSDK_ERR_INVALID_ENGINE,    /* engine enum value out of range           */
    RNGSDK_ERR_INVALID_SEED_LEN,  /* byte seed wrong length for this engine   */
    RNGSDK_ERR_UNSUPPORTED,       /* engine/operation absent in this build    */
    RNGSDK_ERR_BUFFER_TOO_SMALL,  /* out_cap too small for the string + NUL   */
    RNGSDK_ERR_WEAK_SEED,         /* ServerSession seed shorter than 32 chars */
    RNGSDK_ERR_NO_CLIENT_SEED,    /* play() before set_client_seed()          */
    RNGSDK_ERR_REVEALED,          /* play() after reveal()                    */
    RNGSDK_ERR_NONCE_EXHAUSTED,   /* nonce space exhausted                    */
    RNGSDK_ERR_ENTROPY,           /* OS entropy source failed                 */
    RNGSDK_ERR_INTERNAL           /* unexpected exception; catch-all          */
} rngsdk_status;

/* Engines. Also append-only. */
typedef enum {
    RNGSDK_ENGINE_XOSHIRO256PP = 0,  /* fast tier — NOT cryptographic */
    RNGSDK_ENGINE_PCG64,             /* fast tier — NOT cryptographic */
    RNGSDK_ENGINE_HMAC_DRBG,         /* SP 800-90A HMAC-SHA256-DRBG   */
    RNGSDK_ENGINE_AES_CTR_DRBG       /* SP 800-90A AES-256-CTR-DRBG,
                                        OpenSSL builds only — see
                                        rngsdk_build_info()           */
} rngsdk_engine;

/* Opaque handles. Never defined in this header; never dereference them. */
typedef struct rngsdk_random rngsdk_random;
typedef struct rngsdk_pf_session rngsdk_pf_session;

/* ---------------------------------------------------------- introspection */

/* FROZEN. Unlike the enums above, which are append-only, this struct's layout
 * will NOT grow: it is caller-allocated, so adding a field would make a new
 * library write past an old caller's allocation. Future introspection arrives
 * as new functions, never as new members here. */
typedef struct {
    const char* version;          /* e.g. "0.1.0-prototype"; static storage  */
    const char* crypto_backend;   /* "bundled" or "openssl"; static storage  */
    int         has_aes_ctr_drbg; /* 0 or 1                                  */
} rngsdk_build_info_t;

/* Which flavour of this binary am I holding? This is an audit surface: ask
 * the shipped artifact rather than trusting a build log. NULL is a no-op. */
RNGSDK_C_API void rngsdk_build_info(rngsdk_build_info_t* out);

/* A static English string for logging. NEVER returns NULL, and the caller
 * must NEVER free it. The status CODE is the contract; this string is a
 * convenience and its wording may change between versions. */
RNGSDK_C_API const char* rngsdk_status_message(rngsdk_status s);

/* ------------------------------------------------- creation / destruction */

/* Deterministic: same seed, same sequence, on every platform and both crypto
 * backends. Works for all four engines. */
RNGSDK_C_API rngsdk_status rngsdk_random_create_seeded(rngsdk_engine kind,
                                                       uint64_t seed,
                                                       rngsdk_random** out);

/* Deterministic from raw seed bytes. DRBG engines only — the fast tier has no
 * such constructor and returns RNGSDK_ERR_UNSUPPORTED.
 *   RNGSDK_ENGINE_HMAC_DRBG     needs >= 32 bytes (SP 800-90A minimum).
 *   RNGSDK_ENGINE_AES_CTR_DRBG  needs EXACTLY 48 bytes (the no-df seedlen).
 * Anything else is RNGSDK_ERR_INVALID_SEED_LEN — short entropy is rejected,
 * never zero-extended. */
RNGSDK_C_API rngsdk_status rngsdk_random_create_seeded_bytes(rngsdk_engine kind,
                                                             const uint8_t* seed,
                                                             size_t seed_len,
                                                             rngsdk_random** out);

/* Seeded from the OS CSPRNG. Nondeterministic by design.
 *
 * For the fast-tier engines this seeds the FULL 256-bit engine state from OS
 * entropy — it does not use their default constructors, which would hand back
 * a fixed, predictable stream.
 *
 * READ THIS: seeding the fast tier from the OS makes it UNPREDICTABLE AT
 * INSTANTIATION. It does NOT make it cryptographically secure. xoshiro256++
 * and PCG64 are linear generators whose entire future output follows from
 * observed output. Never use the fast tier for paid outcomes or for anything
 * a player can verify — see obligation 4 in docs/INTEGRATION_GUIDE.md.
 *
 * Returns RNGSDK_ERR_ENTROPY if the OS entropy source fails. The library
 * never falls back to a weaker source. */
RNGSDK_C_API rngsdk_status rngsdk_random_create_secure(rngsdk_engine kind,
                                                       rngsdk_random** out);

/* Reseed an existing handle deterministically; restarts the stream. */
RNGSDK_C_API rngsdk_status rngsdk_random_seed(rngsdk_random* h, uint64_t seed);

/* Releases the handle. NULL is a no-op, matching free(). Null your own pointer
 * afterwards: the library cannot detect a destroyed handle, so reusing one is
 * undefined behaviour, not an error code. */
RNGSDK_C_API void rngsdk_random_destroy(rngsdk_random* h);

/* ------------------------------------------------------------- generators */

/* PERFORMANCE: prefer the _array forms. One call for n values amortises the
 * boundary crossing; the scalar form is for convenience, not for loops and
 * not for benchmarking. n == 0 is a valid no-op (out must still be non-NULL). */
RNGSDK_C_API rngsdk_status rngsdk_next_u64(rngsdk_random* h, uint64_t* out);
RNGSDK_C_API rngsdk_status rngsdk_next_u64_array(rngsdk_random* h,
                                                 uint64_t* out, size_t n);

RNGSDK_C_API rngsdk_status rngsdk_next_u32(rngsdk_random* h, uint32_t* out);
RNGSDK_C_API rngsdk_status rngsdk_next_u32_array(rngsdk_random* h,
                                                 uint32_t* out, size_t n);

/* Uniform on {k * 2^-53 : 0 <= k < 2^53} in [0, 1) — the top 53 bits, the
 * full significand of an IEEE-754 double. Not a division by 2^64. */
RNGSDK_C_API rngsdk_status rngsdk_next_double(rngsdk_random* h, double* out);
RNGSDK_C_API rngsdk_status rngsdk_next_double_array(rngsdk_random* h,
                                                    double* out, size_t n);

/* Uniform on {k * 2^-24 : 0 <= k < 2^24} in [0, 1). */
RNGSDK_C_API rngsdk_status rngsdk_next_float(rngsdk_random* h, float* out);
RNGSDK_C_API rngsdk_status rngsdk_next_float_array(rngsdk_random* h,
                                                   float* out, size_t n);

/* Uniform on [0, bound) with NO modulo bias (Lemire rejection).
 *
 * bound == 0 returns RNGSDK_ERR_INVALID_BOUND. Note that the underlying C++
 * returns 0 for this input instead; the C ABI refuses it so that every
 * bound-taking function in this header behaves the same way. A rejected call
 * writes nothing and consumes no generator output. */
RNGSDK_C_API rngsdk_status rngsdk_next_bounded_u64(rngsdk_random* h, uint64_t bound,
                                                   uint64_t* out);
RNGSDK_C_API rngsdk_status rngsdk_next_bounded_u64_array(rngsdk_random* h, uint64_t bound,
                                                         uint64_t* out, size_t n);
RNGSDK_C_API rngsdk_status rngsdk_next_bounded_u32(rngsdk_random* h, uint32_t bound,
                                                   uint32_t* out);
RNGSDK_C_API rngsdk_status rngsdk_next_bounded_u32_array(rngsdk_random* h, uint32_t bound,
                                                         uint32_t* out, size_t n);

/* Uniform on the INCLUSIVE range [lo, hi]. lo == hi is valid and returns lo.
 * lo > hi returns RNGSDK_ERR_INVALID_BOUND: the range is empty, and the
 * underlying unsigned span arithmetic would otherwise wrap and hand back a
 * value from an interval you did not ask for.
 *
 * Deliberately the one generator with NO _array form. A per-outcome integer
 * range is a game-logic call, not a bulk one; batching it would mean fixing
 * lo and hi for the whole batch, which is not how it gets used. If you need
 * many draws from ONE fixed range, use rngsdk_next_bounded_u64_array(hi - lo
 * + 1) and add lo yourself. */
RNGSDK_C_API rngsdk_status rngsdk_next_int_range(rngsdk_random* h,
                                                 int64_t lo, int64_t hi, int64_t* out);

/* n raw bytes. Already the bulk form; there is no scalar counterpart. */
RNGSDK_C_API rngsdk_status rngsdk_next_bytes(rngsdk_random* h, uint8_t* out, size_t n);

/* ------------------------------------------- Provably Fair — stateless */

/* THE HMAC KEY IS THE SEED STRING'S OWN BYTES.
 *
 * server_seed is a NUL-terminated string, and the scheme uses its CHARACTERS
 * as the HMAC-SHA256 key — the ASCII/UTF-8 bytes of the 64 hex characters,
 * not the 32 bytes those characters encode. If you hold 32 raw bytes, hex-
 * encode them into a string and pass that; passing the raw bytes produces a
 * completely different, silently wrong result stream with nothing to signal
 * the error. This is the single most common way a reimplementation of this
 * scheme goes wrong.
 *
 * client_seed may be empty (""), but must not be NULL. */

/* SHA-256(server_seed) as 64 lowercase hex characters. Publish this BEFORE
 * play. out_cap must be at least RNGSDK_HEX_BUF; nothing is written if it is
 * not. */
RNGSDK_C_API rngsdk_status rngsdk_pf_commitment(const char* server_seed,
                                                char* out_hex, size_t out_cap);

/* *out_ok = 1 if SHA-256(server_seed) equals commitment_hex, else 0. The
 * return value reports whether the CHECK RAN, not what it concluded — check
 * the status first, then out_ok. */
RNGSDK_C_API rngsdk_status rngsdk_pf_verify_commitment(const char* server_seed,
                                                       const char* commitment_hex,
                                                       int* out_ok);

/* A fresh 256-bit server seed from the OS CSPRNG, hex-encoded (64 chars).
 * Use this — never a literal, never a value derived from a counter or a
 * timestamp. Returns RNGSDK_ERR_ENTROPY if the OS source fails. */
RNGSDK_C_API rngsdk_status rngsdk_pf_generate_server_seed(char* out_hex, size_t out_cap);

/* n outcomes in [0, 1) for one bet, industry-compatible mapping (4 bytes ->
 * sum b_i/256^(i+1)). out must have room for n doubles; n == 0 is a no-op. */
RNGSDK_C_API rngsdk_status rngsdk_pf_next_floats(const char* server_seed,
                                                 const char* client_seed,
                                                 uint64_t nonce, size_t n, double* out);

/* One outcome in [0, 1) for one bet — the spec's Generate(server_seed,
 * client_seed, nonce). Exactly rngsdk_pf_next_floats(..., 1, out); provided
 * because that is the name integrators look for. */
RNGSDK_C_API rngsdk_status rngsdk_pf_generate(const char* server_seed,
                                              const char* client_seed,
                                              uint64_t nonce, double* out);

/* n integers in [0, bound), industry-compatible: floor(f * bound). Carries a
 * relative bias of at most bound/2^32 — negligible at game sizes but NOT
 * zero. Use rngsdk_pf_next_ints_unbiased when "provably no bias" has to hold. */
/* bound == 0 returns RNGSDK_ERR_INVALID_BOUND, as on the generator handles. */
RNGSDK_C_API rngsdk_status rngsdk_pf_next_ints(const char* server_seed,
                                               const char* client_seed,
                                               uint64_t nonce, size_t n,
                                               uint64_t bound, uint64_t* out);

/* n integers in [0, bound) with EXACTLY zero bias (Lemire rejection over the
 * HMAC byte stream). Does not match other operators' verifiers.
 * bound == 0 returns RNGSDK_ERR_INVALID_BOUND. */
RNGSDK_C_API rngsdk_status rngsdk_pf_next_ints_unbiased(const char* server_seed,
                                                        const char* client_seed,
                                                        uint64_t nonce, size_t n,
                                                        uint64_t bound, uint64_t* out);

/* --------------------------------------------- Provably Fair — session */

/* A server-side session enforcing the protocol order and nonce monotonicity.
 * Not thread-safe; use one session per thread, or serialise access.
 *
 * start_nonce has NO default, deliberately. It is how a server that restarted
 * mid-session resumes where it left off: re-instantiating at 0 with the same
 * seed pair replays outcomes the player has already seen. Requiring the value
 * at every call site makes that decision explicit rather than omittable. See
 * obligation 2 in docs/INTEGRATION_GUIDE.md.
 *
 * server_seed must be at least 32 characters, or the call returns
 * RNGSDK_ERR_WEAK_SEED. Use rngsdk_pf_generate_server_seed(). */
RNGSDK_C_API rngsdk_status rngsdk_pf_session_create(const char* server_seed,
                                                    uint64_t start_nonce,
                                                    rngsdk_pf_session** out);

/* NULL is a no-op. Null your own pointer afterwards: the library cannot detect
 * a destroyed handle, so reusing one is undefined behaviour, not an error
 * code. (See PfSession.close() in bindings/python/rngsdk.py.) */
RNGSDK_C_API void rngsdk_pf_session_destroy(rngsdk_pf_session* h);

/* Publish this BEFORE any play. out_cap >= RNGSDK_HEX_BUF. */
RNGSDK_C_API rngsdk_status rngsdk_pf_session_commitment(rngsdk_pf_session* h,
                                                        char* out_hex, size_t out_cap);

/* The player's seed, and it must genuinely be the player's — generated on
 * their device AFTER the commitment is published. May be set again mid-session;
 * doing so does NOT rewind the nonce. */
RNGSDK_C_API rngsdk_status rngsdk_pf_session_set_client_seed(rngsdk_pf_session* h,
                                                             const char* client_seed);

/* One bet: n_floats outcomes in [0, 1) at the current nonce, which then
 * advances by one. Returns RNGSDK_ERR_NO_CLIENT_SEED before the client seed is
 * set, RNGSDK_ERR_REVEALED after reveal, RNGSDK_ERR_NONCE_EXHAUSTED at the end
 * of the nonce space (rotate the seed rather than wrapping). */
RNGSDK_C_API rngsdk_status rngsdk_pf_session_play(rngsdk_pf_session* h,
                                                  size_t n_floats, double* out);

/* The nonce the NEXT play will use. Persist this alongside the server seed. */
RNGSDK_C_API rngsdk_status rngsdk_pf_session_next_nonce(rngsdk_pf_session* h, uint64_t* out);

/* End of session: hand the server seed to the player so they can verify. The
 * session refuses to play afterwards. out_cap must be at least
 * strlen(server_seed) + 1 -- size it from the seed you passed to
 * rngsdk_pf_session_create, NOT from RNGSDK_HEX_BUF. RNGSDK_HEX_BUF suffices
 * only for a seed from rngsdk_pf_generate_server_seed(); create() accepts any
 * seed of 32 characters or more, and a short buffer here fails AFTER the
 * reveal latch has fired, leaving a session that can neither play nor hand
 * over the seed the player needs to verify. */
RNGSDK_C_API rngsdk_status rngsdk_pf_session_reveal(rngsdk_pf_session* h,
                                                    char* out_hex, size_t out_cap);

#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* RNGSDK_C_H */
