// rngsdk/crypto/os_entropy.hpp — OS CSPRNG entropy (resolves OPEN_RESEARCH #1).
//
// Policy (deliberate, documented for the security analysis):
//  * CONSUME the platform CSPRNG, don't own a noise source. Each backend below
//    is the OS's kernel-seeded, health-tested DRBG (SP 800-90B obligations —
//    continuous health tests, entropy estimation — are the platform's, and all
//    of these are FIPS-validated or kernel-audited). "We built our own noise
//    source" is the answer that fails audits; this is the one that passes.
//  * NO conditioning layer. These sources emit full-entropy bytes already;
//    re-hashing through SHA-256 cannot add entropy (H(f(X)) <= H(X)) and only
//    adds a construction to justify in the math doc.
//  * NO fallback, FAIL LOUDLY. If the OS call fails we throw — we never
//    degrade to std::random_device / time / ASLR. A crypto seed source that
//    silently weakens passes every statistical test while being guessable;
//    a thrown exception gets fixed the same day. std::random_device is
//    explicitly NOT used: the C++ standard permits it to be deterministic
//    ([rand.device]/2), and MinGW shipped exactly that for years.
//    Corollary, by design: on a pre-3.17 kernel or in a seccomp sandbox that
//    blocks getrandom(2), this THROWS rather than reaching for /dev/urandom.
//    A second code path is a second thing to audit; deployments that need it
//    should mount a working entropy source, not weaken the library.
//  * Exception text carries the OS error code (NTSTATUS / errno). Under a
//    no-fallback policy the exception is the whole operator-facing diagnostic:
//    "CNG unavailable" and "sandbox blocked the syscall" must be tellable
//    apart at 3am.
//
// Backends: BCryptGenRandom (Windows CNG), getrandom(2) (Linux, glibc 2.25+),
// getentropy(3) (macOS/BSD), /dev/urandom (other POSIX).
//
// Windows note: we declare BCryptGenRandom ourselves rather than including
// <windows.h>/<bcrypt.h>. This is a public header in a header-only SDK —
// dragging in <windows.h> (and force-defining WIN32_LEAN_AND_MEAN / NOMINMAX
// for the rest of the consumer's translation unit) would change how *their*
// later includes behave, order-dependently. The declaration below matches the
// Windows SDK exactly (NTSTATUS=long, WINAPI=__stdcall, BCRYPT_ALG_HANDLE=void*,
// PUCHAR=unsigned char*, ULONG=unsigned long) and carries no dllimport, so it
// co-exists with a consumer's own <bcrypt.h> in either include order.
//
// License: MIT.
#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "sha256.hpp"   // Bytes

#if defined(_WIN32)
extern "C" long __stdcall BCryptGenRandom(void* hAlgorithm,
                                          unsigned char* pbBuffer,
                                          unsigned long cbBuffer,
                                          unsigned long dwFlags);
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt")
#endif
#elif defined(__linux__)
#include <sys/random.h>
#include <cerrno>
#include <cstring>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/random.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#elif defined(__OpenBSD__) || defined(__NetBSD__)
#include <unistd.h>          // OpenBSD declares getentropy here; no <sys/random.h>
#include <cerrno>
#include <cstring>
#else
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#endif

namespace rngsdk {
namespace crypto {

namespace detail {
#if defined(_WIN32)
// BCRYPT_USE_SYSTEM_PREFERRED_RNG: nullptr algorithm handle + the CNG system DRBG.
inline constexpr unsigned long kUseSystemPreferredRng = 0x00000002UL;
// BCryptGenRandom takes a 32-bit ULONG length; chunk so a size_t request can
// never truncate to a smaller value (or to zero) and silently "succeed".
inline constexpr std::size_t kWinMaxChunk = 0x1000000u;   // 16 MiB
#endif
inline std::string WithCode(const char* what, long code) {
    return std::string(what) + " (code " + std::to_string(code) + ")";
}
} // namespace detail

// Fill out[0..n) from the OS CSPRNG. Throws std::runtime_error on any failure.
inline void OsEntropyFill(std::uint8_t* out, std::size_t n) {
    if (n == 0) return;   // never hand a possibly-null data() to an OS call
#if defined(_WIN32)
    while (n > 0) {
        const std::size_t take = n < detail::kWinMaxChunk ? n : detail::kWinMaxChunk;
        const long st = BCryptGenRandom(nullptr, out, static_cast<unsigned long>(take),
                                        detail::kUseSystemPreferredRng);
        if (st < 0)   // NT_SUCCESS: error and warning severities both set the sign bit
            throw std::runtime_error(detail::WithCode("OsEntropy: BCryptGenRandom failed", st));
        out += take;
        n -= take;
    }
#elif defined(__linux__)
    while (n > 0) {
        const ssize_t got = getrandom(out, n, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(detail::WithCode(
                "OsEntropy: getrandom failed — no fallback by design", errno));
        }
        if (got == 0)   // would otherwise spin forever
            throw std::runtime_error("OsEntropy: getrandom returned 0 bytes");
        out += got;
        n -= static_cast<std::size_t>(got);
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    while (n > 0) {
        const std::size_t take = n < 256 ? n : 256;   // getentropy per-call cap
        if (getentropy(out, take) != 0)
            throw std::runtime_error(detail::WithCode("OsEntropy: getentropy failed", errno));
        out += take;
        n -= take;
    }
#else
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) throw std::runtime_error(detail::WithCode("OsEntropy: cannot open /dev/urandom", errno));
    // Verify we opened the real character device: in a chroot or a tampered
    // container a planted regular file would yield attacker-chosen "entropy".
    struct stat st {};
    if (fstat(fileno(f), &st) != 0 || !S_ISCHR(st.st_mode)) {
        std::fclose(f);
        throw std::runtime_error("OsEntropy: /dev/urandom is not a character device");
    }
    const std::size_t got = std::fread(out, 1, n, f);
    std::fclose(f);
    if (got != n) throw std::runtime_error("OsEntropy: short read from /dev/urandom");
#endif
}

// n bytes of OS entropy. Throws on failure — no fallback by design (above).
inline Bytes OsEntropy(std::size_t n) {
    Bytes out(n);
    OsEntropyFill(out.data(), n);
    return out;
}

} // namespace crypto
} // namespace rngsdk
