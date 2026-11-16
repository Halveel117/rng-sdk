// provenance.hpp — the compiler/arch/build/backend/timestamp block that heads
// every committed benchmark artifact.
//
// Lifted out of benchmark.cpp when rng_thread_bench arrived (OPEN_RESEARCH #9)
// so the two tools cannot print different provenance for the same machine.
// Spec section 6 asks for results across CPU architectures, which makes these
// lines load-bearing evidence rather than hygiene: a throughput or scaling
// table without them cannot be compared against another machine's.
//
// Each tool prints its own iteration/repeat line after calling this, because
// what counts as "one unit of work" differs between them.
#pragma once

#include <cstdio>
#include <ctime>

namespace rngtools {

inline void PrintProvenance() {
#if defined(_MSC_VER)
    std::printf("compiler:   MSVC %d\n", _MSC_VER);
#elif defined(__clang__)
    std::printf("compiler:   clang %d.%d.%d\n", __clang_major__, __clang_minor__,
                __clang_patchlevel__);
#elif defined(__GNUC__)
    std::printf("compiler:   gcc %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    std::puts("compiler:   unknown");
#endif

#if defined(_M_X64) || defined(__x86_64__)
    std::puts("arch:       x86-64");
#elif defined(_M_ARM64) || defined(__aarch64__)
    std::puts("arch:       arm64");
#elif defined(_M_IX86) || defined(__i386__)
    std::puts("arch:       x86-32");
#else
    std::puts("arch:       unknown");
#endif

#if defined(NDEBUG)
    std::puts("build:      Release (NDEBUG)");
#else
    std::puts("build:      DEBUG -- these numbers are NOT representative");
#endif

#if defined(RNGSDK_USE_OPENSSL)
    std::puts("crypto:     OpenSSL backend (CTR-DRBG row present)");
#else
    std::puts("crypto:     bundled reference backend (no CTR-DRBG row)");
#endif

    // localtime() is not thread-safe and MSVC deprecates it; use the platform's
    // reentrant variant rather than silencing the warning.
    const std::time_t now = std::time(nullptr);
    std::tm tm_buf{};
    bool have_tm = false;
#if defined(_MSC_VER)
    have_tm = (localtime_s(&tm_buf, &now) == 0);
#else
    have_tm = (localtime_r(&now, &tm_buf) != nullptr);
#endif
    char stamp[64] = {0};
    if (have_tm && std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm_buf) != 0)
        std::printf("generated:  %s\n", stamp);
}

}  // namespace rngtools
