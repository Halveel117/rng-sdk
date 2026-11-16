// memory_report.cpp — per-type memory footprint (spec section 6, "memory
// consumption"). Closes the OPEN_RESEARCH #7b gap of the same name.
//
// Why sizeof and not a heap profiler: no engine in this SDK allocates to
// produce output. State is fixed at construction and the generate path is
// pure arithmetic over it, so there is no growth curve to chase -- the whole
// answer is a static footprint per type. The exceptions are real but small
// and enumerated below rather than guessed at, because the one thing a
// profiler would add here is noise from the allocator, not information about
// the library.
//
// The numbers are printed by the compiler that built this binary rather than
// worked out by hand, for the same reason rng_bench prints provenance: a
// figure in a document that nothing recomputes is the failure mode this
// project has already hit twice (OPEN_RESEARCH #7c(a), item #8's flavour
// table). sizeof is ABI-dependent -- std::string and std::size_t differ
// across libc++/libstdc++/MSVC and across 32- vs 64-bit -- so a committed
// table is only valid for the provenance block printed above it.
//
// What sizeof does not capture is enumerated by the tool itself, under
// "Not captured by sizeof" in its own output. It is stated there and not
// here so there is exactly one copy: this comment previously repeated all
// four items verbatim, which is how two copies of anything start drifting.
//
// License: MIT.
#include <cstdio>
#include <string>

#include "rngsdk/rngsdk.hpp"
#include "provenance.hpp"  // rngtools::PrintProvenance

#define ROW(T, note) std::printf("  %-34s %8zu   %s\n", #T, sizeof(T), note)
// The OpenSSL-only rows still need a line in a bundled build, or the table
// silently has fewer rows than the one it is compared against.
#define ROW_NA(name) std::printf("  %-34s %8s   %s\n", name, "--", "OpenSSL build only")

// Pinned only where the layout is genuinely platform-invariant: these types
// are fixed-width members with 8-byte alignment, no pointers and no
// std::string, so the value is the same under every ABI the SDK targets.
// The buffered engines are deliberately NOT pinned to an exact size -- their
// std::size_t cursor is 4 bytes on a 32-bit build, and an exact assert would
// break the x86-32 configure that OPEN_RESEARCH #9 still wants to exercise.
static_assert(sizeof(rngsdk::Xoshiro256pp) == 32, "xoshiro256++ state is 4 x uint64");
static_assert(sizeof(rngsdk::Pcg64) == 32, "PCG64 state is 2 x uint128");
static_assert(sizeof(rngsdk::crypto::HmacDrbg) == 80, "HMAC-DRBG state: K + V + counter + flag");

// The invariant that actually matters for the buffered engines: the adapter
// is its buffer plus a small constant, so a future field that quietly makes
// an engine expensive to hold per session fails here instead of in a table
// nobody rereads.
static_assert(sizeof(rngsdk::crypto::HmacDrbgEngine) <
                  rngsdk::crypto::HmacDrbgEngine::kBufBytes + 128,
              "HmacDrbgEngine should be its 4 KiB buffer plus a small constant");
#if defined(RNGSDK_USE_OPENSSL)
static_assert(sizeof(rngsdk::crypto::CtrDrbgEngine) <
                  rngsdk::crypto::CtrDrbgEngine::kBufBytes + 128,
              "CtrDrbgEngine should be its 4 KiB buffer plus a small constant");
#endif

int main() {
    std::puts("RNG-SDK memory footprint (spec section 6: memory consumption)");
    std::puts("");
    rngtools::PrintProvenance();
    std::puts("");
    std::puts("sizeof is ABI-dependent; this table is valid for the build above.");
    std::puts("");

    std::printf("  %-34s %8s   %s\n", "type", "bytes", "notes");
    std::printf("  %-34s %8s   %s\n", "----------------------------------", "--------",
                "-----");

    std::puts("");
    std::puts("  Fast tier -- engine state, no heap at all");
    ROW(rngsdk::Xoshiro256pp, "4 x uint64 state");
    ROW(rngsdk::Pcg64, "128-bit state + 128-bit stream selector");
    ROW(rngsdk::SplitMix64, "seeding helper, 1 x uint64");

    std::puts("");
    std::puts("  Crypto tier -- DRBG cores (SP 800-90A state only)");
    ROW(rngsdk::crypto::HmacDrbg, "K + V + reseed counter; 33B transient per Generate");
#if defined(RNGSDK_USE_OPENSSL)
    ROW(rngsdk::crypto::CtrDrbg, "Key + V + counter + EVP_CIPHER_CTX* (heap, opaque)");
#else
    ROW_NA("rngsdk::crypto::CtrDrbg");
#endif

    std::puts("");
    std::puts("  Crypto tier -- engine adapters (what a session actually holds)");
    ROW(rngsdk::crypto::HmacDrbgEngine, "DRBG core + 4 KiB output buffer + cursor");
#if defined(RNGSDK_USE_OPENSSL)
    ROW(rngsdk::crypto::CtrDrbgEngine, "DRBG core + 4 KiB output buffer + cursor");
#else
    ROW_NA("rngsdk::crypto::CtrDrbgEngine");
#endif

    std::puts("");
    std::puts("  Public wrappers -- Random<E> adds no state of its own");
    ROW(rngsdk::FastRandom, "== sizeof(Xoshiro256pp)");
    ROW(rngsdk::Pcg64Random, "== sizeof(Pcg64)");
    ROW(rngsdk::CryptoRandom, "== sizeof(HmacDrbgEngine)");
#if defined(RNGSDK_USE_OPENSSL)
    ROW(rngsdk::CtrRandom, "== sizeof(CtrDrbgEngine)");
#else
    ROW_NA("rngsdk::CtrRandom");
#endif

    std::puts("");
    std::puts("  Provably Fair -- per-session objects");
    ROW(rngsdk::pf::ByteStream, "2 std::string seeds (heap) + 32B block + cursors");
    ROW(rngsdk::pf::ServerSession, "3 std::string (heap) + nonce counter + 2 flags");

    std::puts("");
    std::puts("  Reference points for the same ABI");
    ROW(std::string, "empty string; 64-char hex seed also heap-allocates");
    ROW(void*, "pointer width");

    std::puts("");
    std::puts("Not captured by sizeof (by design, each one bounded):");
    std::puts("  1. CtrDrbg's EVP_CIPHER_CTX -- one opaque OpenSSL heap object per");
    std::puts("     engine, size is an OpenSSL internal and is not guessed at here.");
    std::puts("  2. HmacDrbg::Update -- one 33-byte transient per Generate call,");
    std::puts("     i.e. per 4096 bytes of output once buffered, not per word.");
    std::puts("  3. pf::ByteStream / pf::ServerSession -- one heap allocation per");
    std::puts("     seed string; 64-char hex seeds exceed every SSO threshold.");
    std::puts("  4. NextFloats / NextInts / NextBytes(n) -- caller-sized output,");
    std::puts("     not library overhead.");
    std::puts("");
    std::puts("No engine allocates to produce output: the generate path is");
    std::puts("arithmetic over fixed state, so footprint does not grow with the");
    std::puts("number of values drawn. Per-thread cost is one engine instance");
    std::puts("(see docs/scalability_results.txt -- no shared mutable state).");

    return 0;
}
