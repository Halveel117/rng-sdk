// benchmark.cpp — throughput comparison (spec: "performance: numbers/sec").
//
// Measures raw 64-bit words/sec and doubles/sec for: xoshiro256++, PCG64,
// HMAC-DRBG (ours), std::mt19937_64 (the Mersenne Twister baseline), the C
// library's rand() via rngtools::RandBuiltin, and std::minstd_rand. A volatile
// sink prevents the optimizer from deleting the loops. Single-threaded by
// design — the fast engines' multithreading story is jump()-separated streams,
// benchmarked per-core.
//
// Two corrections landed 2026-08-25 (OPEN_RESEARCH #7c(a),(b)):
//
//  * This file used to describe std::minstd_rand as "the language built-in".
//    It is not — it is a standard-library LCG. The generator rng_pi/rng_ode
//    actually use for their "rand()-builtin" row is C rand(), wrapped by
//    rngtools::RandBuiltin. So spec 10.3 names five generators to compare on
//    speed and only four of them had a throughput figure. RandBuiltin is now
//    measured here, through the SAME adapter the Monte Carlo tools use, so the
//    speed and accuracy columns describe one generator rather than two.
//  * The committed docs/benchmark_results.txt recorded no machine, compiler or
//    build configuration. A throughput number without that is unreproducible,
//    and it showed: README quoted xoshiro at ~6.4e8 while the results file said
//    7.625e8, from a different machine, with nothing to reconcile them. main()
//    now prints a provenance block, so the artifact cannot drift from the box
//    that produced it. Spec §6 asks for results across CPU architectures, which
//    makes that line load-bearing rather than hygiene.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <random>

#include "rngsdk/rngsdk.hpp"
#include "provenance.hpp"            // rngtools::PrintProvenance
#include "std_engine_adapters.hpp"   // rngtools::RandBuiltin — the real built-in

static volatile std::uint64_t g_sink;

template <class Gen>
static double MeasureWords(Gen& g, std::uint64_t n) {
    const auto t0 = std::chrono::steady_clock::now();
    std::uint64_t acc = 0;
    for (std::uint64_t i = 0; i < n; ++i) acc ^= g();
    g_sink = acc;
    const std::chrono::duration<double> dt = std::chrono::steady_clock::now() - t0;
    return static_cast<double>(n) / dt.count();
}

template <class Engine>
static double MeasureDoubles(rngsdk::Random<Engine>& r, std::uint64_t n) {
    const auto t0 = std::chrono::steady_clock::now();
    double acc = 0;
    for (std::uint64_t i = 0; i < n; ++i) acc += r.NextDouble();
    g_sink = static_cast<std::uint64_t>(acc);
    const std::chrono::duration<double> dt = std::chrono::steady_clock::now() - t0;
    return static_cast<double>(n) / dt.count();
}

int main(int argc, char** argv) {
    std::uint64_t n = 50'000'000;
    if (argc > 1) n = std::strtoull(argv[1], nullptr, 10);
    const std::uint64_t n_crypto = n / 10;   // DRBG is ~2 orders slower; keep runtime sane

    rngtools::PrintProvenance();
    std::printf("iterations: %llu (crypto rows use n/10)\n\n",
                static_cast<unsigned long long>(n));
    std::printf("%-22s %16s %16s\n", "generator", "uint64/s", "doubles/s");

    {
        rngsdk::Random<rngsdk::Xoshiro256pp> r(1);
        rngsdk::Xoshiro256pp g(1);
        std::printf("%-22s %16.3e %16.3e\n", "xoshiro256++ (ours)", MeasureWords(g, n), MeasureDoubles(r, n));
    }
    {
        rngsdk::Random<rngsdk::Pcg64> r(1);
        rngsdk::Pcg64 g(1);
        std::printf("%-22s %16.3e %16.3e\n", "pcg64 (ours)", MeasureWords(g, n), MeasureDoubles(r, n));
    }
    {
        rngsdk::Random<rngsdk::crypto::HmacDrbgEngine> r(std::uint64_t{1});
        rngsdk::crypto::HmacDrbgEngine g(std::uint64_t{1});
        std::printf("%-22s %16.3e %16.3e\n", "hmac-drbg (ours)", MeasureWords(g, n_crypto), MeasureDoubles(r, n_crypto));
    }
#if defined(RNGSDK_USE_OPENSSL)
    {
        rngsdk::Random<rngsdk::crypto::CtrDrbgEngine> r(std::uint64_t{1});
        rngsdk::crypto::CtrDrbgEngine g(std::uint64_t{1});
        std::printf("%-22s %16.3e %16.3e\n", "ctr-drbg aes-256 (ours)",
                    MeasureWords(g, n_crypto), MeasureDoubles(r, n_crypto));
    }
#endif
    {
        std::mt19937_64 g(1);
        std::printf("%-22s %16.3e %16s\n", "std::mt19937_64", MeasureWords(g, n), "-");
    }
    {
        // The spec's "language built-in", measured through the SAME adapter
        // rng_pi/rng_ode use, so this row and their accuracy rows describe one
        // generator. Note it spends FIVE rand() calls per 64-bit word (see
        // std_engine_adapters.hpp) — so this is the cost of a word as the Monte
        // Carlo tools consume it, not the cost of a single rand() call.
        // Fewer iterations because of that 5x, not because it is a crypto tier.
        const std::uint64_t n_builtin = n / 5;
        rngsdk::Random<rngtools::RandBuiltin> r(std::uint64_t{1});
        rngtools::RandBuiltin g(1);
        std::printf("%-22s %16.3e %16.3e\n", "C rand() (built-in)",
                    MeasureWords(g, n_builtin), MeasureDoubles(r, n_builtin));
    }
    {
        // Kept as an extra data point, NOT as "the language built-in" — that is
        // the row above. std::minstd_rand is a standard-library LCG.
        std::minstd_rand g(1);
        std::printf("%-22s %16.3e %16s\n", "std::minstd_rand", MeasureWords(g, n), "-");
    }
    std::puts("\nThe \"C rand()\" row spends five rand() calls per 64-bit word, which is");
    std::puts("how rng_pi and rng_ode consume it; divide by 5 for a per-rand() cost.");
    std::puts("\nNote: compile with -O2/Release. HMAC-DRBG cost is dominated by two");
    std::puts("SHA-256 compressions per 32-byte block. CTR-DRBG rides AES-NI (build");
    std::puts("-DRNGSDK_USE_OPENSSL=ON to include it; absent from this table");
    std::puts("otherwise).");
    std::puts("");
    std::puts("The CTR-vs-HMAC speedup is deliberately NOT printed here: an honest");
    std::puts("ratio needs the bundled and OpenSSL builds run on the SAME idle box,");
    std::puts("and only one of the two rows exists in either build. See");
    std::puts("docs/benchmark_results.txt, which carries both tables.");
    std::puts("");
    std::puts("MEASUREMENT VALIDITY -- run this on an IDLE machine, >=4 times, and");
    std::puts("report a median with spread. Concurrent load moves these numbers by");
    std::puts("more than the between-engine differences the table exists to show.");
    std::puts("Procedure and the measured idle-vs-loaded spreads are in");
    std::puts("docs/OPEN_RESEARCH.md #7c(a) and #9.");
    return 0;
}
