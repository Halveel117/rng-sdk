// thread_bench.cpp — scalability under multithreading (spec section 6:
// "performance: throughput, memory, scalability (multithreading), results
// across CPU architectures"). OPEN_RESEARCH #9.
//
// rng_bench answers "how fast is one engine on one core". This answers the
// other half: what happens when you run N of them at once. The SDK's whole
// multithreading story is that it has no shared mutable state — every thread
// owns its engine — so throughput should track core count until the cores run
// out. That is a claim about measured behaviour, so it is measured here rather
// than asserted in a document.
//
// Per-thread stream separation, which is what makes "one engine per thread"
// legitimate rather than merely parallel:
//   * xoshiro256++ — thread t calls Jump() t times, landing on a disjoint
//     2^128-long subsequence (Jump/LongJump are pinned to reference vectors in
//     the test suite).
//   * PCG64 — a distinct seed per thread, which SplitMix64-expands into a
//     distinct 128-bit stream selector; PCG64 has 2^127 selectable streams.
//   * HMAC-DRBG / CTR-DRBG — wholly independent instances, distinct seeds.
//
// A stream-separation self-check runs before any timing (see VerifyDistinct).
// Without it, a copy-paste slip that gave every thread the SAME seed would
// still produce a textbook-perfect linear scaling curve — a false artifact
// that no timing assertion could catch.
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include "rngsdk/rngsdk.hpp"
#include "provenance.hpp"
#include "write_csv.hpp"

static std::atomic<std::uint64_t> g_sink{0};

// ---- engine factories: index -> a freshly seeded, independent engine -------

static rngsdk::Xoshiro256pp MakeXoshiro(unsigned t) {
    rngsdk::Xoshiro256pp g(1);
    for (unsigned i = 0; i < t; ++i) g.Jump();
    return g;
}
static rngsdk::Pcg64 MakePcg(unsigned t) { return rngsdk::Pcg64(1000 + t); }
static rngsdk::crypto::HmacDrbgEngine MakeHmac(unsigned t) {
    return rngsdk::crypto::HmacDrbgEngine(std::uint64_t{1000} + t);
}
#if defined(RNGSDK_USE_OPENSSL)
static rngsdk::crypto::CtrDrbgEngine MakeCtr(unsigned t) {
    return rngsdk::crypto::CtrDrbgEngine(std::uint64_t{1000} + t);
}
#endif

// ---- one timed cell -------------------------------------------------------

// Returns aggregate words/sec across `threads` threads, each drawing
// `per_thread` 64-bit words from its own engine.
//
// The spin gate matters: engines are constructed BEFORE the gate opens (DRBG
// instantiation costs a seeding operation) and every thread is parked on it,
// so the clock covers generation only, and thread 1 is not already finishing
// while thread 16 is still being spawned. Without it the 1-thread baseline is
// flattered and every speedup below it understated.
template <class Factory>
static double RunCell(Factory make, unsigned threads, std::uint64_t per_thread) {
    std::atomic<bool> go{false};
    std::atomic<unsigned> ready{0};
    std::vector<std::uint64_t> sinks(threads, 0);
    std::vector<std::thread> pool;
    pool.reserve(threads);

    for (unsigned t = 0; t < threads; ++t) {
        pool.emplace_back([&, t] {
            auto engine = make(t);
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) { /* spin */ }
            std::uint64_t acc = 0;
            for (std::uint64_t i = 0; i < per_thread; ++i) acc ^= engine();
            sinks[t] = acc;   // one store, after the loop — no false sharing while timing
        });
    }
    while (ready.load(std::memory_order_acquire) != threads) std::this_thread::yield();

    const auto t0 = std::chrono::steady_clock::now();
    go.store(true, std::memory_order_release);
    for (auto& th : pool) th.join();
    const std::chrono::duration<double> dt = std::chrono::steady_clock::now() - t0;

    for (std::uint64_t s : sinks) g_sink.fetch_add(s, std::memory_order_relaxed);
    return static_cast<double>(threads) * static_cast<double>(per_thread) / dt.count();
}

static double Median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    const std::size_t n = v.size();
    return (n % 2) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

// ---- stream-separation self-check -----------------------------------------

// Draws the first word from each of the first `threads` engines and fails if
// any two coincide. A collision here means the benchmark below is timing the
// same sequence N times over and reporting it as parallel work.
template <class Factory>
static bool VerifyDistinct(Factory make, unsigned threads) {
    std::vector<std::uint64_t> first;
    first.reserve(threads);
    for (unsigned t = 0; t < threads; ++t) {
        auto engine = make(t);
        first.push_back(engine());
    }
    std::sort(first.begin(), first.end());
    return std::adjacent_find(first.begin(), first.end()) == first.end();
}

// ---- driver ---------------------------------------------------------------

struct Row {
    const char* engine;
    unsigned threads;
    double median, lo, hi;
    double speedup, efficiency;
};

template <class Factory>
static void Benchmark(const char* name, Factory make, const std::vector<unsigned>& counts,
                      std::uint64_t per_thread, unsigned repeats, std::vector<Row>& out) {
    double base = 0;
    bool first = true;
    for (unsigned t : counts) {
        RunCell(make, t, per_thread);  // untimed warm-up, discarded: excludes first-touch/
                                        // thread-creation jitter from the recorded repeats
        std::vector<double> s;
        s.reserve(repeats);
        std::printf("  raw repeats:");
        for (unsigned r = 0; r < repeats; ++r) {
            const double v = RunCell(make, t, per_thread);
            std::printf(" %.3e", v);
            s.push_back(v);
        }
        std::printf("\n");
        const double med = Median(s);
        if (first) { base = med; first = false; }
        const double lo = *std::min_element(s.begin(), s.end());
        const double hi = *std::max_element(s.begin(), s.end());
        const double speedup = med / base;
        out.push_back(Row{name, t, med, lo, hi, speedup, 100.0 * speedup / t});
        std::printf("%-22s %8u %14.3e %10.2fx %9.1f%% %9.2fx\n", name, t, med, speedup,
                    100.0 * speedup / t, hi / lo);
        std::fflush(stdout);
    }
}

static bool ParseU64(const char* s, std::uint64_t& out) {
    if (s == nullptr || *s == 0 || *s == '-') return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != 0 || v == 0) return false;
    out = static_cast<std::uint64_t>(v);
    return true;
}

int main(int argc, char** argv) {
    std::uint64_t n = 50000000;     // words per thread, fast engines
    std::uint64_t repeats = 5;
    const char* csv_path = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--repeats") == 0 && i + 1 < argc) {
            if (!ParseU64(argv[++i], repeats)) {
                std::fprintf(stderr, "bad --repeats (want a positive integer)\n");
                return 2;
            }
        } else if (std::strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (!ParseU64(argv[i], n)) {
            std::fprintf(stderr,
                         "usage: rng_thread_bench [words_per_thread] [--repeats R] [--csv FILE]\n");
            return 2;
        }
    }
    // The two DRBGs are ~25x apart from each other, so one shared divisor would
    // leave the CTR cells running for ~10ms — short enough that thread start-up
    // jitter, not throughput, would decide the number. Each gets a divisor that
    // lands its cells in the 50-400ms band on the hardware we have measured.
    const std::uint64_t n_hmac = n / 25;
#if defined(RNGSDK_USE_OPENSSL)
    const std::uint64_t n_ctr = n / 5;
#endif

    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 1;

    // 1, 2, 4, ... up to the core count, then the core count itself, then 2x it.
    // The oversubscribed row is the cheap one worth having: with no shared state
    // it should degrade gracefully rather than collapse, and a collapse would be
    // evidence of contention we did not know about.
    std::vector<unsigned> counts;
    for (unsigned t = 1; t <= hw; t *= 2) counts.push_back(t);
    if (counts.back() != hw) counts.push_back(hw);
    counts.push_back(2 * hw);

    rngtools::PrintProvenance();
    std::printf("hw_threads: %u (hardware_concurrency)\n", hw);
    std::printf("words:      %llu per thread (hmac rows n/25, ctr rows n/5)\n",
                static_cast<unsigned long long>(n));
    std::printf("repeats:    %llu per cell, median reported\n\n",
                static_cast<unsigned long long>(repeats));

    // Self-check before any timing: independent engines, or the table is fiction.
    const unsigned probe = counts.back();
    const bool distinct = VerifyDistinct(MakeXoshiro, probe) && VerifyDistinct(MakePcg, probe) &&
                          VerifyDistinct(MakeHmac, probe)
#if defined(RNGSDK_USE_OPENSSL)
                          && VerifyDistinct(MakeCtr, probe)
#endif
        ;
    if (!distinct) {
        std::fprintf(stderr, "FATAL: per-thread streams are not distinct -- refusing to report\n");
        return 1;
    }
    std::printf("streams:    distinct across %u threads for every engine (verified)\n\n", probe);

    std::printf("%-22s %8s %14s %11s %10s %10s\n", "engine", "threads", "u64/s (agg)", "speedup",
                "efficiency", "spread");

    std::vector<Row> rows;
    Benchmark("xoshiro256++ (ours)", MakeXoshiro, counts, n, static_cast<unsigned>(repeats), rows);
    Benchmark("pcg64 (ours)", MakePcg, counts, n, static_cast<unsigned>(repeats), rows);
    Benchmark("hmac-drbg (ours)", MakeHmac, counts, n_hmac, static_cast<unsigned>(repeats), rows);
#if defined(RNGSDK_USE_OPENSSL)
    Benchmark("ctr-drbg aes-256 (ours)", MakeCtr, counts, n_ctr, static_cast<unsigned>(repeats),
              rows);
#endif

    std::puts("");
    std::puts("speedup    = median throughput at T threads / median at 1 thread.");
    std::puts("efficiency = speedup / T. 100% is perfectly linear scaling; the last");
    std::puts("             row is deliberately oversubscribed (2x hardware threads)");
    std::puts("             and is EXPECTED to sit near 50% -- that is the scheduler");
    std::puts("             time-slicing, not lock contention. A COLLAPSE there, or");
    std::puts("             efficiency falling off well before the core count, would");
    std::puts("             be the finding worth chasing.");
    std::puts("spread     = max/min across repeats. Treat a cell above ~1.3x as noise-");
    std::puts("             dominated and re-run on an idle machine -- see the load");
    std::puts("             warning in rng_bench and OPEN_RESEARCH #7c(a).");
    std::puts("");
    std::puts("Machines with heterogeneous cores (Apple P/E, Intel P/E) will show");
    std::puts("efficiency sagging once the scheduler starts filling efficiency cores.");
    std::puts("That is the hardware, not the library: report the core split alongside.");

    if (csv_path != nullptr) {
        const bool ok = rngtools::WriteCsv(
            csv_path,
            "engine,threads,median_u64_per_s,min_u64_per_s,max_u64_per_s,speedup,"
            "efficiency_pct,repeats\n",
            [&](std::ostream& f) {
                for (const Row& r : rows)
                    f << r.engine << ',' << r.threads << ',' << r.median << ',' << r.lo << ','
                      << r.hi << ',' << r.speedup << ',' << r.efficiency << ',' << repeats << "\n";
            });
        if (!ok) return 1;
        std::printf("\nwrote %s\n", csv_path);
    }
    return 0;
}
