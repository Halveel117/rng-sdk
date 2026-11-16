// test_main.cpp — known-answer + statistical smoke tests for the prototype.
//
// Layers of validation (weakest claim -> strongest):
//   1. Known-answer: crypto vs FIPS/RFC vectors and independent Python
//      (hashlib/hmac), engines vs NumPy PCG64 / canonical xoshiro. Catches
//      porting bugs exactly.
//   2. Construction properties: determinism, avalanche, nonce monotonicity,
//      commit–reveal round trip.
//   3. Statistical smoke: monobit, byte chi-square, bounded-int chi-square
//      (incl. the classic modulo-bias killer bounds). These are NOT a
//      substitute for NIST SP 800-22 / TestU01 / PractRand — see
//      docs/OPEN_RESEARCH.md.
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "rngsdk/rngsdk.hpp"
#include "golden/golden_values.hpp"
#include "golden/golden_cavp.hpp"
#include "golden/golden_pf_vectors.hpp"
#include "stream_sources.hpp"   // tools/ — the byte-stream tool feeding the batteries
#include "ode_solver.hpp"       // tools/ — the ODE Monte Carlo estimator (item #7)
#include "lcg_smallmul_bad.hpp" // tools/ — second broken control, 2-D lattice defect
#include "std_engine_adapters.hpp" // tools/ — MT19937-64 + rand() for spec 10.3
#include "stability_stats.hpp"     // tools/ — repeats: stability + fitted exponent
#include "rngsdk_c.h"           // c_api/ — the C ABI under test

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        ++g_checks;                                                         \
        if (!(cond)) {                                                      \
            ++g_failures;                                                   \
            std::cout << "FAIL " << __FILE__ << ":" << __LINE__ << "  "     \
                      << #cond << "\n";                                     \
        }                                                                   \
    } while (0)

#define CHECK_EQ(a, b)                                                      \
    do {                                                                    \
        ++g_checks;                                                         \
        const auto va_ = (a);   /* evaluate exactly once — side effects! */ \
        const auto vb_ = (b);                                               \
        if (!(va_ == vb_)) {                                                \
            ++g_failures;                                                   \
            std::cout << "FAIL " << __FILE__ << ":" << __LINE__ << "  "     \
                      << #a << " != " << #b << "\n  lhs=" << va_            \
                      << "\n  rhs=" << vb_ << "\n";                         \
        }                                                                   \
    } while (0)

using namespace rngsdk;
using crypto::Bytes;

// ---------------------------------------------------------------- SHA-256
static void TestSha256() {
    CHECK_EQ(crypto::ToHex(crypto::Sha256::Hash(std::string(""))), std::string(golden::kSha256Empty));
    CHECK_EQ(crypto::ToHex(crypto::Sha256::Hash(std::string("abc"))), std::string(golden::kSha256Abc));
    CHECK_EQ(crypto::ToHex(crypto::Sha256::Hash(std::string(
                 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
             std::string(golden::kSha256TwoBlock));
    // 1M 'a' — exercises multi-block streaming + length bookkeeping.
    crypto::Sha256 s;
    const std::string chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) s.Update(chunk.data(), chunk.size());
    CHECK_EQ(crypto::ToHex(s.Finish()), std::string(golden::kSha256MillionA));
}

// ------------------------------------------------------------ HMAC-SHA256
static void TestHmac() {
    const Bytes k1(20, 0x0b);
    const std::string d1 = "Hi There";
    CHECK_EQ(crypto::ToHex(crypto::HmacSha256(k1.data(), k1.size(), d1.data(), d1.size())),
             std::string(golden::kHmacCase1));   // RFC 4231 case 1
    CHECK_EQ(crypto::ToHex(crypto::HmacSha256(std::string("Jefe"),
                                              std::string("what do ya want for nothing?"))),
             std::string(golden::kHmacCase2));   // RFC 4231 case 2
    const Bytes k6(131, 0xaa);                    // key > block size -> hashed key path
    const std::string d6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    CHECK_EQ(crypto::ToHex(crypto::HmacSha256(k6.data(), k6.size(), d6.data(), d6.size())),
             std::string(golden::kHmacCase6));   // RFC 4231 case 6
}

// -------------------------------------------------------------- HMAC-DRBG
static void TestHmacDrbg() {
    Bytes entropy(32);
    for (int i = 0; i < 32; ++i) entropy[i] = static_cast<std::uint8_t>(i);

    crypto::HmacDrbg drbg;
    drbg.Instantiate(entropy);
    CHECK_EQ(crypto::ToHex(drbg.Generate(64)), std::string(golden::kDrbgGen1));
    CHECK_EQ(crypto::ToHex(drbg.Generate(64)), std::string(golden::kDrbgGen2));
    CHECK_EQ(drbg.ReseedCounter(), 3u);

    crypto::HmacDrbg drbg2;
    const std::string pers = "rngsdk-test-personalization";
    drbg2.Instantiate(entropy, {}, Bytes(pers.begin(), pers.end()));
    const std::string add = "additional-input";
    CHECK_EQ(crypto::ToHex(drbg2.Generate(32, Bytes(add.begin(), add.end()))),
             std::string(golden::kDrbgPersAdd));

    // Entropy floor enforced.
    bool threw = false;
    try { crypto::HmacDrbg bad; bad.Instantiate(Bytes(16, 0xAA)); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw);

    // Engine adapter: convenience seed 42 must match the Python chain.
    crypto::HmacDrbgEngine eng(static_cast<std::uint64_t>(42));
    for (std::uint64_t expected : golden::kDrbgEngineSeed42)
        CHECK_EQ(eng.Next(), expected);
}

// ---------------------------------------------------------------- engines
static void TestXoshiro() {
    Xoshiro256pp x;
    x.SeedState({1, 2, 3, 4});
    for (std::uint64_t expected : golden::kXoshiroState1234) CHECK_EQ(x.Next(), expected);

    Xoshiro256pp x42(42);
    for (std::uint64_t expected : golden::kXoshiroSeed42) CHECK_EQ(x42.Next(), expected);

    // Determinism: same seed, same sequence.
    Xoshiro256pp a(123), b(123);
    for (int i = 0; i < 100; ++i) CHECK_EQ(a.Next(), b.Next());

    // Jump / LongJump against the independent Python transcription (audit
    // finding CA-05). The old test here only asserted that one post-Jump word
    // differed from one un-jumped word, which a completely wrong jump would
    // also satisfy — and LongJump had no coverage at all. The header claims
    // jumped streams are non-overlapping, which is the property per-thread
    // parallel use depends on; that claim rests on DoJump being correct, so it
    // needs a vector, not an inequality.
    Xoshiro256pp j(7);
    j.Jump();
    for (std::uint64_t expected : golden::kXoshiroSeed7Jump) CHECK_EQ(j.Next(), expected);

    Xoshiro256pp lj(7);
    lj.LongJump();
    for (std::uint64_t expected : golden::kXoshiroSeed7LongJump) CHECK_EQ(lj.Next(), expected);

    // Jump and LongJump must land in different places, and neither on the
    // un-jumped stream.
    Xoshiro256pp base(7), jj(7), ll(7);
    jj.Jump();
    ll.LongJump();
    const std::uint64_t b0 = base.Next(), j0 = jj.Next(), l0 = ll.Next();
    CHECK(j0 != b0);
    CHECK(l0 != b0);
    CHECK(j0 != l0);
}

// SplitMix64 is the seed expander for xoshiro256++, and splitmix64.hpp claims
// it is a bijection on uint64 so distinct seeds never collide. That claim is
// load-bearing — MATH_JUSTIFICATION Prop 4.2 uses it to prove the forbidden
// all-zero xoshiro state is unreachable from Seed() — and it had no test at
// all (audit finding CA-06). A bijection cannot be proved by sampling, so this
// checks the falsifiable consequence: no collisions over a large sweep, and
// distinct seeds giving distinct expanded states.
static void TestSplitMix64Injective() {
    // One assertion per property, not one per sample — a sweep that spends
    // 200k checks on the same claim buries the signal in the suite total.
    const std::uint64_t kN = 200000;
    std::set<std::uint64_t> seen;
    for (std::uint64_t i = 0; i < kN; ++i) {
        SplitMix64 sm(i);
        seen.insert(sm.Next());
    }
    CHECK_EQ(seen.size(), static_cast<std::size_t>(kN));   // zero collisions

    // No seed may expand to the forbidden all-zero xoshiro state.
    std::size_t all_zero = 0;
    for (std::uint64_t s = 0; s < 20000; ++s) {
        SplitMix64 sm(s);
        const std::uint64_t w0 = sm.Next(), w1 = sm.Next(), w2 = sm.Next(), w3 = sm.Next();
        if ((w0 | w1 | w2 | w3) == 0) ++all_zero;
    }
    CHECK_EQ(all_zero, static_cast<std::size_t>(0));
}

static void TestPcg64() {
    Pcg64 p;
    p.SeedState({0, 42}, {0, 54});   // pcg-random demo pair, cross-checked vs NumPy
    for (std::uint64_t expected : golden::kPcg64Demo) CHECK_EQ(p.Next(), expected);

    Pcg64 w;
    w.SeedState({0x0123456789abcdefULL, 0xfedcba9876543210ULL},
                {0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL});
    for (std::uint64_t expected : golden::kPcg64Wide) CHECK_EQ(w.Next(), expected);

    Pcg64 a(99), b(99);
    for (int i = 0; i < 100; ++i) CHECK_EQ(a.Next(), b.Next());
}

// -------------------------------------------------------- mapping layer
template <class Engine>
static void TestMapping(const char* name) {
    Random<Engine> rng(static_cast<std::uint64_t>(2026));

    // Doubles in [0,1) with full 53-bit structure.
    double mn = 1.0, mx = 0.0, sum = 0.0;
    const int n = 200000;
    for (int i = 0; i < n; ++i) {
        const double d = rng.NextDouble();
        CHECK(d >= 0.0 && d < 1.0);
        if (d < mn) mn = d;
        if (d > mx) mx = d;
        sum += d;
    }
    const double mean = sum / n;
    CHECK(std::fabs(mean - 0.5) < 0.005);   // ~7.7 sigma for U(0,1) mean
    CHECK(mn < 0.001 && mx > 0.999);

    // Floats in [0,1).
    for (int i = 0; i < 10000; ++i) {
        const float f = rng.NextFloat();
        CHECK(f >= 0.0f && f < 1.0f);
    }

    // Bounded ints: chi-square uniformity on "hostile" bounds — ones where
    // naive % is measurably biased because they don't divide 2^64.
    for (std::uint64_t bound : {3ULL, 5ULL, 6ULL, 7ULL, 10ULL, 12ULL, 100ULL}) {
        std::vector<std::uint64_t> counts(bound, 0);
        const int trials = 120000;
        for (int i = 0; i < trials; ++i) ++counts[rng.NextUInt64(bound)];
        const double expected = static_cast<double>(trials) / bound;
        double chi2 = 0;
        for (auto c : counts) {
            const double d = c - expected;
            chi2 += d * d / expected;
        }
        // df = bound-1 <= 99; chi2 < df + 6*sqrt(2*df) is ~beyond 5-sigma.
        const double df = static_cast<double>(bound - 1);
        CHECK(chi2 < df + 6.0 * std::sqrt(2.0 * df) + 3.0);
    }

    // 32-bit path.
    for (int i = 0; i < 10000; ++i) { CHECK(rng.NextUInt32(97u) < 97u); }

    // NextInt inclusive range hits both endpoints.
    bool lo_hit = false, hi_hit = false;
    for (int i = 0; i < 2000; ++i) {
        const auto v = rng.NextInt(-3, 3);
        CHECK(v >= -3 && v <= 3);
        if (v == -3) lo_hit = true;
        if (v == 3) hi_hit = true;
    }
    CHECK(lo_hit && hi_hit);

    // NextBytes byte-level chi-square.
    std::vector<std::uint8_t> buf(256 * 1024);
    rng.NextBytes(buf.data(), buf.size());
    std::vector<std::uint32_t> bytec(256, 0);
    for (auto b : buf) ++bytec[b];
    const double exp_b = buf.size() / 256.0;
    double chi2b = 0;
    for (auto c : bytec) {
        const double d = c - exp_b;
        chi2b += d * d / exp_b;
    }
    CHECK(chi2b < 255 + 6.0 * std::sqrt(510.0));

    // The NextBytes(n) overload must be the pointer form, not a second
    // implementation: same seed -> byte-identical output. 37 is deliberately
    // not a multiple of 8, so the partial-word tail is in the comparison.
    {
        Random<Engine> a(static_cast<std::uint64_t>(99));
        Random<Engine> b(static_cast<std::uint64_t>(99));
        std::vector<std::uint8_t> ptr_form(37);
        a.NextBytes(ptr_form.data(), ptr_form.size());
        CHECK(b.NextBytes(37) == ptr_form);
        CHECK(b.NextBytes(0).empty());
    }

    // Monobit on raw words.
    std::uint64_t ones = 0;
    const int words = 100000;
    for (int i = 0; i < words; ++i) {
        std::uint64_t x = rng.NextUInt64();
        while (x) { ones += x & 1; x >>= 1; }
    }
    const double bits = 64.0 * words;
    const double z = (2.0 * ones - bits) / std::sqrt(bits);
    CHECK(std::fabs(z) < 5.0);

    std::cout << "  mapping[" << name << "]: mean=" << mean << " monobit z=" << z << "\n";
}

// ------------------------------------------------------------- avalanche
// Spec: one flipped seed bit should flip ~half the output bits.
template <class Engine>
static void TestAvalanche(const char* name) {
    const int seeds = 64, words = 16;
    double total_frac = 0;
    int samples = 0;
    for (int s = 0; s < seeds; ++s) {
        const std::uint64_t base = 0x9E3779B97F4A7C15ULL * (s + 1);
        for (int bit = 0; bit < 64; bit += 7) {
            // Seed explicitly at construction: default-constructing a crypto
            // engine now draws OS entropy + a full Instantiate, which this
            // deterministic test would immediately discard.
            Engine a(base), b(base ^ (1ULL << bit));
            std::uint64_t diff_bits = 0;
            for (int w = 0; w < words; ++w) {
                std::uint64_t d = a.Next() ^ b.Next();
                while (d) { diff_bits += d & 1; d >>= 1; }
            }
            total_frac += static_cast<double>(diff_bits) / (64.0 * words);
            ++samples;
        }
    }
    const double avg = total_frac / samples;
    CHECK(avg > 0.47 && avg < 0.53);
    std::cout << "  avalanche[" << name << "]: " << avg * 100 << "% bits flipped\n";
}

// ---------------------------------------------------------- Provably Fair
static void TestProvablyFair() {
    const std::string server = "s3cret-server-seed", client = "player-seed";
    const std::uint64_t nonce = 7;

    CHECK_EQ(pf::Commitment(server), std::string(golden::kPfCommitment));
    CHECK(pf::VerifyCommitment(server, golden::kPfCommitment));
    CHECK(!pf::VerifyCommitment("s3cret-server-seed2", golden::kPfCommitment));

    // 12 floats crosses the 32-byte HMAC block -> exercises the cursor.
    const auto floats = pf::Generator::NextFloats(server, client, nonce, 12);
    for (int i = 0; i < 12; ++i) CHECK(std::fabs(floats[i] - golden::kPfFloats[i]) < 1e-15);

    // Different nonce -> different results (no replay).
    const auto f8 = pf::Generator::NextFloats(server, client, 8, 12);
    bool any_diff = false;
    for (int i = 0; i < 12; ++i) any_diff |= (f8[i] != floats[i]);
    CHECK(any_diff);

    // Unbiased ints in range and deterministic.
    const auto ints = pf::Generator::NextIntsUnbiased(server, client, nonce, 100, 37);
    const auto ints2 = pf::Generator::NextIntsUnbiased(server, client, nonce, 100, 37);
    CHECK_EQ(ints.size(), 100u);
    for (std::size_t i = 0; i < ints.size(); ++i) {
        CHECK(ints[i] < 37);
        CHECK_EQ(ints[i], ints2[i]);
    }

    // ServerSession protocol: commitment fixed before client seed, nonce
    // strictly monotonic, reveal matches commitment.
    pf::ServerSession session("another-server-seed-with-entropy");
    const std::string commitment = session.CommitmentHex();
    session.SetClientSeed("adversarial-client");
    CHECK_EQ(session.NextNonce(), 0u);
    const auto r0 = session.Play(1);
    const auto r1 = session.Play(1);
    CHECK_EQ(session.NextNonce(), 2u);
    CHECK(r0[0] != r1[0]);
    CHECK(pf::VerifyCommitment(session.Reveal(), commitment));
    // Player-side recomputation reproduces the session's results.
    const auto replay = pf::Generator::NextFloats(session.Reveal(), "adversarial-client", 0, 1);
    CHECK_EQ(replay[0], r0[0]);

    // Generate() is the spec's literal API name and must be exactly the
    // one-outcome case of the generator it aliases — never a second stream.
    CHECK_EQ(pf::Generate(server, client, nonce), floats[0]);
    CHECK(pf::Generate(server, client, nonce) != pf::Generate(server, client, nonce + 1));
}

// Provably Fair vectors from the independent Python implementation
// (tests/golden/generate_pf_vectors.py). The same vectors are embedded in
// web/verifier.html, so a failure here and a failure in the page's self-test
// are the same finding reached from two directions.
//
// Floats are compared EXACTLY. FloatFromBytes sums b/2^8 + b/2^16 + b/2^24 +
// b/2^32; every partial sum is k/2^32 with k < 2^32, which needs 32 mantissa
// bits against the 53 a double has. No rounding occurs at any step, so the
// value is bit-identical across C++, Python and JavaScript — and == is the
// stronger assertion here, not the sloppier one.
static void TestPfGoldenVectors() {
    for (std::size_t i = 0; i < golden_pf::kCommitmentCaseCount; ++i) {
        const auto& c = golden_pf::kCommitmentCases[i];
        CHECK_EQ(pf::Commitment(c.server_seed), std::string(c.commitment));
        CHECK(pf::VerifyCommitment(c.server_seed, c.commitment));
    }

    for (std::size_t i = 0; i < golden_pf::kFloatCaseCount; ++i) {
        const auto& c = golden_pf::kFloatCases[i];
        const auto got = pf::Generator::NextFloats(c.server_seed, c.client_seed,
                                                   c.nonce, c.count);
        CHECK_EQ(got.size(), c.count);
        for (std::size_t j = 0; j < c.count; ++j) CHECK_EQ(got[j], c.expected[j]);
    }

    for (std::size_t i = 0; i < golden_pf::kIntCaseCount; ++i) {
        const auto& c = golden_pf::kIntCases[i];
        const auto got = pf::Generator::NextIntsUnbiased(c.server_seed, c.client_seed,
                                                          c.nonce, c.count, c.bound);
        CHECK_EQ(got.size(), c.count);
        for (std::size_t j = 0; j < c.count; ++j) {
            CHECK_EQ(got[j], c.expected[j]);
            CHECK(got[j] < c.bound);
        }
    }
}

// The web verifier embeds docs/pf_test_vectors.json verbatim, because fetch()
// of a sibling file is blocked by CORS under file:// — the page's primary
// usage mode. Embedding means the two copies can drift, and a drifted page
// still self-tests green, just against the wrong answers. This is the guard.
//
// Carriage returns are stripped before comparing: the two files may be checked
// out with different line endings depending on git configuration, and that is
// not the kind of difference this test exists to catch.
static std::string ReadWholeFile(const std::string& path, bool* ok) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { *ok = false; return {}; }
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    *ok = true;
    return s;
}

static std::string NormalizeVectors(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) if (c != '\r') out += c;
    const auto first = out.find_first_not_of(" \n\t");
    const auto last = out.find_last_not_of(" \n\t");
    if (first == std::string::npos) return {};
    return out.substr(first, last - first + 1);
}

static void TestWebVerifierVectorsInSync() {
    const std::string root = RNGSDK_SOURCE_DIR;
    bool html_ok = false, json_ok = false;
    const std::string html = ReadWholeFile(root + "/web/verifier.html", &html_ok);
    const std::string json = ReadWholeFile(root + "/docs/pf_test_vectors.json", &json_ok);
    CHECK(html_ok);
    CHECK(json_ok);
    if (!html_ok || !json_ok) return;

    const std::string open_tag = "<script type=\"application/json\" id=\"pf-test-vectors\">";
    const std::string close_tag = "</script>";
    const auto a = html.find(open_tag);
    CHECK(a != std::string::npos);
    if (a == std::string::npos) return;
    const auto b = html.find(close_tag, a);
    CHECK(b != std::string::npos);
    if (b == std::string::npos) return;

    const std::string embedded = html.substr(a + open_tag.size(), b - a - open_tag.size());
    CHECK_EQ(NormalizeVectors(embedded), NormalizeVectors(json));
}

// Reveal-lock: once the seed is public every future result is precomputable
// by anyone, so Play() must refuse after Reveal() rather than only saying so
// in a comment. (Ported after review of an independent Python prototype that
// enforces this; ours didn't.)
static void TestRevealLock() {
    pf::ServerSession session("reveal-lock-server-seed-with-entropy");
    session.SetClientSeed("client");
    session.Play(1);           // fine before reveal
    (void)session.Reveal();
    bool threw = false;
    try { session.Play(1); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

// --------------------------------------------- SA-01: nonce replay (critical)
// Re-selecting a client seed that has already been played MUST NOT reproduce
// outcomes the player has already seen. Previously SetClientSeed() reset
// next_nonce_ to 0 with no record of used pairs, so a player could probe with
// minimum stakes, re-select the seed, and bet maximum on the known winners.
// See SECURITY_ANALYSIS.md §5.1.
//
// The fix is that the nonce never resets, so reuse is HARMLESS rather than
// forbidden — nothing has to be remembered for the guarantee to hold.
static void TestClientSeedReuseDoesNotReplay() {
    pf::ServerSession session("a-server-seed-with-ample-entropy-here");
    session.SetClientSeed("player-choice-A");
    double first[5];
    for (int i = 0; i < 5; ++i) first[i] = session.Play(1)[0];

    session.SetClientSeed("player-choice-A");   // the same seed, again
    for (int i = 0; i < 5; ++i) CHECK(session.Play(1)[0] != first[i]);

    // Interleaving a different seed must not rewind the counter either.
    pf::ServerSession s2("a-server-seed-with-ample-entropy-here");
    s2.SetClientSeed("A");
    const double a0 = s2.Play(1)[0];
    s2.SetClientSeed("B");
    s2.Play(1);
    s2.SetClientSeed("A");
    CHECK(s2.Play(1)[0] != a0);
}

// --------------------------------------------------- SA-07: nonce overflow
// Unreachable in practice (2^64 bets), but a silent wrap would be SA-01 again,
// so it must fail loudly rather than be argued safe by arithmetic. The
// start-nonce constructor argument is what makes the boundary reachable in a
// test; it exists because session resumption after a server restart needs it
// (restarting at 0 with the same seed IS the replay bug).
static void TestNonceOverflowRefused() {
    pf::ServerSession session("a-server-seed-with-ample-entropy-here",
                              std::numeric_limits<std::uint64_t>::max());
    session.SetClientSeed("client");
    bool threw = false;
    try { session.Play(1); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw);

    // One below the ceiling is still a legal bet.
    pf::ServerSession ok("a-server-seed-with-ample-entropy-here",
                         std::numeric_limits<std::uint64_t>::max() - 1);
    ok.SetClientSeed("client");
    ok.Play(1);
    CHECK_EQ(ok.NextNonce(), std::numeric_limits<std::uint64_t>::max());
}

// ------------------------------------------- SA-02: weak server seed refused
// The published commitment is a free offline brute-force oracle: enumerate
// candidate seeds, hash, compare. A hand-typed seed falls in seconds, and the
// player then knows every future outcome. Length is a crude proxy for entropy
// — it catches the realistic failure, not a long low-entropy string.
static void TestWeakServerSeedRefused() {
    for (const char* weak : {"", "abc", "server-seed", "0123456789abcdef"}) {
        bool threw = false;
        try { pf::ServerSession session(weak); }
        catch (const std::exception&) { threw = true; }
        CHECK(threw);
    }
    // The supported path must always satisfy its own floor.
    pf::ServerSession good(pf::GenerateServerSeed());
    CHECK(!good.CommitmentHex().empty());
}

// ---------------------------------- SA-03: implicit client seed refused
// A client seed the operator knows at commit time defeats the whole scheme:
// it can grind candidate server seeds and commit to a favourable one. The old
// default of "default" meant an integrator who never called SetClientSeed
// shipped that silently — commitments still verified, replays still checked
// out, and the anti-grinding property was simply absent.
static void TestPlayWithoutClientSeedRefused() {
    pf::ServerSession session("a-server-seed-with-ample-entropy-here");
    bool threw = false;
    try { session.Play(1); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw);

    session.SetClientSeed("explicit");   // and fine once set
    CHECK_EQ(session.Play(1).size(), 1u);
}

// ------------------------------------------------- modulo bias demonstration
// Shows WHY rejection sampling is required: naive % over a deliberately
// truncated 8-bit generator has visible bias that Lemire-style rejection
// removes. (With 2^64 words the naive bias exists but needs ~2^32 samples to
// see; scaling the word size down to 8 bits makes it visible in 200k.)
static void TestModuloBiasDemo() {
    Xoshiro256pp gen(1);
    const std::uint32_t bound = 6;          // dice; 256 % 6 = 4 -> bias
    // Noncentrality: sum((p_i - 1/6)^2 / (1/6)) = 8/2^16 per trial; with 2M
    // trials the naive chi2 concentrates around ~250 while a fair die stays
    // near df=5. Thresholds sit >5 sigma from both distributions.
    const int trials = 2000000;
    std::vector<double> naive(bound, 0), rejected(bound, 0);
    for (int i = 0; i < trials; ++i) {
        const std::uint8_t byte = static_cast<std::uint8_t>(gen.Next() >> 56);
        ++naive[byte % bound];
        // 8-bit rejection: accept only below the largest multiple of 6.
        std::uint8_t r = byte;
        while (r >= 252) r = static_cast<std::uint8_t>(gen.Next() >> 56);
        ++rejected[r % bound];   // % is exact once the range is a multiple of bound
    }
    const double expected = static_cast<double>(trials) / bound;
    double chi2_naive = 0, chi2_rej = 0;
    for (std::uint32_t v = 0; v < bound; ++v) {
        const double dn = naive[v] - expected, dr = rejected[v] - expected;
        chi2_naive += dn * dn / expected;
        chi2_rej += dr * dr / expected;
    }
    // naive: faces 0..3 get 43/256, faces 4..5 get 42/256.
    CHECK(chi2_naive > 100.0);   // glaring bias (expected ~250 at 2M trials)
    CHECK(chi2_rej < 5 + 6.0 * std::sqrt(10.0) + 3.0);
    std::cout << "  modulo-bias demo: naive chi2=" << chi2_naive
              << "  rejection chi2=" << chi2_rej << "\n";
}

// ---------------------------------------------------------------------------
// NIST CAVP known-answer vectors (open item #4). Stronger than the
// cross-implementation golden values: these come from the standards body, so
// they catch a spec misreading shared by both of our implementations.
// Procedure per vector: Instantiate; Generate(n) DISCARDED; Generate(n) == expected.
static Bytes FromHex(const char* hex) {
    Bytes out;
    for (const char* p = hex; p[0] && p[1]; p += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out.push_back(static_cast<std::uint8_t>(nib(p[0]) * 16 + nib(p[1])));
    }
    return out;
}

template <class Drbg, std::size_t N>
static void RunCavp(const golden::CavpVector (&vectors)[N], int returned_bytes) {
    // A truncated regeneration must be loud, not merely a smaller suite.
    static_assert(N == 6, "expected 6 CAVP vectors per section");
    for (const auto& v : vectors) {
        Drbg drbg;
        drbg.Instantiate(FromHex(v.entropy), FromHex(v.nonce), FromHex(v.personalization));
        drbg.Generate(returned_bytes, FromHex(v.additional0));   // discarded per CAVP
        const auto got = drbg.Generate(returned_bytes, FromHex(v.additional1));
        CHECK_EQ(crypto::ToHex(got), std::string(v.returned_bits));
    }
}

static void TestCavpHmacDrbg() {
    RunCavp<crypto::HmacDrbg>(golden::kCavpHmacSha256Plain, golden::kCavpHmacReturnedBytes);
    // Non-empty personalization + additional input: exercises the 0x01 branch
    // of HMAC_DRBG_Update, which the plain vectors never reach.
    RunCavp<crypto::HmacDrbg>(golden::kCavpHmacSha256Full, golden::kCavpHmacReturnedBytes);
}

#if defined(RNGSDK_USE_OPENSSL)
static void TestCavpCtrDrbg() {
    RunCavp<crypto::CtrDrbg>(golden::kCavpCtrAes256NoDfPlain, golden::kCavpCtrReturnedBytes);
    // The section that matters: with a non-empty personalization string, the
    // no-df seed material is entropy XOR pers (SP 800-90A 10.2.1.3.1) -- a
    // concatenating implementation passes the plain vectors and fails these.
    RunCavp<crypto::CtrDrbg>(golden::kCavpCtrAes256NoDfFull, golden::kCavpCtrReturnedBytes);
}

// Engine adapter contract, mirroring the HMAC engine's: explicit seeds are
// reproducible, distinct seeds diverge, and default construction is OS-seeded.
static void TestCtrDrbgEngine() {
    crypto::CtrDrbgEngine a(static_cast<std::uint64_t>(2026));
    crypto::CtrDrbgEngine b(static_cast<std::uint64_t>(2026));
    for (int i = 0; i < 8; ++i) CHECK_EQ(a.Next(), b.Next());

    crypto::CtrDrbgEngine c(static_cast<std::uint64_t>(2027));
    crypto::CtrDrbgEngine d(static_cast<std::uint64_t>(2026));
    CHECK(c.Next() != d.Next());

    const crypto::Bytes seed(48, 0x5A);
    crypto::CtrDrbgEngine e1(seed), e2(seed);
    for (int i = 0; i < 4; ++i) CHECK_EQ(e1.Next(), e2.Next());

    crypto::CtrDrbgEngine os1, os2;                 // OS-seeded, must differ
    CHECK(os1.Next() != os2.Next());

    // Buffer-refill boundary: 4 KiB buffer, so 600 words crosses it.
    crypto::CtrDrbgEngine f1(static_cast<std::uint64_t>(9)), f2(static_cast<std::uint64_t>(9));
    for (int i = 0; i < 600; ++i) CHECK_EQ(f1.Next(), f2.Next());

    // Re-seeding an already-used engine must match a fresh one. Guards the
    // cipher-context re-key path: a stale AES key would still emit plausible
    // bytes, so only an equality check against a fresh engine catches it.
    crypto::CtrDrbgEngine reused(static_cast<std::uint64_t>(1));
    reused.Next();
    reused.Seed(static_cast<std::uint64_t>(77));
    crypto::CtrDrbgEngine fresh(static_cast<std::uint64_t>(77));
    for (int i = 0; i < 4; ++i) CHECK_EQ(reused.Next(), fresh.Next());

    // Movable (so std::vector<CtrRandom> works for per-thread instances);
    // the moved-to engine continues the stream exactly.
    crypto::CtrDrbgEngine src(static_cast<std::uint64_t>(5));
    crypto::CtrDrbgEngine ref(static_cast<std::uint64_t>(5));
    src.Next();
    ref.Next();
    crypto::CtrDrbgEngine moved(std::move(src));
    for (int i = 0; i < 4; ++i) CHECK_EQ(moved.Next(), ref.Next());
    std::vector<CtrRandom> pool;
    pool.emplace_back(std::uint64_t{3});
    pool.emplace_back(std::uint64_t{4});
    CHECK(pool[0].NextUInt64() != pool[1].NextUInt64());
}

// The no-df length contract: entropy must be EXACTLY seedlen. Silently
// zero-padding a short input would instantiate a nominally 256-bit generator
// from less entropy -- the quiet degradation this SDK refuses everywhere.
static void TestCtrDrbgLengthContract() {
    const Bytes good(crypto::CtrDrbg::kSeedLen, 0x11);
    struct Case { Bytes entropy; Bytes nonce; Bytes pers; };
    const Case bad[] = {
        {Bytes(16, 0xAA), {}, {}},                                   // too short
        {Bytes(32, 0xAA), {}, {}},                                   // HMAC-sized, still short
        {Bytes(64, 0xAA), {}, {}},                                   // too long
        {good, Bytes(8, 0x01), {}},                                  // no-df takes no nonce
        {good, {}, Bytes(64, 0x02)},                                 // pers longer than seedlen
    };
    for (const auto& c : bad) {
        bool threw = false;
        try { crypto::CtrDrbg d; d.Instantiate(c.entropy, c.nonce, c.pers); }
        catch (const std::exception&) { threw = true; }
        CHECK(threw);
    }
    // Exactly seedlen, with and without personalization, is accepted.
    crypto::CtrDrbg ok1; ok1.Instantiate(good);
    crypto::CtrDrbg ok2; ok2.Instantiate(good, {}, Bytes(crypto::CtrDrbg::kSeedLen, 0x33));
    CHECK(ok1.Generate(16) != ok2.Generate(16));   // personalization must matter
    CHECK_EQ(ok1.ReseedCounter(), 2u);             // instantiate=1, one Generate -> 2

    // Reseed enforces the same contract.
    bool threw = false;
    try { ok1.Reseed(Bytes(16, 0x44)); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
    ok1.Reseed(Bytes(crypto::CtrDrbg::kSeedLen, 0x44));
    CHECK_EQ(ok1.ReseedCounter(), 1u);             // reseed resets the counter
}
#endif

// ---------------------------------------------------------------------------
// OS entropy sourcing (open item #1). Randomness itself can't be unit-tested,
// but the *contract* can: requested length honored, successive draws differ,
// output not degenerate, and the deterministic seeding paths stay deterministic
// (golden vectors above already pin those byte-exactly).
static void TestOsEntropy() {
    const auto a = crypto::OsEntropy(32);
    CHECK_EQ(a.size(), static_cast<std::size_t>(32));
    const auto b = crypto::OsEntropy(32);
    CHECK_EQ(b.size(), static_cast<std::size_t>(32));
    CHECK(a != b);                       // 2^-256 false-failure probability
    bool nonzero = false;
    for (auto x : a) nonzero |= (x != 0);
    CHECK(nonzero);
    // Length beyond any per-call OS cap (getentropy caps at 256) must chunk.
    CHECK_EQ(crypto::OsEntropy(1024).size(), static_cast<std::size_t>(1024));
    CHECK(crypto::OsEntropy(0).empty());
    // SecureEntropy() is 48 bytes for a specific reason: SP 800-90A §8.6.7
    // permits the nonce to be part of the entropy input, at 3/2 x
    // security_strength = 1.5 * 256 bits = 384 bits = 48 bytes. Do not
    // "optimize" this to 32 — the size IS the standards argument.
    const auto s1 = crypto::SecureEntropy();
    const auto s2 = crypto::SecureEntropy();
    CHECK_EQ(s1.size(), static_cast<std::size_t>(48));
    CHECK(s1 != s2);
    bool all_same = true;                       // stuck/constant-source check
    for (auto x : s1) all_same &= (x == s1[0]);
    CHECK(!all_same);
}

// The Bytes-seed constructor is the production instantiation path (it is what
// SecureEntropy() feeds); it must stay deterministic for a fixed input, which
// is only covered transitively elsewhere.
static void TestBytesSeedDeterminism() {
    const crypto::Bytes seed(48, 0xA5);
    crypto::HmacDrbgEngine e1(seed), e2(seed);
    for (int i = 0; i < 4; ++i) CHECK_EQ(e1.Next(), e2.Next());
    crypto::Bytes other = seed;
    other[47] ^= 0x01;                          // one bit -> different stream
    crypto::HmacDrbgEngine e3(other);
    crypto::HmacDrbgEngine e4(seed);
    CHECK(e3.Next() != e4.Next());
}

static void TestGenerateServerSeed() {
    const std::string s1 = pf::GenerateServerSeed();
    const std::string s2 = pf::GenerateServerSeed();
    CHECK_EQ(s1.size(), static_cast<std::size_t>(64));   // 32 bytes -> 64 hex
    CHECK(s1 != s2);
    bool hex_ok = true;
    for (char c : s1) hex_ok &= (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    CHECK(hex_ok);
    // Usable directly as a session seed with a verifiable commitment.
    pf::ServerSession session(s1);
    CHECK(pf::VerifyCommitment(s1, session.CommitmentHex()));
}

static void TestSecureDefaultConstruction() {
    // Default construction must draw OS entropy, not silently seed with 0:
    // two default-constructed engines must produce different streams.
    crypto::HmacDrbgEngine e1;
    crypto::HmacDrbgEngine e2;
    CHECK(e1.Next() != e2.Next());
    CryptoRandom r1;
    CryptoRandom r2;
    CHECK(r1.NextUInt64() != r2.NextUInt64());
    // Explicit seeding stays deterministic (reproducible-stream API contract).
    crypto::HmacDrbgEngine d1(static_cast<std::uint64_t>(7));
    crypto::HmacDrbgEngine d2(static_cast<std::uint64_t>(7));
    CHECK_EQ(d1.Next(), d2.Next());
}

// --------------------------------------------------- rng_stream (item #3)
// The byte-stream tool that feeds the external batteries (NIST SP 800-22,
// Dieharder, TestU01, PractRand). A defect here would silently invalidate
// every battery result, so the source dispatch is held to the same standard
// as the SDK: each source must equal the SDK API it claims to expose.

static void TestStreamParseByteCount() {
    using rngstream::ParseByteCount;
    CHECK_EQ(ParseByteCount("0"), std::uint64_t{0});
    CHECK_EQ(ParseByteCount("1024"), std::uint64_t{1024});
    CHECK_EQ(ParseByteCount("1K"), std::uint64_t{1024});
    CHECK_EQ(ParseByteCount("1k"), std::uint64_t{1024});
    CHECK_EQ(ParseByteCount("125M"), std::uint64_t{125} * 1024 * 1024);
    CHECK_EQ(ParseByteCount("2G"), std::uint64_t{2} * 1024 * 1024 * 1024);

    // Every rejection below would otherwise produce a battery log that names
    // one run and describes another.
    const char* bad[] = {"", "abc", "12X", "-5", "+5", "1.5M", "M", "1 K", "5G7", "1KK",
                         "0x10", " 7", "7 ",
                         "99999999999999999999999",   // overflows in the digit loop
                         "18446744073709551616",      // UINT64_MAX + 1, exactly
                         "17179869184G"};             // digits fit; x2^30 overflows
    for (const char* s : bad) {
        bool threw = false;
        try { ParseByteCount(s); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    CHECK_EQ(ParseByteCount("18446744073709551615"), UINT64_MAX);   // the boundary itself is fine
    CHECK_EQ(ParseByteCount("16777216G"), std::uint64_t{1} << 54);  // large but legitimate

    // --seed feeds the runbook's adjudication protocol ("re-run with a
    // different --seed"), so it must not use std::stoull, which parses "1abc"
    // as 1 and "-1" as UINT64_MAX without complaint — silently re-running an
    // identical stream while the log records a different seed.
    using rngstream::ParseU64;
    CHECK_EQ(ParseU64("0"), std::uint64_t{0});
    CHECK_EQ(ParseU64("42"), std::uint64_t{42});
    const char* bad_seed[] = {"", "1abc", "-1", "+1", "0x10", " 7", "7 ", "1K", "1.0", "abc"};
    for (const char* s : bad_seed) {
        bool threw = false;
        try { ParseU64(s); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
}

static void TestStreamUnknownSourceRejected() {
    const rngstream::Options opt;
    const char* bad[] = {"", "xoshiro256++", "XOSHIRO", "mt19937", "pcg"};
    for (const char* name : bad) {
        bool threw = false;
        try { rngstream::MakeSource(name, opt); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
}

// A source must emit exactly the bytes of the SDK call it advertises —
// otherwise the batteries test something that is not the shipped API.
template <class Engine>
static void CheckStreamMatchesEngine(const char* source_name) {
    const std::uint64_t seed = 12345;
    rngstream::Options opt;
    opt.seed = seed;
    auto src = rngstream::MakeSource(source_name, opt);

    // 16 KiB, deliberately: the DRBG engine adapters refill a 4 KiB buffer,
    // and a slice replayed instead of refilled is the one defect class CAVP
    // vectors cannot see (they test single Generate calls). A read that fits
    // inside the first buffer would never reach it.
    const std::size_t kSpansSeveralRefills = 16384;
    Bytes from_stream(kSpansSeveralRefills);
    src->Fill(from_stream.data(), from_stream.size());

    Random<Engine> rng(seed);
    Bytes from_sdk(kSpansSeveralRefills);
    rng.NextBytes(from_sdk.data(), from_sdk.size());

    CHECK_EQ(crypto::ToHex(from_stream), crypto::ToHex(from_sdk));
}

// The tool writes in fixed-size buffers, so a source that resets or drops
// state at a buffer boundary would corrupt the stream in a way no single
// Fill() call can reveal. Splitting must be invisible.
static void CheckStreamChunkingInvariant(const char* source_name) {
    rngstream::Options opt;
    opt.seed = 99;

    // Ragged splits that straddle the 8-byte engine word, the 32-byte PF
    // block, the source's own 4 KiB production buffer, and the DRBG adapters'
    // 4 KiB refill. The totals must cross several refills, or the whole test
    // lives inside the first buffer and proves nothing about the boundary.
    const std::size_t splits[] = {1, 7, 24, 32, 33, 96, 107, 4000, 4096, 4351};
    std::size_t total = 0;
    for (std::size_t n : splits) total += n;
    CHECK(total > 3 * 4096);   // the invariant this test's value depends on

    auto whole_src = rngstream::MakeSource(source_name, opt);
    Bytes whole(total);
    whole_src->Fill(whole.data(), whole.size());

    auto split_src = rngstream::MakeSource(source_name, opt);
    Bytes pieced;
    for (std::size_t n : splits) {
        Bytes part(n);
        split_src->Fill(part.data(), part.size());
        pieced.insert(pieced.end(), part.begin(), part.end());
    }
    CHECK_EQ(pieced.size(), whole.size());
    CHECK_EQ(crypto::ToHex(pieced), crypto::ToHex(whole));
}

static void TestStreamSources() {
    CheckStreamMatchesEngine<Xoshiro256pp>("xoshiro");
    CheckStreamMatchesEngine<Pcg64>("pcg64");
    CheckStreamMatchesEngine<crypto::HmacDrbgEngine>("hmac");
#if defined(RNGSDK_USE_OPENSSL)
    CheckStreamMatchesEngine<crypto::CtrDrbgEngine>("ctr");
#endif

    for (const char* s : {"xoshiro", "pcg64", "hmac", "pf", "randu"})
        CheckStreamChunkingInvariant(s);
#if defined(RNGSDK_USE_OPENSSL)
    CheckStreamChunkingInvariant("ctr");
#endif

    // Same seed -> same stream; different seed -> different stream.
    for (const char* s : {"xoshiro", "pcg64", "hmac", "pf", "randu"}) {
        rngstream::Options a;
        a.seed = 4;
        rngstream::Options b;
        b.seed = 5;
        Bytes x(64), y(64), z(64);
        rngstream::MakeSource(s, a)->Fill(x.data(), x.size());
        rngstream::MakeSource(s, a)->Fill(y.data(), y.size());
        rngstream::MakeSource(s, b)->Fill(z.data(), z.size());
        CHECK_EQ(crypto::ToHex(x), crypto::ToHex(y));
        CHECK(crypto::ToHex(x) != crypto::ToHex(z));
    }
}

// The negative control must fail the batteries because of RANDU's lattice
// defect, not because of structurally constant bits. Emitting the raw
// engine word (31 bits top-aligned, 33 zero bits) would fail every battery
// in the first kilobyte and prove nothing about detecting structure — so
// the source emits the top 16 bits of each 31-bit output instead.
static void TestStreamRanduPacking() {
    rngstream::Options opt;
    opt.seed = 1;
    auto src = rngstream::MakeSource("randu", opt);
    // RANDU ramps up slowly from a small seed (the first outputs are 6, 36,
    // 162, ...), so a short sample would leave the high lane all-zero and the
    // constant-bit check below would fail for a reason that is not a defect.
    Bytes got(4096);
    src->Fill(got.data(), got.size());

    // Independent transcription of RANDU from its definition. Note this pins
    // the implementation rather than validating the seeding *choice* — the
    // assertion with teeth against the old non-injective `| 1` seeding is the
    // seed-4-vs-5 comparison in TestStreamSources.
    std::uint64_t state = 2 * (opt.seed % 0x40000000ull) + 1;
    Bytes want;
    while (want.size() < got.size()) {
        state = (state * 65539ull) % 0x80000000ull;
        const std::uint32_t top16 = static_cast<std::uint32_t>(state >> 15);  // 31 -> 16 bits
        want.push_back(static_cast<std::uint8_t>(top16 >> 8));
        want.push_back(static_cast<std::uint8_t>(top16 & 0xFF));
    }
    CHECK_EQ(crypto::ToHex(got), crypto::ToHex(want));

    // No bit position may be constant across the stream — the property the
    // raw-word layout would have violated. The two byte lanes must be
    // accumulated SEPARATELY: OR-ing them together lets a constant bit in one
    // lane be masked by the other, so a plausible off-by-one (`>> 16`, which
    // yields 15 bits and pins bit 7 of every high byte to 0) would pass.
    std::uint8_t ones[2] = {0, 0}, zeros[2] = {0, 0};
    for (std::size_t i = 0; i < got.size(); ++i) {
        ones[i % 2] |= got[i];
        zeros[i % 2] |= static_cast<std::uint8_t>(~got[i]);
    }
    for (int lane = 0; lane < 2; ++lane) {
        CHECK_EQ(static_cast<int>(ones[lane]), 0xFF);
        CHECK_EQ(static_cast<int>(zeros[lane]), 0xFF);
    }
}

// The Provably Fair source must exercise the nonce path, not the cursor
// path: correlation between adjacent nonces is the defect that would matter,
// and streaming one nonce's cursor forever would never reach it.
static void TestStreamProvablyFairLayout() {
    rngstream::Options opt;
    opt.seed = 7;
    opt.pf_bytes_per_nonce = 32;
    auto src = rngstream::MakeSource("pf", opt);

    Bytes got(96);
    src->Fill(got.data(), got.size());

    const std::string server = rngstream::ServerSeedForStream(opt.seed);
    const std::string client = rngstream::kStreamClientSeed;
    for (std::uint64_t nonce = 0; nonce < 3; ++nonce) {
        const std::string msg = client + ":" + std::to_string(nonce) + ":0";
        const auto mac = crypto::HmacSha256(server.data(), server.size(), msg.data(), msg.size());
        const Bytes want(mac.begin(), mac.end());
        const Bytes slice(got.begin() + static_cast<std::ptrdiff_t>(nonce * 32),
                          got.begin() + static_cast<std::ptrdiff_t>(nonce * 32 + 32));
        CHECK_EQ(crypto::ToHex(slice), crypto::ToHex(want));
    }

    // A per-nonce budget above one HMAC block must advance the cursor within
    // the nonce before moving on, so both paths stay reachable.
    rngstream::Options wide = opt;
    wide.pf_bytes_per_nonce = 48;
    auto wide_src = rngstream::MakeSource("pf", wide);
    Bytes wide_got(48);
    wide_src->Fill(wide_got.data(), wide_got.size());
    const std::string msg1 = client + ":0:1";
    const auto mac1 = crypto::HmacSha256(server.data(), server.size(), msg1.data(), msg1.size());
    const Bytes tail(wide_got.begin() + 32, wide_got.end());
    CHECK_EQ(crypto::ToHex(tail), crypto::ToHex(Bytes(mac1.begin(), mac1.begin() + 16)));

    // Distinct seeds must yield distinct server seeds (else every "different
    // seed" run in the matrix would be the same run).
    CHECK(rngstream::ServerSeedForStream(1) != rngstream::ServerSeedForStream(2));
    CHECK_EQ(rngstream::ServerSeedForStream(1).size(), std::size_t{64});
}

// Cross-platform determinism pin. The batteries run on a collaborator's Linux
// box built with g++; development is Windows/MSVC. If the two builds disagree,
// every returned log is unattributable — so the same constants live in
// docs/statistical_results/fingerprints.txt for the remote side to compare
// against, and here so our side cannot drift unnoticed. Doubles as the
// cross-compiler determinism evidence open item #9 needs.
static void TestStreamFingerprints() {
    struct Fingerprint { const char* source; const char* hex; };
    static const Fingerprint kPins[] = {
        {"xoshiro", "9bc2036f7fd0c5cf8de03f96324142bf20f5aa57577da319d656cd059f1108bf"},
        {"pcg64",   "d61266d7f9b5a7534286896f3e437f634098f91b6dc86527b0219ceb38d31e78"},
        {"hmac",    "2db283af2967306f9f16b8285fef7c389266af5402dc5347a3f7e54c804bc3b6"},
        {"pf",      "f907af13077cc2450cbb6bb5ba108cc5349f52d634119dc6f7521955ad54e00b"},
        {"randu",   "0006002400a20288097e222c779a9a1067f7053977a29ec883ff82f16dabf785"},
#if defined(RNGSDK_USE_OPENSSL)
        {"ctr",     "68237f540cd9270ee6e8d5e1e226aeb913d3ea94604be9ebc6127761c333dd65"},
#endif
    };
    for (const auto& pin : kPins) {
        rngstream::Options opt;   // seed 1, 32 bytes per nonce — the documented defaults
        Bytes got(32);
        rngstream::MakeSource(pin.source, opt)->Fill(got.data(), got.size());
        CHECK_EQ(crypto::ToHex(got), std::string(pin.hex));
    }
}

// ------------------------------------------------------- ODE Monte Carlo
// Layer 1 of the two-layer strategy in the design spec
// (docs/design/2026-08-24-ode-monte-carlo-design.md §5):
// deterministic checks with NO generator involved. Their whole purpose is
// attribution — if these pass and the statistical layer fails, the fault is
// the RNG and not the derivation.
//
//   Neumann series == Taylor series of sin  -> TestOdeNeumannSeries
//   inverse-CDF sampler inverts its own CDF -> TestOdeSampler
//   walk arithmetic, scripted uniforms      -> TestOdeWalkScripted
static void TestOdeNeumannSeries() {
    // K^n f(x) = (-1)^n x^(2n+1)/(2n+1)!  — proved by induction in the spec §2.2.
    const double x = 1.3;
    CHECK(std::fabs(rngtools::NeumannTerm(0, x) - x) < 1e-15);
    CHECK(std::fabs(rngtools::NeumannTerm(1, x) - (-(x * x * x) / 6.0)) < 1e-15);
    CHECK(std::fabs(rngtools::NeumannTerm(2, x) - std::pow(x, 5) / 120.0) < 1e-15);
    CHECK(std::fabs(rngtools::NeumannTerm(3, x) - (-std::pow(x, 7) / 5040.0)) < 1e-15);

    // The partial sums are therefore sin's Taylor polynomials, so they must
    // converge to sin. This is the identity the whole estimator rests on.
    for (double t : {0.1, 0.5, 1.0, 1.5707963267948966, 3.141592653589793})
        CHECK(std::fabs(rngtools::NeumannPartialSum(25, t) - std::sin(t)) < 1e-13);
}

static void TestOdeSampler() {
    // p(t|x) = 2(x-t)/x^2 has CDF F(t) = (2xt - t^2)/x^2; the sampler is F^-1.
    const double x = 2.0;
    CHECK(std::fabs(rngtools::SampleT(x, 0.0) - 0.0) < 1e-15);
    CHECK(std::fabs(rngtools::SampleT(x, 1.0) - x) < 1e-15);
    for (double u : {0.05, 0.25, 0.5, 0.75, 0.95}) {
        const double t = rngtools::SampleT(x, u);
        CHECK(t >= 0.0 && t <= x);
        CHECK(std::fabs((2.0 * x * t - t * t) / (x * x) - u) < 1e-12);   // F(F^-1(u)) == u
    }

    // The check above compares SampleT against an F written here in the test,
    // so a consistent p/F mismatch would satisfy both and still be wrong. This
    // closes that by recovering the DENSITY numerically: dF/du at u gives
    // dt/du, and p(t) = 1/(dt/du) must equal 2(x-t)/x^2 — the density the
    // importance-sampling cancellation in ode_solver.hpp actually assumes.
    const double h = 1e-6;
    for (double u : {0.2, 0.5, 0.8}) {
        const double t = rngtools::SampleT(x, u);
        const double dtdu = (rngtools::SampleT(x, u + h) - rngtools::SampleT(x, u - h)) / (2 * h);
        CHECK(dtdu > 0.0);
        CHECK(std::fabs(1.0 / dtdu - 2.0 * (x - t) / (x * x)) < 1e-6);
    }
}

// 8-point Gauss–Legendre on [0,1]: exact for polynomials to degree 15, which
// covers every depth this test uses.
static const double kGl8X[] = {0.0198550717512319, 0.1016667612931866,
                               0.2372337950418355, 0.4082826787521751,
                               0.5917173212478249, 0.7627662049581645,
                               0.8983332387068134, 0.9801449282487681};
static const double kGl8W[] = {0.0506142681451881, 0.1111905172266872,
                               0.1568533229389436, 0.1813418916891810,
                               0.1813418916891810, 0.1568533229389436,
                               0.1111905172266872, 0.0506142681451881};

// E[S(x)] truncated at depth D, evaluated deterministically by quadrature
// through the SAME SampleT and WalkWeight the random walk calls.
//
// Substituting u = 1 − v² turns SampleT into the smooth map x(1−v) and makes
// the integrand a polynomial, so Gauss–Legendre is exact. The roulette
// probability cancels (q · W/q = W), which is why no q appears here — and is
// itself a check that the 1/q compensation is right.
static double ExpectedScoreByQuadrature(int depth, double x) {
    if (depth == 0) return x;
    double acc = 0.0;
    for (int i = 0; i < 8; ++i) {
        const double v = kGl8X[i];
        const double t = rngtools::SampleT(x, 1.0 - v * v);
        acc += kGl8W[i] * 2.0 * v * ExpectedScoreByQuadrature(depth - 1, t);
    }
    return x + rngtools::WalkWeight(x) * acc;
}

// Closes the gap that made the spec's attribution claim unfounded: every other
// Layer-1 test checks NeumannTerm/NeumannPartialSum, which share no code with
// the estimator, so a mismatched sampler/weight pair would pass them all. This
// one integrates the ACTUAL walk machinery and asserts it reproduces the
// analytic Neumann partial sums — the only test that can catch a derivation
// error before it is misattributed to the RNG.
static void TestOdeExpectationMatchesSeries() {
    for (double x : {0.3, 0.9, 1.5707963267948966}) {
        for (int d = 0; d <= 5; ++d) {
            const double quad = ExpectedScoreByQuadrature(d, x);
            const double series = rngtools::NeumannPartialSum(d, x);
            CHECK(std::fabs(quad - series) < 1e-12);
        }
    }
}

// Deterministic (no RNG) check that ForcedWalkTerm's expectation is the
// isolated Neumann term Kᵈf(x), not the partial sum — a structurally
// different quadrature than ExpectedScoreByQuadrature above (no "+x" base
// added per level; only the deepest value propagates). Exists so the depth
// decomposition diagnostic in rng_ode (used to localize where an RNG
// defect's bias concentrates) rests on a proven-correct estimator.
static double TermByQuadrature(int depth, double x) {
    if (depth == 0) return x;
    double acc = 0.0;
    for (int i = 0; i < 8; ++i) {
        const double v = kGl8X[i];
        const double t = rngtools::SampleT(x, 1.0 - v * v);
        acc += kGl8W[i] * 2.0 * v * TermByQuadrature(depth - 1, t);
    }
    return rngtools::WalkWeight(x) * acc;
}

static void TestOdeForcedWalkTermMatchesNeumannTerm() {
    for (double x : {0.3, 0.9, 1.5707963267948966})
        for (int d = 0; d <= 5; ++d)
            CHECK(std::fabs(TermByQuadrature(d, x) - rngtools::NeumannTerm(d, x)) < 1e-12);
}

static void TestOdeWalkScripted() {
    // Scripted uniforms make the walk fully deterministic, so the score is
    // hand-computable. Consumption order per step is roulette-then-position;
    // survival is u < q.
    struct Scripted {
        std::vector<double> vals;
        std::size_t i = 0;
        double operator()() { return i < vals.size() ? vals[i++] : 1.0; }
    };
    const double q = 0.5, x = 1.0;

    // Roulette fails immediately -> score is just f(x) = x.
    Scripted die{{0.9}};
    CHECK(std::fabs(rngtools::OdeWalkScore(die, x, q) - 1.0) < 1e-15);

    // Survive once (0.1 < q), jump with u=0.75 -> t = x(1 - sqrt(1-u)) = 0.5,
    // then die. W(x) = -x^2/2 = -0.5, so W/q = -1 and the score is
    // f(x) + (W/q)*f(t) = 1.0 - 0.5 = 0.5.
    Scripted one{{0.1, 0.75, 0.9}};
    CHECK(std::fabs(rngtools::OdeWalkScore(one, x, q) - 0.5) < 1e-15);

    // A TWO-survival walk. Without this the running weight product is never
    // exercised: with at most one jump, `weight *= ...` and `weight = ...` are
    // indistinguishable, so a mutation destroying the entire Neumann product
    // structure passes the two cases above. Verified by mutation testing.
    //   step 1: W(1.0)/q = -1.0,   t = 0.5   -> score 1.0 - 0.5      = 0.5
    //   step 2: weight *= W(0.5)/q = -0.25   -> weight = +0.25
    //           t = 0.25                     -> score 0.5 + 0.0625   = 0.5625
    Scripted two{{0.1, 0.75, 0.1, 0.75, 0.9}};
    CHECK(std::fabs(rngtools::OdeWalkScore(two, x, q) - 0.5625) < 1e-15);
}

// sigma_hat is the denominator of every acceptance criterion in the spec and
// of every CI in the results CSV, yet TestOdeConvergence cannot police it: a
// bug that INFLATES m2 widens that test's own tolerance and passes, while
// silently making every reported interval too wide. This cross-checks Welford
// against a naive two-pass variance over the identical score sequence.
static void TestOdeWelfordMatchesTwoPass() {
    struct Scripted {
        std::vector<double> vals;
        std::size_t i = 0;
        double operator()() { return vals[i++ % vals.size()]; }
    };
    // A short repeating cycle whose length is coprime with the per-walk draw
    // count, so the scores genuinely vary rather than repeating one value.
    const std::vector<double> cycle{0.11, 0.83, 0.42, 0.07, 0.66, 0.29, 0.95};
    const double x = 1.1, q = 0.5;
    const std::uint64_t n = 500;

    Scripted a{cycle};
    const auto est = rngtools::EstimateY(a, x, n, q);

    Scripted b{cycle};
    std::vector<double> scores;
    for (std::uint64_t i = 0; i < n; ++i) scores.push_back(rngtools::OdeWalkScore(b, x, q));

    double sum = 0.0;
    for (double s : scores) sum += s;
    const double mean = sum / static_cast<double>(n);
    double ss = 0.0;
    for (double s : scores) ss += (s - mean) * (s - mean);
    const double var = ss / static_cast<double>(n - 1);

    CHECK(std::fabs(est.mean - mean) < 1e-12);
    CHECK(std::fabs(est.stddev - std::sqrt(var)) < 1e-10);
    CHECK(est.stddev > 1e-6);   // the sequence must actually vary, or this proves nothing
}

// Layer 2 of the spec's §5 strategy: statistical. With a sound engine the
// sample mean must land inside the interval its OWN measured sigma predicts.
//
// The tolerance is derived from the run rather than hardcoded, which is the
// point: since the estimator's bias is exactly zero (spec §2.4), a fixed
// threshold would test nothing but our guess at the variance. 5 sigma at a
// fixed seed keeps this a deterministic regression test rather than a flaky
// one, while still failing loudly if the estimator or the engine regresses.
static void TestOdeConvergence() {
    Random<Xoshiro256pp> rng(20260824);
    auto u01 = [&rng] { return rng.NextDouble(); };
    for (double x : {0.5, 1.0, 1.5707963267948966}) {
        const auto est = rngtools::EstimateY(u01, x, 200000, 0.5);
        CHECK_EQ(est.n, static_cast<std::uint64_t>(200000));
        CHECK(est.stddev > 0.0 && std::isfinite(est.stddev));
        CHECK(std::fabs(est.stderr_mean - est.stddev / std::sqrt(200000.0)) < 1e-15);
        CHECK(std::fabs(est.mean - std::sin(x)) < 5.0 * est.stderr_mean);
    }
}

// The load-bearing claim in lcg_smallmul_bad.hpp, checked rather than
// asserted: conditioned on the walk's roulette draw surviving (u1 < q), the
// NEXT uniform is not uniform. For q = 0.5, u2 = frac(5*u1) puts 60% of its
// mass below 0.5 instead of 50% — three of the five lattice lines land there.
// That skew is the entire mechanism by which rng_ode's estimate is biased,
// so if this test fails the second control demonstrates nothing.
static void TestSmallMultiplierLcgPairSkew() {
    Random<rngtools::SmallMultiplierLcg> rng(12345);
    std::uint64_t survived = 0, low = 0;
    for (int i = 0; i < 400000; ++i) {
        const double u1 = rng.NextDouble();
        const double u2 = rng.NextDouble();
        if (u1 < 0.5) { ++survived; if (u2 < 0.5) ++low; }
    }
    CHECK(survived > 190000);   // ~half the draws, sanity on the loop itself
    CHECK(std::fabs(static_cast<double>(low) / survived - 0.6) < 0.01);

    // Each output is marginally uniform, which is why a one-value-at-a-time
    // test cannot see the defect. Contrast with the pair skew above.
    Random<rngtools::SmallMultiplierLcg> m(999);
    std::uint64_t below = 0;
    for (int i = 0; i < 400000; ++i) if (m.NextDouble() < 0.5) ++below;
    CHECK(std::fabs(static_cast<double>(below) / 400000.0 - 0.5) < 0.01);
}

// Mt19937_64Adapter must be bit-identical to raw std::mt19937_64, or it isn't
// actually comparing against Mersenne Twister — it's comparing against a
// silent reimplementation of it.
static void TestMt19937Adapter() {
    for (std::uint64_t seed : {1ull, 42ull, 0xdeadbeefull}) {
        std::mt19937_64 ref(seed);
        rngtools::Mt19937_64Adapter adapt(seed);
        for (int i = 0; i < 1000; ++i) CHECK_EQ(adapt.Next(), ref());
    }
}

// RandBuiltin holds process-global state (documented in the header), so this
// only checks the two observable properties that global state still permits:
// distinct seeds visibly change the stream, and Next() is not degenerate.
static void TestRandBuiltinVaries() {
    rngtools::RandBuiltin a(1);
    const std::uint64_t v1 = a.Next();
    rngtools::RandBuiltin b(2);
    const std::uint64_t v2 = b.Next();
    CHECK(v1 != v2);

    std::set<std::uint64_t> seen;
    rngtools::RandBuiltin c(7);
    for (int i = 0; i < 1000; ++i) seen.insert(c.Next());
    CHECK(seen.size() > 900);   // allow a handful of coincidental repeats
}

// Regression for the bug the earlier construction had: masking rand()'s
// output to a fixed 16-bit width, when MSVC's RAND_MAX is only 15 bits,
// forced the top bit of every Next() to 0. Since NextDouble() reads the top
// bits first, u01() was < 0.5 on EVERY call, which hangs OdeWalkScore's
// roulette check outright (never u >= 0.5). This asserts the top bit of
// Next() varies, which the old construction fails deterministically.
static void TestRandBuiltinSpansAboveHalf() {
    rngtools::RandBuiltin r(20260824);
    bool saw_high = false;
    for (int i = 0; i < 200 && !saw_high; ++i)
        if (r.Next() & (1ull << 63)) saw_high = true;
    CHECK(saw_high);
}

// ---- stability + convergence-exponent statistics (OPEN_RESEARCH #7c(c),(d)) --
//
// Every expected value below is hand-computed from the definition, NOT read
// off the implementation, and each test was mutation-checked (see the audit
// note in the commit): flipping the Bessel divisor, dropping the t-table, or
// making RepeatSeed non-injective each breaks at least one of them.

static void TestStabilityAggregateHandComputed() {
    // estimates {1,2,3,4,5}, exact 3.  mean = 15/5 = 3, so bias = 0.
    // deviations from mean: -2,-1,0,1,2 -> squares sum to 10.
    //   sample sd = sqrt(10/4) = sqrt(2.5)
    //   rms_err   = sqrt(10/5) = sqrt(2)
    const std::vector<double> est = {1.0, 2.0, 3.0, 4.0, 5.0};
    const auto s = rngtools::Aggregate(est, 3.0);
    CHECK_EQ(s.repeats, 5);
    CHECK(std::fabs(s.mean - 3.0) < 1e-12);
    CHECK(std::fabs(s.bias - 0.0) < 1e-12);
    CHECK(std::fabs(s.sd - std::sqrt(2.5)) < 1e-12);
    CHECK(std::fabs(s.rms_err - std::sqrt(2.0)) < 1e-12);
}

static void TestStabilityBiasVarianceDecomposition() {
    // The claim the whole repeats experiment rests on:
    //     rms_err^2 == bias^2 + sd^2 * (R-1)/R
    // estimates {2,4}, exact 1 -> mean 3, bias 2, sd sqrt(2), rms sqrt(5).
    // Check: 5 == 4 + 2*(1/2) = 5.
    const std::vector<double> est = {2.0, 4.0};
    const auto s = rngtools::Aggregate(est, 1.0);
    CHECK(std::fabs(s.mean - 3.0) < 1e-12);
    CHECK(std::fabs(s.bias - 2.0) < 1e-12);
    CHECK(std::fabs(s.sd - std::sqrt(2.0)) < 1e-12);
    CHECK(std::fabs(s.rms_err - std::sqrt(5.0)) < 1e-12);
    const double lhs = s.rms_err * s.rms_err;
    const double rhs = s.bias * s.bias + s.sd * s.sd * (s.repeats - 1) / s.repeats;
    CHECK(std::fabs(lhs - rhs) < 1e-12);

    // Bias must keep its SIGN. LCG5's 2-D pi estimate sits BELOW pi (3.088)
    // while its 3-D estimate sits ABOVE (3.264), so the direction of the error
    // is real information about the defect, not a magnitude to be discarded.
    // Added because a mutation making bias unsigned survived the two cases
    // above (bias 0 and bias +2, where |x| = x).
    // estimates {1,2}, exact 5 -> mean 1.5, bias -3.5, sd sqrt(0.5),
    // rms sqrt(12.5); identity: 12.5 == 12.25 + 0.5*0.5.
    const auto neg = rngtools::Aggregate({1.0, 2.0}, 5.0);
    CHECK(std::fabs(neg.bias - (-3.5)) < 1e-12);
    CHECK(neg.bias < 0.0);
    CHECK(std::fabs(neg.sd - std::sqrt(0.5)) < 1e-12);
    CHECK(std::fabs(neg.rms_err - std::sqrt(12.5)) < 1e-12);
    const double nlhs = neg.rms_err * neg.rms_err;
    const double nrhs = neg.bias * neg.bias + neg.sd * neg.sd * (neg.repeats - 1) / neg.repeats;
    CHECK(std::fabs(nlhs - nrhs) < 1e-12);
}

static void TestSlopeFitRecoversMinusOneHalf() {
    // y = 100 * x^(-1/2) exactly -- the O(1/sqrt(N)) law spec 10.1 asks us to
    // confirm. A noiseless power law must return the exponent exactly, and
    // with zero residual the interval collapses to a point.
    const std::vector<double> xs = {1e4, 1e5, 1e6, 1e7};
    std::vector<double> ys;
    for (double x : xs) ys.push_back(100.0 / std::sqrt(x));
    const auto f = rngtools::FitLogLogSlope(xs, ys);
    CHECK(f.valid);
    CHECK_EQ(f.df, 2);
    CHECK(std::fabs(f.slope + 0.5) < 1e-12);
    CHECK(std::fabs(f.ci_hi - f.ci_lo) < 1e-9);
}

static void TestSlopeFitFlatSeriesIsZero() {
    // An error FLOOR -- what LCG5 and RANDU show. Slope 0, not -1/2, is the
    // signature that separates "converging" from "converged to the wrong value".
    const std::vector<double> xs = {1e4, 1e5, 1e6, 1e7};
    const std::vector<double> ys = {0.05, 0.05, 0.05, 0.05};
    const auto f = rngtools::FitLogLogSlope(xs, ys);
    CHECK(f.valid);
    CHECK(std::fabs(f.slope) < 1e-12);
}

static void TestSlopeFitWidensIntervalWithScatter() {
    // Same slope, but perturbed off the line: the point estimate must stay
    // near -1/2 while the interval opens up. Guards against an implementation
    // that reports a CI without ever using the residuals.
    const std::vector<double> xs = {1e4, 1e5, 1e6, 1e7};
    std::vector<double> ys;
    const double bump[] = {1.20, 0.85, 1.15, 0.90};
    for (int i = 0; i < 4; ++i) ys.push_back(bump[i] * 100.0 / std::sqrt(xs[i]));
    const auto f = rngtools::FitLogLogSlope(xs, ys);
    CHECK(f.valid);
    CHECK(std::fabs(f.slope + 0.5) < 0.15);
    CHECK(f.ci_hi - f.ci_lo > 1e-3);          // genuinely wider than the exact fit
    CHECK(f.ci_lo < -0.5 && f.ci_hi > -0.5);  // and it covers the truth

    // Pin the ACTUAL width, hand-computed, or the t-table goes untested: with
    // df = 2 the normal 1.96 understates the interval by 2.2x, and the interval
    // is the deliverable for spec 10.1. A first version of this test asserted
    // only "> 1e-3 and covers -0.5", and a mutation replacing the t-table with
    // 1.96 SURVIVED it. Worked out by hand from lx = {4,5,6,7}:
    //   sxx = 5, slope = -0.52435, sse = 0.0139253,
    //   se   = sqrt((sse/2)/5) = 0.0373166,
    //   half = t(0.975, df=2) * se = 4.303 * 0.0373166 = 0.16057.
    CHECK(std::fabs(f.slope - (-0.524354)) < 1e-5);
    CHECK(std::fabs((f.ci_hi - f.slope) - 0.160573) < 1e-4);
}

static void TestTCriticalTable() {
    // Guards the table itself. df = 2 is the case every fit in this project
    // actually uses (four N values), and it is the one where using the normal
    // approximation would be most wrong.
    CHECK(std::fabs(rngtools::TCritical95(1) - 12.706) < 1e-9);
    CHECK(std::fabs(rngtools::TCritical95(2) - 4.303) < 1e-9);
    CHECK(std::fabs(rngtools::TCritical95(10) - 2.228) < 1e-9);
    CHECK(std::fabs(rngtools::TCritical95(50) - 1.959964) < 1e-9);  // falls back to normal
    // Monotone decreasing toward the normal limit, and never below it.
    for (int df = 1; df <= 10; ++df) {
        CHECK(rngtools::TCritical95(df) >= 1.959964);
        CHECK(rngtools::TCritical95(df) >= rngtools::TCritical95(df + 1) - 1e-12);
    }
}

static void TestSlopeFitRejectsBadInput() {
    const std::vector<double> two_x = {1e4, 1e5};
    const std::vector<double> two_y = {1.0, 0.5};
    CHECK(!rngtools::FitLogLogSlope(two_x, two_y).valid);   // df would be 0

    const std::vector<double> xs = {1e4, 1e5, 1e6};
    const std::vector<double> has_zero = {1.0, 0.0, 0.1};   // log10(0) undefined
    CHECK(!rngtools::FitLogLogSlope(xs, has_zero).valid);

    const std::vector<double> flat_x = {1e5, 1e5, 1e5};     // sxx == 0
    const std::vector<double> ys = {1.0, 0.5, 0.25};
    CHECK(!rngtools::FitLogLogSlope(flat_x, ys).valid);

    const std::vector<double> mismatched = {1.0, 0.5};
    CHECK(!rngtools::FitLogLogSlope(xs, mismatched).valid);
}

static void TestRepeatSeedsAreInjective() {
    // Two "independent" repeats that silently share a seed are the same run
    // twice -- and the resulting spread would be an underestimate with no
    // symptom. RanduBad::Seed had exactly this defect until 2026-08-18.
    const std::uint64_t base = 20260702;
    std::set<std::uint64_t> seen;
    for (int r = 0; r < 25; ++r)
        for (int e = 4; e <= 8; ++e)
            seen.insert(rngtools::RepeatSeed(base, r, e));
    CHECK_EQ(static_cast<int>(seen.size()), 25 * 5);

    // ...and none of them collides with the baseline single-run seed base+e,
    // so a stability run never silently re-runs the committed trial.
    for (int e = 4; e <= 8; ++e)
        CHECK(seen.find(base + static_cast<std::uint64_t>(e)) == seen.end());

    CHECK_EQ(rngtools::RepeatSeed(base, 0, 4), base + 1000003ULL + 4ULL);
}

static void TestGridSlotBasesAreDisjoint() {
    // The defect this pins: rng_ode's stability run originally seeded both of
    // its grid points with RepeatSeed(base, r, e) -- no dependence on x. The
    // ODE walk's roulette test (u01() >= q) is also x-independent, so the two
    // "independent" grid points consumed a BIT-IDENTICAL uniform stream and
    // differed only in the deterministic scoring. The measured correlation of
    // bias/predicted_sd between them was 1.00. Two slots must never share a
    // seed, or the second point corroborates nothing.
    const std::uint64_t base = 20260824;
    CHECK(rngtools::GridSlotBase(base, 0) != rngtools::GridSlotBase(base, 1));

    std::set<std::uint64_t> seen;
    for (int slot = 0; slot < 2; ++slot)
        for (int r = 0; r < 25; ++r)
            for (int e = 4; e <= 8; ++e)
                seen.insert(rngtools::RepeatSeed(
                    rngtools::GridSlotBase(base, slot), r, e));
    CHECK_EQ(static_cast<int>(seen.size()), 2 * 25 * 5);

    // Slot 0 keeps the historical base, so its numbers stay comparable with
    // any earlier single-slot run.
    CHECK_EQ(rngtools::GridSlotBase(base, 0), base);

    // The stride must clear the whole RepeatSeed span at the tools' repeat
    // cap, not merely the span at R=25 -- otherwise raising --repeats would
    // silently re-introduce the overlap. Both operands are constexpr, so this
    // is a compile-time invariant rather than a runtime check.
    static_assert(rngtools::kRepeatSeedSpan >
                      1000003ULL * static_cast<std::uint64_t>(rngtools::kMaxRepeats) + 8ULL,
                  "grid-slot stride must exceed the RepeatSeed span at kMaxRepeats");

    // Same guarantee exercised at the boundary the compile-time check asserts:
    // the last seed of slot 0 at the cap still sits below slot 1's first.
    CHECK(rngtools::RepeatSeed(rngtools::GridSlotBase(base, 0),
                               rngtools::kMaxRepeats - 1, 8) <
          rngtools::RepeatSeed(rngtools::GridSlotBase(base, 1), 0, 4));
}

static void TestPiStabilityParamsByDimension() {
    // The defect this pins: RunStability picks p and the prefactor from `dim`.
    // Forcing the 2D values (p=pi/4, prefactor=4) into the 3D branch inflates
    // every 3D sd_ratio by ~1.216x while the table still LOOKS calibrated --
    // a mutation that survived the suite until this test existed.
    const double kPi = 3.14159265358979323846;
    const auto d2 = rngtools::PiStabilityParams(2);
    const auto d3 = rngtools::PiStabilityParams(3);

    CHECK(std::fabs(d2.p - kPi / 4.0) < 1e-15);
    CHECK_EQ(d2.prefactor, 4.0);
    CHECK(std::fabs(d3.p - kPi / 6.0) < 1e-15);
    CHECK_EQ(d3.prefactor, 6.0);

    // pi = prefactor * p in both dimensions -- the identity the estimator rests
    // on, and the one a mismatched (p, prefactor) pair would break.
    CHECK(std::fabs(d2.prefactor * d2.p - kPi) < 1e-14);
    CHECK(std::fabs(d3.prefactor * d3.p - kPi) < 1e-14);

    // Distinct seed bases, or the 2D and 3D rows are the same trials again.
    CHECK(d2.base != d3.base);
}

// ------------------------------------------------------------------- C ABI
static void TestCApiBuildInfo() {
    rngsdk_build_info_t info;
    std::memset(&info, 0, sizeof info);
    rngsdk_build_info(&info);
    CHECK(info.version != nullptr);
    CHECK_EQ(std::string(info.version), std::string(kVersion));
#if defined(RNGSDK_USE_OPENSSL)
    CHECK_EQ(std::string(info.crypto_backend), std::string("openssl"));
    CHECK_EQ(info.has_aes_ctr_drbg, 1);
#else
    CHECK_EQ(std::string(info.crypto_backend), std::string("bundled"));
    CHECK_EQ(info.has_aes_ctr_drbg, 0);
#endif
    rngsdk_build_info(nullptr);   // documented no-op; must not crash

    // Every declared status has a non-empty message and none returns NULL —
    // a caller that logs the message must never dereference garbage.
    for (int i = RNGSDK_OK; i <= RNGSDK_ERR_INTERNAL; ++i) {
        const char* m = rngsdk_status_message(static_cast<rngsdk_status>(i));
        CHECK(m != nullptr);
        CHECK(m[0] != '\0');
    }
    CHECK_EQ(std::string(rngsdk_status_message(static_cast<rngsdk_status>(9999))),
             std::string("unknown status"));

    // RNGSDK_OK == 0 is load-bearing: callers write `if (rngsdk_...())`.
    static_assert(RNGSDK_OK == 0,
                   "RNGSDK_OK must be 0 -- callers write `if (rngsdk_...())`");
}

static void TestCApiCreateSeededMatchesCpp() {
    // The core claim of the whole item: the C path is the SAME code. Compare
    // by exact value, not by distribution — anything but equality is a defect.
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 12345ull, &h),
                 RNGSDK_OK);
        CHECK(h != nullptr);
        FastRandom ref(12345ull);
        std::uint64_t buf[64];
        CHECK_EQ(rngsdk_next_u64_array(h, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) CHECK_EQ(buf[i], ref.NextUInt64());
        rngsdk_random_destroy(h);
    }
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_PCG64, 999ull, &h), RNGSDK_OK);
        Pcg64Random ref(999ull);
        std::uint64_t buf[64];
        CHECK_EQ(rngsdk_next_u64_array(h, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) CHECK_EQ(buf[i], ref.NextUInt64());
        rngsdk_random_destroy(h);
    }
    {
        // 4200 words crosses the engine's 4 KiB refill boundary (512 words per
        // buffer), so the buffering adapter is genuinely in the compared path.
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_HMAC_DRBG, 7ull, &h), RNGSDK_OK);
        CryptoRandom ref(7ull);
        std::vector<std::uint64_t> buf(4200);
        CHECK_EQ(rngsdk_next_u64_array(h, buf.data(), buf.size()), RNGSDK_OK);
        bool all_equal = true;
        for (std::size_t i = 0; i < buf.size(); ++i)
            if (buf[i] != ref.NextUInt64()) all_equal = false;
        CHECK(all_equal);
        rngsdk_random_destroy(h);
    }
#if defined(RNGSDK_USE_OPENSSL)
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_AES_CTR_DRBG, 7ull, &h), RNGSDK_OK);
        CtrRandom ref(7ull);
        std::vector<std::uint64_t> buf(4200);
        CHECK_EQ(rngsdk_next_u64_array(h, buf.data(), buf.size()), RNGSDK_OK);
        bool all_equal = true;
        for (std::size_t i = 0; i < buf.size(); ++i)
            if (buf[i] != ref.NextUInt64()) all_equal = false;
        CHECK(all_equal);
        rngsdk_random_destroy(h);
    }
#else
    {
        // Same symbol exists in both flavours (spec §6): a caller needs no
        // conditional compilation, only a runtime status check.
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_AES_CTR_DRBG, 7ull, &h),
                 RNGSDK_ERR_UNSUPPORTED);
        CHECK(h == nullptr);
    }
#endif

    // Scalar and array forms must agree: the scalar form IS a bulk call of 1.
    {
        rngsdk_random* a = nullptr;
        rngsdk_random* b = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 31337ull, &a), RNGSDK_OK);
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 31337ull, &b), RNGSDK_OK);
        std::uint64_t arr[32];
        CHECK_EQ(rngsdk_next_u64_array(a, arr, 32), RNGSDK_OK);
        for (int i = 0; i < 32; ++i) {
            std::uint64_t one = 0;
            CHECK_EQ(rngsdk_next_u64(b, &one), RNGSDK_OK);
            CHECK_EQ(arr[i], one);
        }
        rngsdk_random_destroy(a);
        rngsdk_random_destroy(b);
    }

    // Reseeding an existing handle restarts the stream, exactly like C++.
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_PCG64, 1ull, &h), RNGSDK_OK);
        std::uint64_t discard = 0;
        CHECK_EQ(rngsdk_next_u64(h, &discard), RNGSDK_OK);
        CHECK_EQ(rngsdk_random_seed(h, 42ull), RNGSDK_OK);
        Pcg64Random ref(42ull);
        for (int i = 0; i < 8; ++i) {
            std::uint64_t v = 0;
            CHECK_EQ(rngsdk_next_u64(h, &v), RNGSDK_OK);
            CHECK_EQ(v, ref.NextUInt64());
        }
        rngsdk_random_destroy(h);
    }

    // n == 0 is a valid no-op, so callers need no special case.
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 5ull, &h), RNGSDK_OK);
        std::uint64_t buf[1] = {0xABCDu};
        CHECK_EQ(rngsdk_next_u64_array(h, buf, 0), RNGSDK_OK);
        CHECK_EQ(buf[0], static_cast<std::uint64_t>(0xABCDu));   // untouched
        rngsdk_random_destroy(h);
    }
}

static void TestCApiCreationErrorPaths() {
    rngsdk_random* h = nullptr;

    // NULL out-parameter.
    CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 1ull, nullptr),
             RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_random_create_secure(RNGSDK_ENGINE_HMAC_DRBG, nullptr),
             RNGSDK_ERR_NULL_ARG);

    // Unknown engine. 99 is not a declared enumerator; a C caller can pass it.
    CHECK_EQ(rngsdk_random_create_seeded(static_cast<rngsdk_engine>(99), 1ull, &h),
             RNGSDK_ERR_INVALID_ENGINE);
    CHECK(h == nullptr);

    // NULL handle on every handle-taking function.
    std::uint64_t v = 0;
    CHECK_EQ(rngsdk_random_seed(nullptr, 1ull), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_next_u64(nullptr, &v), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_next_u64_array(nullptr, &v, 1), RNGSDK_ERR_NULL_ARG);

    // NULL output buffer, even when n == 0.
    CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 1ull, &h), RNGSDK_OK);
    CHECK_EQ(rngsdk_next_u64(h, nullptr), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_next_u64_array(h, nullptr, 0), RNGSDK_ERR_NULL_ARG);
    rngsdk_random_destroy(h);

    // destroy(NULL) is a no-op, matching free(). Cleanup paths need no guard.
    rngsdk_random_destroy(nullptr);
}

static void TestCApiSeededBytes() {
    const Bytes b48(48, 0x5a);
    const Bytes b31(31, 0x5a);
    rngsdk_random* h = nullptr;

    // The fast tier has no byte-seed constructor at all.
    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_XOSHIRO256PP,
                                               b48.data(), b48.size(), &h),
             RNGSDK_ERR_UNSUPPORTED);
    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_PCG64,
                                               b48.data(), b48.size(), &h),
             RNGSDK_ERR_UNSUPPORTED);

    // HMAC-DRBG: SP 800-90A minimum is 32 bytes; below it the C++ throws.
    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_HMAC_DRBG,
                                               b31.data(), b31.size(), &h),
             RNGSDK_ERR_INVALID_SEED_LEN);
    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_HMAC_DRBG,
                                               b48.data(), b48.size(), &h),
             RNGSDK_OK);
    {
        CryptoRandom ref{crypto::HmacDrbgEngine(b48)};
        for (int i = 0; i < 8; ++i) {
            std::uint64_t v = 0;
            CHECK_EQ(rngsdk_next_u64(h, &v), RNGSDK_OK);
            CHECK_EQ(v, ref.NextUInt64());
        }
    }
    rngsdk_random_destroy(h);
    h = nullptr;

    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_HMAC_DRBG, nullptr, 48, &h),
             RNGSDK_ERR_NULL_ARG);

#if defined(RNGSDK_USE_OPENSSL)
    // CTR-DRBG no-df takes EXACTLY seedlen. Rejecting short entropy rather
    // than zero-extending it was one of the two SP 800-90A defects the
    // CTR-DRBG review caught, so it must not fold into a generic error.
    const Bytes b47(47, 0x5a);
    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_AES_CTR_DRBG,
                                               b47.data(), b47.size(), &h),
             RNGSDK_ERR_INVALID_SEED_LEN);
    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_AES_CTR_DRBG,
                                               b48.data(), b48.size(), &h),
             RNGSDK_OK);
    {
        CtrRandom ref{crypto::CtrDrbgEngine(b48)};
        for (int i = 0; i < 8; ++i) {
            std::uint64_t v = 0;
            CHECK_EQ(rngsdk_next_u64(h, &v), RNGSDK_OK);
            CHECK_EQ(v, ref.NextUInt64());
        }
    }
    rngsdk_random_destroy(h);
#else
    CHECK_EQ(rngsdk_random_create_seeded_bytes(RNGSDK_ENGINE_AES_CTR_DRBG,
                                               b48.data(), b48.size(), &h),
             RNGSDK_ERR_UNSUPPORTED);
#endif
}

static void TestCApiCreateSecureIsNotTheFixedStream() {
    // The trap this test exists to catch: _create_secure on the fast tier
    // must NOT default-construct, because Xoshiro256pp()/Pcg64() seed from the
    // fixed constant 0xDEFA017DEFA017. A function named _secure that hands
    // back a predictable sequence is exactly the failure this SDK exists not
    // to contain.
    const rngsdk_engine kinds[] = {RNGSDK_ENGINE_XOSHIRO256PP,
                                   RNGSDK_ENGINE_PCG64,
                                   RNGSDK_ENGINE_HMAC_DRBG};
    for (rngsdk_engine k : kinds) {
        rngsdk_random* a = nullptr;
        rngsdk_random* b = nullptr;
        CHECK_EQ(rngsdk_random_create_secure(k, &a), RNGSDK_OK);
        CHECK_EQ(rngsdk_random_create_secure(k, &b), RNGSDK_OK);
        std::uint64_t va[4], vb[4];
        CHECK_EQ(rngsdk_next_u64_array(a, va, 4), RNGSDK_OK);
        CHECK_EQ(rngsdk_next_u64_array(b, vb, 4), RNGSDK_OK);
        // Two secure handles must differ (P[false failure] = 2^-256).
        CHECK(std::memcmp(va, vb, sizeof va) != 0);
        rngsdk_random_destroy(a);
        rngsdk_random_destroy(b);
    }

    // And specifically: not the default-constructed fixed-constant stream.
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_secure(RNGSDK_ENGINE_XOSHIRO256PP, &h), RNGSDK_OK);
        std::uint64_t v[4];
        CHECK_EQ(rngsdk_next_u64_array(h, v, 4), RNGSDK_OK);
        FastRandom fixed;                       // 0xDEFA017DEFA017
        std::uint64_t f[4];
        for (int i = 0; i < 4; ++i) f[i] = fixed.NextUInt64();
        CHECK(std::memcmp(v, f, sizeof v) != 0);
        rngsdk_random_destroy(h);
    }
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_secure(RNGSDK_ENGINE_PCG64, &h), RNGSDK_OK);
        std::uint64_t v[4];
        CHECK_EQ(rngsdk_next_u64_array(h, v, 4), RNGSDK_OK);
        Pcg64Random fixed;
        std::uint64_t f[4];
        for (int i = 0; i < 4; ++i) f[i] = fixed.NextUInt64();
        CHECK(std::memcmp(v, f, sizeof v) != 0);
        rngsdk_random_destroy(h);
    }

#if !defined(RNGSDK_USE_OPENSSL)
    {
        rngsdk_random* h = nullptr;
        CHECK_EQ(rngsdk_random_create_secure(RNGSDK_ENGINE_AES_CTR_DRBG, &h),
                 RNGSDK_ERR_UNSUPPORTED);
        CHECK(h == nullptr);
    }
#endif
}

// One template covering every mapping function for one engine, so adding an
// engine later means adding one line rather than a block per function.
template <class CppRandom>
static void CheckCApiMappingMatches(rngsdk_engine kind, std::uint64_t seed) {
    rngsdk_random* h = nullptr;
    CHECK_EQ(rngsdk_random_create_seeded(kind, seed, &h), RNGSDK_OK);
    CppRandom ref(seed);

    // uint32
    {
        std::uint32_t buf[64];
        CHECK_EQ(rngsdk_next_u32_array(h, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) CHECK_EQ(buf[i], ref.NextUInt32());
    }
    // double — compared BY BIT PATTERN, not by tolerance. The claim is that
    // this is the same code, so anything but exact equality is a defect.
    {
        double buf[64];
        CHECK_EQ(rngsdk_next_double_array(h, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) {
            const double expect = ref.NextDouble();
            CHECK(std::memcmp(&buf[i], &expect, sizeof(double)) == 0);
        }
    }
    // float — same rule.
    {
        float buf[64];
        CHECK_EQ(rngsdk_next_float_array(h, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) {
            const float expect = ref.NextFloat();
            CHECK(std::memcmp(&buf[i], &expect, sizeof(float)) == 0);
        }
    }
    // bounded u64: 37 is small; 9223372036854775809 (2^63 + 1) makes Lemire's
    // rejection path fire often, so the loop inside NextUInt64(bound) is
    // genuinely exercised rather than short-circuited.
    {
        std::uint64_t buf[64];
        CHECK_EQ(rngsdk_next_bounded_u64_array(h, 37ull, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) CHECK_EQ(buf[i], ref.NextUInt64(37ull));
        CHECK_EQ(rngsdk_next_bounded_u64_array(h, 9223372036854775809ull, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) CHECK_EQ(buf[i], ref.NextUInt64(9223372036854775809ull));
    }
    // bounded u32, including a bound that does not divide 2^32.
    {
        std::uint32_t buf[64];
        CHECK_EQ(rngsdk_next_bounded_u32_array(h, 6u, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) CHECK_EQ(buf[i], ref.NextUInt32(6u));
        CHECK_EQ(rngsdk_next_bounded_u32_array(h, 2147483649u, buf, 64), RNGSDK_OK);
        for (int i = 0; i < 64; ++i) CHECK_EQ(buf[i], ref.NextUInt32(2147483649u));
    }
    // inclusive integer range, including a negative lower bound.
    {
        for (int i = 0; i < 32; ++i) {
            std::int64_t v = 0;
            CHECK_EQ(rngsdk_next_int_range(h, -5, 5, &v), RNGSDK_OK);
            CHECK_EQ(v, ref.NextInt(-5, 5));
        }
    }
    // bytes at lengths straddling the 8-byte word boundary and the DRBG's
    // 4 KiB refill boundary.
    {
        const std::size_t lens[] = {1, 7, 8, 9, 4095, 4096, 4097};
        for (std::size_t len : lens) {
            std::vector<std::uint8_t> got(len), expect(len);
            CHECK_EQ(rngsdk_next_bytes(h, got.data(), len), RNGSDK_OK);
            ref.NextBytes(expect.data(), len);
            CHECK(got == expect);
        }
    }
    rngsdk_random_destroy(h);
}

static void TestCApiMappingLayer() {
    CheckCApiMappingMatches<FastRandom>(RNGSDK_ENGINE_XOSHIRO256PP, 12345ull);
    CheckCApiMappingMatches<Pcg64Random>(RNGSDK_ENGINE_PCG64, 999ull);
    CheckCApiMappingMatches<CryptoRandom>(RNGSDK_ENGINE_HMAC_DRBG, 7ull);
#if defined(RNGSDK_USE_OPENSSL)
    CheckCApiMappingMatches<CtrRandom>(RNGSDK_ENGINE_AES_CTR_DRBG, 7ull);
#endif
}

static void TestCApiScalarMatchesArray() {
    // The risk created by implementing scalar in terms of bulk: if the bulk
    // loop ever diverges from a sequence of single calls, everything is wrong
    // at once. This is the test that catches it.
    rngsdk_random* a = nullptr;
    rngsdk_random* b = nullptr;
    CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_PCG64, 4242ull, &a), RNGSDK_OK);
    CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_PCG64, 4242ull, &b), RNGSDK_OK);

    std::uint32_t a32[16];
    CHECK_EQ(rngsdk_next_u32_array(a, a32, 16), RNGSDK_OK);
    for (int i = 0; i < 16; ++i) {
        std::uint32_t v = 0;
        CHECK_EQ(rngsdk_next_u32(b, &v), RNGSDK_OK);
        CHECK_EQ(a32[i], v);
    }
    double ad[16];
    CHECK_EQ(rngsdk_next_double_array(a, ad, 16), RNGSDK_OK);
    for (int i = 0; i < 16; ++i) {
        double v = 0.0;
        CHECK_EQ(rngsdk_next_double(b, &v), RNGSDK_OK);
        CHECK(std::memcmp(&ad[i], &v, sizeof(double)) == 0);
    }
    float af[16];
    CHECK_EQ(rngsdk_next_float_array(a, af, 16), RNGSDK_OK);
    for (int i = 0; i < 16; ++i) {
        float v = 0.0f;
        CHECK_EQ(rngsdk_next_float(b, &v), RNGSDK_OK);
        CHECK(std::memcmp(&af[i], &v, sizeof(float)) == 0);
    }
    std::uint64_t a64[16];
    CHECK_EQ(rngsdk_next_bounded_u64_array(a, 1000ull, a64, 16), RNGSDK_OK);
    for (int i = 0; i < 16; ++i) {
        std::uint64_t v = 0;
        CHECK_EQ(rngsdk_next_bounded_u64(b, 1000ull, &v), RNGSDK_OK);
        CHECK_EQ(a64[i], v);
    }
    std::uint32_t ab32[16];
    CHECK_EQ(rngsdk_next_bounded_u32_array(a, 1000u, ab32, 16), RNGSDK_OK);
    for (int i = 0; i < 16; ++i) {
        std::uint32_t v = 0;
        CHECK_EQ(rngsdk_next_bounded_u32(b, 1000u, &v), RNGSDK_OK);
        CHECK_EQ(ab32[i], v);
    }
    rngsdk_random_destroy(a);
    rngsdk_random_destroy(b);
}

static void TestCApiBoundZeroIsRejectedOnPurpose() {
    // DELIBERATE DIVERGENCE FROM THE C++ — do not "fix" this.
    // Random::NextUInt64(0) returns 0 (random.hpp:73) while
    // pf::Generator::NextIntsUnbiased(..., 0) throws (provably_fair.hpp:171).
    // Both are defensible in C++ and documented where they live. Behind ONE C
    // status enum they are not: two identically-shaped calls would behave
    // differently for the same input with nothing at the C level to explain
    // why. The C ABI therefore refuses bound == 0 everywhere.
    rngsdk_random* h = nullptr;
    CHECK_EQ(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 1ull, &h), RNGSDK_OK);

    std::uint64_t v64 = 0xDEADBEEFull;
    std::uint32_t v32 = 0xDEADBEEFu;
    CHECK_EQ(rngsdk_next_bounded_u64(h, 0ull, &v64), RNGSDK_ERR_INVALID_BOUND);
    CHECK_EQ(rngsdk_next_bounded_u64_array(h, 0ull, &v64, 1), RNGSDK_ERR_INVALID_BOUND);
    CHECK_EQ(rngsdk_next_bounded_u32(h, 0u, &v32), RNGSDK_ERR_INVALID_BOUND);
    CHECK_EQ(rngsdk_next_bounded_u32_array(h, 0u, &v32, 1), RNGSDK_ERR_INVALID_BOUND);
    // A rejected call writes nothing and consumes no engine output.
    CHECK_EQ(v64, static_cast<std::uint64_t>(0xDEADBEEFull));
    CHECK_EQ(v32, static_cast<std::uint32_t>(0xDEADBEEFu));
    {
        FastRandom ref(1ull);
        std::uint64_t got = 0;
        CHECK_EQ(rngsdk_next_u64(h, &got), RNGSDK_OK);
        CHECK_EQ(got, ref.NextUInt64());   // stream position unchanged by the rejections
    }

    // Inverted range: the C++ would wrap span to ~2^64 and return a value from
    // the wrong interval, so the wrapper refuses it.
    std::int64_t r = 0;
    CHECK_EQ(rngsdk_next_int_range(h, 5, -5, &r), RNGSDK_ERR_INVALID_BOUND);
    // lo == hi is a legitimate single-element range and must still work.
    CHECK_EQ(rngsdk_next_int_range(h, 3, 3, &r), RNGSDK_OK);
    CHECK_EQ(r, static_cast<std::int64_t>(3));

    // NULL checks across the whole family.
    CHECK_EQ(rngsdk_next_u32(nullptr, &v32), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_next_double(h, nullptr), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_next_float(h, nullptr), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_next_bytes(h, nullptr, 4), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_next_int_range(h, 0, 1, nullptr), RNGSDK_ERR_NULL_ARG);

    rngsdk_random_destroy(h);
}

static void TestCApiPfVectors() {
    // The same canonical vectors the C++ test, the web verifier and the
    // Python generator all consume (docs/pf_test_vectors.json). If the C path
    // reproduces them, the wrapper is not a second implementation.
    for (std::size_t i = 0; i < golden_pf::kCommitmentCaseCount; ++i) {
        const auto& c = golden_pf::kCommitmentCases[i];
        char hex[RNGSDK_HEX_BUF];
        CHECK_EQ(rngsdk_pf_commitment(c.server_seed, hex, sizeof hex), RNGSDK_OK);
        CHECK_EQ(std::string(hex), std::string(c.commitment));

        int ok = -1;
        CHECK_EQ(rngsdk_pf_verify_commitment(c.server_seed, c.commitment, &ok), RNGSDK_OK);
        CHECK_EQ(ok, 1);
        ok = -1;
        CHECK_EQ(rngsdk_pf_verify_commitment(c.server_seed,
                     "0000000000000000000000000000000000000000000000000000000000000000",
                     &ok), RNGSDK_OK);
        CHECK_EQ(ok, 0);
    }

    for (std::size_t i = 0; i < golden_pf::kFloatCaseCount; ++i) {
        const auto& c = golden_pf::kFloatCases[i];
        std::vector<double> got(c.count);
        CHECK_EQ(rngsdk_pf_next_floats(c.server_seed, c.client_seed, c.nonce,
                                       c.count, got.data()), RNGSDK_OK);
        for (std::size_t j = 0; j < c.count; ++j)
            CHECK(std::memcmp(&got[j], &c.expected[j], sizeof(double)) == 0);

        // rngsdk_pf_generate is the same vector's first outcome, bit-for-bit.
        double one = -1.0;
        CHECK_EQ(rngsdk_pf_generate(c.server_seed, c.client_seed, c.nonce, &one),
                 RNGSDK_OK);
        CHECK(std::memcmp(&one, &c.expected[0], sizeof(double)) == 0);
    }

    for (std::size_t i = 0; i < golden_pf::kIntCaseCount; ++i) {
        const auto& c = golden_pf::kIntCases[i];
        std::vector<std::uint64_t> got(c.count);
        CHECK_EQ(rngsdk_pf_next_ints_unbiased(c.server_seed, c.client_seed, c.nonce,
                                              c.count, c.bound, got.data()), RNGSDK_OK);
        for (std::size_t j = 0; j < c.count; ++j) {
            CHECK_EQ(got[j], c.expected[j]);
            CHECK(got[j] < c.bound);
        }
    }

    // The biased-but-industry-compatible mapping has no JSON vectors of its
    // own, so it is checked against the C++ directly.
    {
        const char* ss = "a3f9c1e07b8d2456901fbe34ac57d8e21093b6f4c8a70d5e2f6b19c48307ad52";
        const char* cs = "player-seed";
        const auto expect = pf::Generator::NextInts(ss, cs, 0, 16, 37);
        std::vector<std::uint64_t> got(16);
        CHECK_EQ(rngsdk_pf_next_ints(ss, cs, 0, 16, 37, got.data()), RNGSDK_OK);
        for (std::size_t j = 0; j < expect.size(); ++j) CHECK_EQ(got[j], expect[j]);
    }

    // A generated server seed is 64 hex characters and verifies against its
    // own commitment.
    {
        char seed[RNGSDK_HEX_BUF];
        char hex[RNGSDK_HEX_BUF];
        CHECK_EQ(rngsdk_pf_generate_server_seed(seed, sizeof seed), RNGSDK_OK);
        CHECK_EQ(std::strlen(seed), static_cast<std::size_t>(64));
        CHECK_EQ(rngsdk_pf_commitment(seed, hex, sizeof hex), RNGSDK_OK);
        int ok = 0;
        CHECK_EQ(rngsdk_pf_verify_commitment(seed, hex, &ok), RNGSDK_OK);
        CHECK_EQ(ok, 1);

        // Two draws differ — GenerateServerSeed is OS entropy, not a counter.
        char seed2[RNGSDK_HEX_BUF];
        CHECK_EQ(rngsdk_pf_generate_server_seed(seed2, sizeof seed2), RNGSDK_OK);
        CHECK(std::string(seed) != std::string(seed2));
    }
}

static void TestCApiPfErrorPaths() {
    char hex[RNGSDK_HEX_BUF];
    const char* ss = "a3f9c1e07b8d2456901fbe34ac57d8e21093b6f4c8a70d5e2f6b19c48307ad52";

    // NULL arguments.
    CHECK_EQ(rngsdk_pf_commitment(nullptr, hex, sizeof hex), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_pf_commitment(ss, nullptr, 65), RNGSDK_ERR_NULL_ARG);
    CHECK_EQ(rngsdk_pf_generate_server_seed(nullptr, 65), RNGSDK_ERR_NULL_ARG);
    {
        int ok = 0;
        CHECK_EQ(rngsdk_pf_verify_commitment(nullptr, hex, &ok), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_verify_commitment(ss, nullptr, &ok), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_verify_commitment(ss, hex, nullptr), RNGSDK_ERR_NULL_ARG);
    }
    {
        double d = 0.0;
        std::uint64_t v = 0;
        CHECK_EQ(rngsdk_pf_next_floats(nullptr, "c", 0, 1, &d), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_next_floats(ss, nullptr, 0, 1, &d), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_next_floats(ss, "c", 0, 1, nullptr), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_generate(nullptr, "c", 0, &d), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_generate(ss, nullptr, 0, &d), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_generate(ss, "c", 0, nullptr), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_next_ints(ss, "c", 0, 1, 10, nullptr), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_next_ints_unbiased(ss, "c", 0, 1, 10, nullptr), RNGSDK_ERR_NULL_ARG);

        // bound == 0: the C++ NextIntsUnbiased throws here (a hardware divide
        // trap would otherwise follow), and NextInts would divide by zero in
        // spirit. Both are refused, and the refusal must be a STATUS, not an
        // exception escaping into a C frame.
        CHECK_EQ(rngsdk_pf_next_ints(ss, "c", 0, 1, 0, &v), RNGSDK_ERR_INVALID_BOUND);
        CHECK_EQ(rngsdk_pf_next_ints_unbiased(ss, "c", 0, 1, 0, &v), RNGSDK_ERR_INVALID_BOUND);

        // n == 0 is a valid no-op.
        CHECK_EQ(rngsdk_pf_next_floats(ss, "c", 0, 0, &d), RNGSDK_OK);
        CHECK_EQ(rngsdk_pf_next_ints_unbiased(ss, "c", 0, 0, 10, &v), RNGSDK_OK);
    }

    // Buffer too small: a 64-char commitment needs 65 bytes. 64 is not enough,
    // and the call must fail rather than truncate.
    {
        char small[64];
        std::memset(small, 'X', sizeof small);
        CHECK_EQ(rngsdk_pf_commitment(ss, small, sizeof small), RNGSDK_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(small[0], 'X');   // nothing written on failure
        CHECK_EQ(rngsdk_pf_generate_server_seed(small, sizeof small),
                 RNGSDK_ERR_BUFFER_TOO_SMALL);
        CHECK_EQ(rngsdk_pf_commitment(ss, small, 0), RNGSDK_ERR_BUFFER_TOO_SMALL);
    }

    // An empty client seed is legitimate (there is a vector for it); only NULL
    // is an error.
    {
        double d[4];
        CHECK_EQ(rngsdk_pf_next_floats(ss, "", 0, 4, d), RNGSDK_OK);
    }
}

static void TestCApiPfSession() {
    const char* kSeed = "a3f9c1e07b8d2456901fbe34ac57d8e21093b6f4c8a70d5e2f6b19c48307ad52";

    // Happy path: commitment matches, results match the stateless generator at
    // the same nonce, the nonce advances by exactly one per bet.
    {
        rngsdk_pf_session* s = nullptr;
        CHECK_EQ(rngsdk_pf_session_create(kSeed, 0, &s), RNGSDK_OK);
        CHECK(s != nullptr);

        char hex[RNGSDK_HEX_BUF];
        CHECK_EQ(rngsdk_pf_session_commitment(s, hex, sizeof hex), RNGSDK_OK);
        CHECK_EQ(std::string(hex), pf::Commitment(kSeed));

        CHECK_EQ(rngsdk_pf_session_set_client_seed(s, "player-seed"), RNGSDK_OK);

        std::uint64_t nonce = 12345;
        CHECK_EQ(rngsdk_pf_session_next_nonce(s, &nonce), RNGSDK_OK);
        CHECK_EQ(nonce, static_cast<std::uint64_t>(0));

        for (std::uint64_t bet = 0; bet < 3; ++bet) {
            double got[4];
            CHECK_EQ(rngsdk_pf_session_play(s, 4, got), RNGSDK_OK);
            const auto expect = pf::Generator::NextFloats(kSeed, "player-seed", bet, 4);
            for (int j = 0; j < 4; ++j)
                CHECK(std::memcmp(&got[j], &expect[j], sizeof(double)) == 0);
            CHECK_EQ(rngsdk_pf_session_next_nonce(s, &nonce), RNGSDK_OK);
            CHECK_EQ(nonce, bet + 1);
        }

        // Reveal returns the seed and locks further play.
        char revealed[RNGSDK_HEX_BUF];
        CHECK_EQ(rngsdk_pf_session_reveal(s, revealed, sizeof revealed), RNGSDK_OK);
        CHECK_EQ(std::string(revealed), std::string(kSeed));
        double after[4];
        CHECK_EQ(rngsdk_pf_session_play(s, 4, after), RNGSDK_ERR_REVEALED);

        rngsdk_pf_session_destroy(s);
    }

    // Play() before SetClientSeed() is refused: a client seed the operator
    // knows at commit time defeats commit-reveal.
    {
        rngsdk_pf_session* s = nullptr;
        CHECK_EQ(rngsdk_pf_session_create(kSeed, 0, &s), RNGSDK_OK);
        double got[2];
        CHECK_EQ(rngsdk_pf_session_play(s, 2, got), RNGSDK_ERR_NO_CLIENT_SEED);
        rngsdk_pf_session_destroy(s);
    }

    // A short server seed is refused: the published commitment is a free
    // offline brute-force oracle.
    {
        rngsdk_pf_session* s = nullptr;
        CHECK_EQ(rngsdk_pf_session_create("0123456789abcdef0123456789abcde", 0, &s),
                 RNGSDK_ERR_WEAK_SEED);   // 31 characters
        CHECK(s == nullptr);
        CHECK_EQ(rngsdk_pf_session_create("0123456789abcdef0123456789abcdef", 0, &s),
                 RNGSDK_OK);              // 32 characters — the documented floor
        rngsdk_pf_session_destroy(s);
    }

    // Changing the client seed must NOT rewind the nonce: rewinding would
    // reproduce outcomes the player has already seen.
    {
        rngsdk_pf_session* s = nullptr;
        CHECK_EQ(rngsdk_pf_session_create(kSeed, 0, &s), RNGSDK_OK);
        CHECK_EQ(rngsdk_pf_session_set_client_seed(s, "first"), RNGSDK_OK);
        double got[1];
        CHECK_EQ(rngsdk_pf_session_play(s, 1, got), RNGSDK_OK);
        CHECK_EQ(rngsdk_pf_session_set_client_seed(s, "second"), RNGSDK_OK);
        std::uint64_t nonce = 0;
        CHECK_EQ(rngsdk_pf_session_next_nonce(s, &nonce), RNGSDK_OK);
        CHECK_EQ(nonce, static_cast<std::uint64_t>(1));
        rngsdk_pf_session_destroy(s);
    }

    // start_nonce is how a restarted server resumes without replaying. It has
    // no default in C on purpose — the caller must state it at every site.
    {
        rngsdk_pf_session* s = nullptr;
        CHECK_EQ(rngsdk_pf_session_create(kSeed, 500, &s), RNGSDK_OK);
        CHECK_EQ(rngsdk_pf_session_set_client_seed(s, "player-seed"), RNGSDK_OK);
        double got[4];
        CHECK_EQ(rngsdk_pf_session_play(s, 4, got), RNGSDK_OK);
        const auto expect = pf::Generator::NextFloats(kSeed, "player-seed", 500, 4);
        for (int j = 0; j < 4; ++j)
            CHECK(std::memcmp(&got[j], &expect[j], sizeof(double)) == 0);
        rngsdk_pf_session_destroy(s);
    }

    // Nonce exhaustion is refused, not wrapped.
    {
        rngsdk_pf_session* s = nullptr;
        CHECK_EQ(rngsdk_pf_session_create(kSeed, std::numeric_limits<std::uint64_t>::max(), &s),
                 RNGSDK_OK);
        CHECK_EQ(rngsdk_pf_session_set_client_seed(s, "player-seed"), RNGSDK_OK);
        double got[1];
        CHECK_EQ(rngsdk_pf_session_play(s, 1, got), RNGSDK_ERR_NONCE_EXHAUSTED);
        rngsdk_pf_session_destroy(s);
    }

    // NULL handling everywhere.
    {
        char hex[RNGSDK_HEX_BUF];
        double d[1];
        std::uint64_t n = 0;
        rngsdk_pf_session* s = nullptr;
        CHECK_EQ(rngsdk_pf_session_create(nullptr, 0, &s), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_create(kSeed, 0, nullptr), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_commitment(nullptr, hex, sizeof hex), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_set_client_seed(nullptr, "x"), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_play(nullptr, 1, d), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_next_nonce(nullptr, &n), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_reveal(nullptr, hex, sizeof hex), RNGSDK_ERR_NULL_ARG);

        CHECK_EQ(rngsdk_pf_session_create(kSeed, 0, &s), RNGSDK_OK);
        CHECK_EQ(rngsdk_pf_session_set_client_seed(s, nullptr), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_commitment(s, nullptr, 65), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_play(s, 1, nullptr), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_next_nonce(s, nullptr), RNGSDK_ERR_NULL_ARG);
        CHECK_EQ(rngsdk_pf_session_reveal(s, nullptr, 65), RNGSDK_ERR_NULL_ARG);
        {
            char small[64];
            CHECK_EQ(rngsdk_pf_session_commitment(s, small, sizeof small),
                     RNGSDK_ERR_BUFFER_TOO_SMALL);
        }
        rngsdk_pf_session_destroy(s);
        rngsdk_pf_session_destroy(nullptr);   // no-op
    }
}

// Pins the reveal latch surviving a failed CopyOut. rngsdk_pf_session_reveal
// sets revealed = true unconditionally, before returning whatever CopyOut
// returns for the seed. That order is deliberate: once the seed has come out
// of ServerSession::Reveal() the session must be dead regardless of whether
// the caller's buffer was big enough to receive it — a caller could otherwise
// pass a deliberately-too-small buffer, get RNGSDK_ERR_BUFFER_TOO_SMALL back,
// and keep playing against a seed that is already revealed. The "obvious"
// tidy-up of returning early on CopyOut failure before setting the flag would
// silently reopen that hole with the rest of the suite still green, which is
// exactly what this test exists to catch.
static void TestCApiPfSessionRevealLatchSurvivesShortBuffer() {
    const char* kSeed = "a3f9c1e07b8d2456901fbe34ac57d8e21093b6f4c8a70d5e2f6b19c48307ad52";

    rngsdk_pf_session* s = nullptr;
    CHECK_EQ(rngsdk_pf_session_create(kSeed, 0, &s), RNGSDK_OK);
    CHECK_EQ(rngsdk_pf_session_set_client_seed(s, "player-seed"), RNGSDK_OK);

    // Get the session live: at least one successful bet.
    double got[1];
    CHECK_EQ(rngsdk_pf_session_play(s, 1, got), RNGSDK_OK);

    // Reveal with a buffer one byte short of RNGSDK_HEX_BUF.
    char small[RNGSDK_HEX_BUF - 1];
    std::memset(small, 'X', sizeof small);
    CHECK_EQ(rngsdk_pf_session_reveal(s, small, sizeof small), RNGSDK_ERR_BUFFER_TOO_SMALL);
    // CopyOut writes nothing on failure — same style as Task 4's buffer tests.
    CHECK_EQ(small[0], 'X');

    // The session must be dead anyway: same status as play-after-successful-reveal.
    double after[1];
    CHECK_EQ(rngsdk_pf_session_play(s, 1, after), RNGSDK_ERR_REVEALED);

    // A second reveal call behaves as it would after a successful reveal.
    char hex[RNGSDK_HEX_BUF];
    CHECK_EQ(rngsdk_pf_session_reveal(s, hex, sizeof hex), RNGSDK_OK);
    CHECK_EQ(std::string(hex), std::string(kSeed));

    rngsdk_pf_session_destroy(s);
}

int main() {
    std::cout << "rngsdk " << kVersion << " test suite\n";
    TestSha256();
    TestHmac();
    TestHmacDrbg();
    TestXoshiro();
    TestSplitMix64Injective();
    TestPcg64();
    TestMapping<Xoshiro256pp>("xoshiro256++");
    TestMapping<Pcg64>("pcg64");
    TestMapping<crypto::HmacDrbgEngine>("hmac-drbg");
    TestAvalanche<Xoshiro256pp>("xoshiro256++");
    TestAvalanche<Pcg64>("pcg64");
    TestAvalanche<crypto::HmacDrbgEngine>("hmac-drbg");
    TestProvablyFair();
    TestPfGoldenVectors();
    TestWebVerifierVectorsInSync();
    TestRevealLock();
    TestClientSeedReuseDoesNotReplay();
    TestNonceOverflowRefused();
    TestWeakServerSeedRefused();
    TestPlayWithoutClientSeedRefused();
    TestModuloBiasDemo();
    TestCavpHmacDrbg();
#if defined(RNGSDK_USE_OPENSSL)
    TestCavpCtrDrbg();
    TestCtrDrbgEngine();
    TestCtrDrbgLengthContract();
    TestMapping<crypto::CtrDrbgEngine>("ctr-drbg");
    TestAvalanche<crypto::CtrDrbgEngine>("ctr-drbg");
#endif
    TestOsEntropy();
    TestBytesSeedDeterminism();
    TestGenerateServerSeed();
    TestSecureDefaultConstruction();
    TestCApiBuildInfo();
    TestCApiCreateSeededMatchesCpp();
    TestCApiCreationErrorPaths();
    TestCApiSeededBytes();
    TestCApiCreateSecureIsNotTheFixedStream();
    TestCApiMappingLayer();
    TestCApiScalarMatchesArray();
    TestCApiBoundZeroIsRejectedOnPurpose();
    TestCApiPfVectors();
    TestCApiPfErrorPaths();
    TestCApiPfSession();
    TestCApiPfSessionRevealLatchSurvivesShortBuffer();
    TestStreamParseByteCount();
    TestStreamUnknownSourceRejected();
    TestStreamSources();
    TestStreamRanduPacking();
    TestStreamProvablyFairLayout();
    TestStreamFingerprints();
    TestOdeNeumannSeries();
    TestOdeSampler();
    TestOdeExpectationMatchesSeries();
    TestOdeForcedWalkTermMatchesNeumannTerm();
    TestOdeWalkScripted();
    TestOdeWelfordMatchesTwoPass();
    TestOdeConvergence();
    TestSmallMultiplierLcgPairSkew();
    TestMt19937Adapter();
    TestRandBuiltinVaries();
    TestRandBuiltinSpansAboveHalf();
    TestStabilityAggregateHandComputed();
    TestStabilityBiasVarianceDecomposition();
    TestSlopeFitRecoversMinusOneHalf();
    TestSlopeFitFlatSeriesIsZero();
    TestSlopeFitWidensIntervalWithScatter();
    TestTCriticalTable();
    TestSlopeFitRejectsBadInput();
    TestRepeatSeedsAreInjective();
    TestGridSlotBasesAreDisjoint();
    TestPiStabilityParamsByDimension();

    std::cout << (g_failures ? "\nFAILED: " : "\nPASSED: ") << g_checks - g_failures
              << "/" << g_checks << " checks\n";
    return g_failures ? 1 : 0;
}
