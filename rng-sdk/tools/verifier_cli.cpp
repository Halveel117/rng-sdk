// verifier_cli.cpp: independent console verifier for the Provably Fair
// scheme. Deliberately includes ONLY the two crypto headers + PF logic, so a
// third party can audit ~500 lines total and trust the output.
//
// Usage:
//   rng_verifier commit  <server_seed>
//   rng_verifier check   <server_seed> <commitment_hex>
//   rng_verifier floats  <server_seed> <client_seed> <nonce> [count=1]
//   rng_verifier ints    <server_seed> <client_seed> <nonce> <bound> [count=1] [--unbiased]
//   rng_verifier verify  <server_seed> <commitment_hex> <client_seed> <nonce> [count=1]
//
// 'verify' is the full player workflow: check the reveal against the
// commitment, then recompute the results for that nonce.
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "rngsdk/provably_fair.hpp"

namespace pf = rngsdk::pf;

// std::strtoull silently accepts non-numeric input as 0, and silently
// SATURATES at ULLONG_MAX (== UINT64_MAX on this platform) for any input
// that overflows 64 bits. A nonce of 2^64 quietly becomes
// 18446744073709551615 instead of being rejected. A typo'd or missing
// argument is then indistinguishable from a deliberately-chosen number.
// Parse strictly instead: every character must be a digit, and strtoull's
// own ERANGE must not have fired. Used for every numeric CLI argument
// (nonce, count, bound) so no raw strtoull call remains in this file.
static bool ParseU64(const std::string& s, std::uint64_t* out) {
    if (s.empty()) return false;
    if (!std::all_of(s.begin(), s.end(),
                      [](unsigned char c) { return std::isdigit(c) != 0; })) {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno == ERANGE) return false;
    *out = static_cast<std::uint64_t>(v);
    return true;
}

static void Usage();

// Parse one numeric CLI argument, or complain and print the usage block.
// Every numeric argument in this file goes through here so the three
// messages cannot drift apart, and so no call site can forget the complaint.
//
// `positive` additionally rejects zero, which only `bound` needs:
// NextIntsUnbiased(bound == 0) is integer division by zero, a hardware trap
// rather than a catchable C++ exception (see provably_fair.hpp), and
// "n integers in [0, 0)" is meaningless regardless.
static bool ArgU64(const char* text, const char* name, const char* expected,
                   std::uint64_t* out, bool positive = false) {
    if (ParseU64(text, out) && (!positive || *out != 0)) return true;
    std::cerr << "error: " << name << " must be " << expected << ", got '" << text
              << "'\n";
    Usage();
    return false;
}

static void Usage() {
    std::cerr <<
        "rng_verifier: Provably Fair verification tool (rngsdk prototype)\n"
        "  commit  <server_seed>\n"
        "  check   <server_seed> <commitment_hex>\n"
        "  floats  <server_seed> <client_seed> <nonce> [count=1]\n"
        "  ints    <server_seed> <client_seed> <nonce> <bound> [count=1] [--unbiased]\n"
        "  verify  <server_seed> <commitment_hex> <client_seed> <nonce> [count=1]\n";
}

int main(int argc, char** argv) {
    if (argc < 3) { Usage(); return 2; }
    const std::string cmd = argv[1];

    try {
        if (cmd == "commit") {
            std::cout << pf::Commitment(argv[2]) << "\n";
            return 0;
        }
        if (cmd == "check") {
            if (argc < 4) { Usage(); return 2; }
            const bool ok = pf::VerifyCommitment(argv[2], argv[3]);
            std::cout << (ok ? "COMMITMENT OK" : "COMMITMENT MISMATCH: server seed is NOT the committed one") << "\n";
            return ok ? 0 : 1;
        }
        if (cmd == "floats") {
            if (argc < 5) { Usage(); return 2; }
            std::uint64_t nonce = 0;
            if (!ArgU64(argv[4], "nonce", "a whole number in [0, 2^64-1]", &nonce)) return 2;
            std::uint64_t count64 = 1;
            if (argc > 5 && !ArgU64(argv[5], "count", "a whole number", &count64)) return 2;
            const std::size_t count = static_cast<std::size_t>(count64);
            for (double f : pf::Generator::NextFloats(argv[2], argv[3], nonce, count))
                std::cout.precision(17), std::cout << f << "\n";
            return 0;
        }
        if (cmd == "ints") {
            if (argc < 6) { Usage(); return 2; }
            std::uint64_t nonce = 0;
            if (!ArgU64(argv[4], "nonce", "a whole number in [0, 2^64-1]", &nonce)) return 2;
            std::uint64_t bound = 0;
            if (!ArgU64(argv[5], "bound", "a positive whole number", &bound, true)) return 2;
            std::uint64_t count64 = 1;
            bool unbiased = false;
            for (int i = 6; i < argc; ++i) {
                if (std::string(argv[i]) == "--unbiased") {
                    unbiased = true;
                } else if (!ArgU64(argv[i], "count", "a whole number", &count64)) {
                    return 2;
                }
            }
            const std::size_t count = static_cast<std::size_t>(count64);
            const auto v = unbiased
                ? pf::Generator::NextIntsUnbiased(argv[2], argv[3], nonce, count, bound)
                : pf::Generator::NextInts(argv[2], argv[3], nonce, count, bound);
            for (auto x : v) std::cout << x << "\n";
            return 0;
        }
        if (cmd == "verify") {
            if (argc < 6) { Usage(); return 2; }
            const std::string server_seed = argv[2], commitment = argv[3], client_seed = argv[4];
            std::uint64_t nonce = 0;
            if (!ArgU64(argv[5], "nonce", "a whole number in [0, 2^64-1]", &nonce)) return 2;
            std::uint64_t count64 = 1;
            if (argc > 6 && !ArgU64(argv[6], "count", "a whole number", &count64)) return 2;
            const std::size_t count = static_cast<std::size_t>(count64);

            const bool ok = pf::VerifyCommitment(server_seed, commitment);
            std::cout << "commitment: " << (ok ? "OK" : "MISMATCH") << "\n";
            if (!ok) {
                std::cout << "expected  : " << pf::Commitment(server_seed) << "\n"
                          << "claimed   : " << commitment << "\n"
                          << "The revealed seed does not match what the server committed to before play.\n";
                return 1;
            }
            std::cout << "results for nonce " << nonce << ":\n";
            std::cout.precision(17);
            for (double f : pf::Generator::NextFloats(server_seed, client_seed, nonce, count))
                std::cout << "  " << f << "\n";
            return 0;
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 3;
    }

    Usage();
    return 2;
}
