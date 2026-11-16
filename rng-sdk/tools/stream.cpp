// stream.cpp — rng_stream: raw byte stream for the external statistical
// batteries (NIST SP 800-22, Dieharder, TestU01, PractRand).
//
//   rng_stream --source xoshiro --seed 1 | RNG_test stdin64
//   rng_stream --source pf --bytes 125M > pf.bin
//
// stdout carries stream bytes and nothing else; every diagnostic goes to
// stderr, so a battery reading the pipe never sees a stray message. Byte
// sources, and the reasoning behind each, live in stream_sources.hpp.
//
// License: MIT.
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#include "stream_sources.hpp"

namespace {

const char kUsage[] =
    "rng_stream — raw random bytes on stdout, for statistical test batteries\n"
    "\n"
    "Usage: rng_stream --source <name> [--seed N] [--bytes N]\n"
    "                  [--pf-bytes-per-nonce N]\n"
    "\n"
    "  --source  xoshiro | pcg64 | hmac | ctr | pf | randu   (required)\n"
    "              xoshiro,pcg64  fast tier, via Random<E>::NextBytes\n"
    "              hmac,ctr       crypto tier (ctr needs the OpenSSL build)\n"
    "              pf             Provably Fair HMAC stream, nonce-advancing\n"
    "              randu          DELIBERATELY BROKEN — the negative control\n"
    "  --seed    stream seed (default 1); same seed => same bytes\n"
    "  --bytes   how many bytes to emit, suffixes K/M/G (default: unlimited)\n"
    "  --pf-bytes-per-nonce  bytes drawn per nonce for --source pf (default 32)\n"
    "\n"
    "Examples:\n"
    "  rng_stream --source xoshiro | RNG_test stdin64\n"
    "  rng_stream --source pcg64 --bytes 125M > pcg64.bin\n"
    "  rng_stream --source randu | dieharder -a -g 200\n";

// Every parse failure is fatal. A tool that silently defaults after a typo
// produces a battery log that names one run and describes another.
[[noreturn]] void Fail(const std::string& message) {
    std::fprintf(stderr, "rng_stream: %s\n\n%s", message.c_str(), kUsage);
    std::exit(2);
}

std::string RequireValue(int argc, char** argv, int& i) {
    if (i + 1 >= argc) Fail(std::string("missing value for ") + argv[i]);
    return argv[++i];
}

// std::strerror is deprecated by MSVC (C4996) and not thread-safe elsewhere.
std::string ErrnoText(int code) {
    char buf[256] = {0};
#if defined(_MSC_VER)
    if (strerror_s(buf, sizeof buf, code) != 0) return "unknown error " + std::to_string(code);
#elif defined(_GNU_SOURCE)
    return strerror_r(code, buf, sizeof buf);   // GNU variant may ignore buf
#else
    if (strerror_r(code, buf, sizeof buf) != 0) return "unknown error " + std::to_string(code);
#endif
    return buf;
}

} // namespace

int main(int argc, char** argv) {
    std::string source;
    rngstream::Options opt;
    bool limited = false;
    bool pf_budget_given = false;
    std::uint64_t total = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        try {
            if (arg == "--source") {
                source = RequireValue(argc, argv, i);
            } else if (arg == "--seed") {
                opt.seed = rngstream::ParseU64(RequireValue(argc, argv, i), "seed");
            } else if (arg == "--bytes") {
                total = rngstream::ParseByteCount(RequireValue(argc, argv, i));
                limited = true;
            } else if (arg == "--pf-bytes-per-nonce") {
                const std::uint64_t n =
                    rngstream::ParseU64(RequireValue(argc, argv, i), "pf bytes-per-nonce");
                if (n == 0) Fail("--pf-bytes-per-nonce must be positive");
                if (n > SIZE_MAX) Fail("--pf-bytes-per-nonce is too large for this platform");
                opt.pf_bytes_per_nonce = static_cast<std::size_t>(n);
                pf_budget_given = true;
            } else if (arg == "--help" || arg == "-h") {
                std::fputs(kUsage, stderr);
                return 0;
            } else {
                Fail("unknown argument: " + arg);
            }
        } catch (const std::exception& e) {
            Fail(arg + ": " + e.what());
        }
    }
    if (source.empty()) Fail("--source is required");
    // Accepting an option that does nothing invites a log claiming a run
    // configuration the stream never had.
    if (pf_budget_given && source != "pf")
        Fail("--pf-bytes-per-nonce applies only to --source pf (got --source " + source + ")");

    std::unique_ptr<rngstream::Source> src;
    try {
        src = rngstream::MakeSource(source, opt);
    } catch (const std::exception& e) {
        Fail(e.what());
    }

#if defined(_WIN32)
    // Without this, every 0x0A byte is written as 0x0D 0x0A and the battery
    // sees corrupted data — silently, since the stream still "looks" random.
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) Fail("could not set stdout to binary mode");
#endif

    // A short write has two very different causes and they must not be
    // conflated. A closed pipe is how an unbounded run normally ends (the
    // battery got what it wanted). Anything else — a full disk on the
    // runbook's `--bytes 125M > /tmp/x.bin` step, most plausibly — would
    // otherwise hand back a truncated file and exit 0, and the battery would
    // report a clean pass over data that was never generated.
    auto ReportWriteFailure = [](std::uint64_t written) -> int {
        if (errno == EPIPE) return 0;   // downstream closed: a normal ending
        std::fprintf(stderr, "rng_stream: write failed after %llu bytes: %s\n",
                     static_cast<unsigned long long>(written), ErrnoText(errno).c_str());
        return 1;
    };

    std::vector<std::uint8_t> buf(1 << 16);
    std::uint64_t written = 0;
    while (!limited || written < total) {
        std::size_t chunk = buf.size();
        if (limited && total - written < chunk) chunk = static_cast<std::size_t>(total - written);
        src->Fill(buf.data(), chunk);
        errno = 0;
        if (std::fwrite(buf.data(), 1, chunk, stdout) != chunk) return ReportWriteFailure(written);
        written += chunk;
    }
    errno = 0;
    if (std::fflush(stdout) != 0) return ReportWriteFailure(written);
    return 0;
}
