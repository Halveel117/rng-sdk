// stream_sources.hpp — the byte sources behind rng_stream.
//
// External statistical batteries (NIST SP 800-22, Dieharder, TestU01,
// PractRand) consume one thing: a raw stream of bytes. This header turns each
// of the SDK's distinct byte-producing code paths into such a stream, so the
// batteries test the shipped API rather than a bespoke harness.
//
// Design points, each one load-bearing (docs/design/
// 2026-08-18-statistical-batteries-design.md):
//
//  * Engine sources stream `Random<Engine>::NextBytes` — the call a consumer
//    actually makes — so the mapping layer and the DRBG engines' 4 KiB
//    buffering are inside the tested path. NIST CAVP vectors validate the
//    DRBG *core* only; a fault in that buffering would pass every vector
//    while making the real stream repeat.
//  * Sources are byte-buffered rather than delegating each Fill() straight to
//    NextBytes(). NextBytes draws a whole 64-bit word for a partial tail and
//    discards the remainder, so an unbuffered source would emit different
//    bytes depending on how the caller chunked its reads — and the tool
//    writes in fixed-size blocks. Buffering makes the split invisible.
//  * The Provably Fair source advances the *nonce*, not just the cursor:
//    correlation between adjacent nonces is the defect that would matter, and
//    a single nonce's cursor stream never reaches it.
//  * RANDU emits the top 16 bits of each 31-bit output, not the raw engine
//    word (which is 33 constant zero bits). The negative control has to fail
//    because of the lattice defect, not because of stuck bits — otherwise it
//    proves nothing about the harness's ability to detect structure.
//
// License: MIT.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

#include "rngsdk/rngsdk.hpp"
#include "randu_bad.hpp"

namespace rngstream {

// Strict non-negative decimal over text[0, count). Rejects everything
// std::stoull silently tolerates — leading whitespace, a '+' or '-' sign, a
// "0x" prefix, and trailing garbage ("1abc" parses as 1). That tolerance is
// the exact failure this tool exists to avoid: the runbook's adjudication
// protocol says to re-run a suspect source "with a different --seed", so a
// silently truncated seed would re-run the identical stream while the log
// records a different one.
inline std::uint64_t ParseDecimal(const std::string& text, std::size_t count,
                                  const char* what) {
    if (count == 0)
        throw std::invalid_argument(std::string(what) + " has no digits: '" + text + "'");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const char c = text[i];
        if (c < '0' || c > '9')
            throw std::invalid_argument(std::string(what) + " is not a decimal number: '" + text + "'");
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10)
            throw std::invalid_argument(std::string(what) + " overflows 64 bits: '" + text + "'");
        value = value * 10 + digit;
    }
    return value;
}

// A plain count with no unit suffix (seeds, per-nonce budgets).
inline std::uint64_t ParseU64(const std::string& text, const char* what = "value") {
    return ParseDecimal(text, text.size(), what);
}

// Byte count with an optional K/M/G suffix (powers of 1024). Every malformed
// input is rejected: a tool that silently defaults after a typo produces a
// battery log that names one run and describes another.
inline std::uint64_t ParseByteCount(const std::string& text) {
    if (text.empty()) throw std::invalid_argument("byte count is empty");

    std::uint64_t multiplier = 1;
    std::size_t digits = text.size();
    switch (text.back()) {
        case 'K': case 'k': multiplier = 1024ull; --digits; break;
        case 'M': case 'm': multiplier = 1024ull * 1024; --digits; break;
        case 'G': case 'g': multiplier = 1024ull * 1024 * 1024; --digits; break;
        default: break;
    }
    const std::uint64_t value = ParseDecimal(text, digits, "byte count");
    if (multiplier > 1 && value > UINT64_MAX / multiplier)
        throw std::invalid_argument("byte count overflows 64 bits: '" + text + "'");
    return value * multiplier;
}

class Source {
public:
    virtual ~Source() = default;
    // Emits exactly n bytes. Splitting a run across calls must not change the
    // byte sequence — the tool relies on this, and so do the batteries.
    virtual void Fill(std::uint8_t* out, std::size_t n) = 0;
};

struct Options {
    std::uint64_t seed = 1;
    std::size_t pf_bytes_per_nonce = 32;   // one HMAC block = one bet's worth
};

inline constexpr const char* kStreamClientSeed = "rngsdk-stream-client";

// Deterministic server seed for the Provably Fair source, so a run is fully
// reproducible from --seed alone. Hex-encoded SHA-256 => 256 bits, matching
// pf::GenerateServerSeed()'s width (this one is deterministic *by design*:
// a battery run must be repeatable, which a real session's seed must not be).
inline std::string ServerSeedForStream(std::uint64_t seed) {
    return rngsdk::crypto::ToHex(
        rngsdk::crypto::Sha256::Hash("rngsdk stream server seed:" + std::to_string(seed)));
}

namespace detail {

// Buffers whole production units so callers may read in any chunk sizes.
class BufferedSource : public Source {
public:
    void Fill(std::uint8_t* out, std::size_t n) final {
        while (n > 0) {
            if (pos_ == len_) {
                len_ = Produce(buf_, sizeof buf_);
                // A zero-length production would spin forever with no output
                // and no error — the worst failure mode for a tool feeding a
                // multi-hour battery run. Fail loudly instead.
                if (len_ == 0) throw std::logic_error("stream source produced no bytes");
                pos_ = 0;
            }
            const std::size_t take = (n < len_ - pos_) ? n : len_ - pos_;
            std::memcpy(out, buf_ + pos_, take);
            out += take;
            pos_ += take;
            n -= take;
        }
    }

protected:
    // Fills up to cap bytes, returning how many. Must return > 0.
    virtual std::size_t Produce(std::uint8_t* out, std::size_t cap) = 0;

private:
    std::uint8_t buf_[4096] = {0};
    std::size_t pos_ = 0;
    std::size_t len_ = 0;
};

template <class Engine>
class EngineSource : public BufferedSource {
public:
    explicit EngineSource(std::uint64_t seed) : rng_(seed) {}

protected:
    std::size_t Produce(std::uint8_t* out, std::size_t cap) override {
        const std::size_t whole_words = (cap / 8) * 8;   // never split a word
        rng_.NextBytes(out, whole_words);
        return whole_words;
    }

private:
    rngsdk::Random<Engine> rng_;
};

// Provably Fair: HMAC-SHA256(server_seed, client_seed:nonce:cursor), a fixed
// budget of bytes per nonce, then the next nonce.
class PfSource : public BufferedSource {
public:
    PfSource(std::uint64_t seed, std::size_t bytes_per_nonce)
        : server_seed_(ServerSeedForStream(seed)), bytes_per_nonce_(bytes_per_nonce) {
        if (bytes_per_nonce_ == 0)
            throw std::invalid_argument("pf bytes-per-nonce must be positive");
    }

protected:
    std::size_t Produce(std::uint8_t* out, std::size_t cap) override {
        if (remaining_ == 0) {
            stream_.reset(new rngsdk::pf::ByteStream(server_seed_, kStreamClientSeed, nonce_++));
            remaining_ = bytes_per_nonce_;
        }
        const std::size_t take = (cap < remaining_) ? cap : remaining_;
        stream_->Fill(out, take);
        remaining_ -= take;
        return take;
    }

private:
    std::string server_seed_;
    std::size_t bytes_per_nonce_;
    std::unique_ptr<rngsdk::pf::ByteStream> stream_;
    std::uint64_t nonce_ = 0;
    std::size_t remaining_ = 0;
};

// RANDU (IBM, 1968): x <- 65539*x mod 2^31. Consecutive triples lie on 15
// planes in 3-space. Included deliberately as the negative control — it MUST
// fail the batteries, or the harness cannot detect failure and every other
// result in the report is void.
class RanduSource : public BufferedSource {
public:
    explicit RanduSource(std::uint64_t seed) : randu_(seed) {}

protected:
    std::size_t Produce(std::uint8_t* out, std::size_t cap) override {
        const std::size_t pairs = cap / 2;               // never split an output
        for (std::size_t i = 0; i < pairs; ++i) {
            const std::uint32_t top16 = randu_.NextRaw31() >> 15;   // 31 -> 16 bits
            out[2 * i] = static_cast<std::uint8_t>(top16 >> 8);
            out[2 * i + 1] = static_cast<std::uint8_t>(top16 & 0xFF);
        }
        return pairs * 2;
    }

private:
    rngtools::RanduBad randu_;
};

} // namespace detail

// Names are the ones written into battery logs and the runbook; an unknown
// name is a hard error, never a silent substitution.
inline std::unique_ptr<Source> MakeSource(const std::string& name, const Options& opt) {
    if (name == "xoshiro")
        return std::unique_ptr<Source>(new detail::EngineSource<rngsdk::Xoshiro256pp>(opt.seed));
    if (name == "pcg64")
        return std::unique_ptr<Source>(new detail::EngineSource<rngsdk::Pcg64>(opt.seed));
    if (name == "hmac")
        return std::unique_ptr<Source>(
            new detail::EngineSource<rngsdk::crypto::HmacDrbgEngine>(opt.seed));
    if (name == "ctr") {
#if defined(RNGSDK_USE_OPENSSL)
        return std::unique_ptr<Source>(
            new detail::EngineSource<rngsdk::crypto::CtrDrbgEngine>(opt.seed));
#else
        throw std::invalid_argument(
            "source 'ctr' needs the OpenSSL backend: rebuild with -DRNGSDK_USE_OPENSSL=ON");
#endif
    }
    if (name == "pf") return std::unique_ptr<Source>(new detail::PfSource(opt.seed, opt.pf_bytes_per_nonce));
    if (name == "randu") return std::unique_ptr<Source>(new detail::RanduSource(opt.seed));
    throw std::invalid_argument("unknown source: '" + name +
                                "' (expected xoshiro, pcg64, hmac, ctr, pf, randu)");
}

} // namespace rngstream
