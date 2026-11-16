// rngsdk/provably_fair.hpp — commit–reveal Provably Fair scheme.
//
// Scheme (industry-standard, Stake-compatible byte derivation):
//
//   commitment = SHA-256(server_seed)          — published BEFORE play
//   bytes(i)   = HMAC-SHA256(key = server_seed,
//                            msg = client_seed ":" nonce ":" cursor)
//                cursor = 0,1,2,... one increment per 32-byte block
//   result     = map(bytes)                    — floats / bounded ints
//
// Design decisions and their reasoning:
//  * commit–reveal is MANDATORY: without the prior SHA-256 commitment the
//    server could grind server seeds after seeing the player's bets. The
//    player verifies SHA-256(revealed_seed) == commitment, then recomputes
//    every result. Server seed must be high-entropy (>= 128 bits) so the
//    commitment can't be brute-forced *forward* before reveal.
//  * server_seed is the HMAC *key*, client_seed goes in the message: the
//    player controls the message half, the server the key half; neither can
//    predict outputs alone, and HMAC's PRF security means outputs reveal
//    nothing about the key until reveal.
//  * nonce is a strictly monotonic uint64 counter, enforced by ServerSession
//    for the life of a session and never rewound — not even when the client
//    seed changes. Reusing a (server, client, nonce) triple would reproduce
//    an outcome the player has already seen, which is directly monetisable;
//    see SECURITY_ANALYSIS.md §5.1 and TestClientSeedReuseDoesNotReplay.
//    (This bullet previously credited enforcement to a "VerifierSession" that
//    does not exist in this codebase, and described the counter as per-(server,
//    client) pair — the design that produced the replay bug.)
//  * cursor extends one bet's stream beyond 32 bytes (multi-card draws etc.)
//    without a scheme change — same trick Stake documents publicly.
//
// Two outcome mappings are provided deliberately:
//  * FloatFromBytes / NextFloats: 4 bytes -> sum b_i/256^(i+1), the exact
//    industry-compatible construction (32-bit resolution). floor(f*N) has a
//    bias <= N/2^32 relative deviation — negligible for game-sized N but
//    NOT zero.
//  * NextIntsUnbiased: Lemire rejection over the HMAC byte stream — exactly
//    unbiased for any N; use this when "provably no bias" must hold in the
//    math doc, at the cost of not matching other operators' verifiers.
//
// License: MIT.
#pragma once
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/hmac_sha256.hpp"
#include "crypto/os_entropy.hpp"
#include "crypto/sha256.hpp"
#include "detail/uint128.hpp"

namespace rngsdk {
namespace pf {

using crypto::Bytes;

// SHA-256 hex commitment for a server seed. Publish before play.
inline std::string Commitment(const std::string& server_seed) {
    return crypto::ToHex(crypto::Sha256::Hash(server_seed));
}

inline bool VerifyCommitment(const std::string& server_seed, const std::string& commitment_hex) {
    return Commitment(server_seed) == commitment_hex;
}

// Fresh server seed: 32 bytes (256 bits) from the OS CSPRNG, hex-encoded.
// This is the value whose SHA-256 commitment gets published — it MUST be
// unguessable, because the commitment is a free offline brute-force oracle
// (enumerate seeds, hash, compare). 256 bits doubles the documented 128-bit
// floor and gives fleet-wide birthday headroom. Throws if the OS entropy
// source fails (never silently degrades). One seed per session; discard
// after Reveal().
inline std::string GenerateServerSeed() {
    return crypto::ToHex(crypto::OsEntropy(32));
}

// Deterministic byte stream for one bet: HMAC-SHA256 blocks with a cursor.
class ByteStream {
public:
    ByteStream(std::string server_seed, std::string client_seed, std::uint64_t nonce)
        : server_seed_(std::move(server_seed)),
          client_seed_(std::move(client_seed)),
          nonce_(nonce) {}

    std::uint8_t NextByte() {
        if (pos_ == 32) NextBlock();
        return block_[pos_++];
    }

    void Fill(std::uint8_t* out, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i) out[i] = NextByte();
    }

    std::uint64_t NextUInt64() {
        std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x = (x << 8) | NextByte();
        return x;
    }

private:
    void NextBlock() {
        const std::string msg = client_seed_ + ":" + std::to_string(nonce_) + ":" + std::to_string(cursor_);
        const auto mac = crypto::HmacSha256(server_seed_.data(), server_seed_.size(),
                                            msg.data(), msg.size());
        for (int i = 0; i < 32; ++i) block_[i] = mac[i];
        ++cursor_;
        pos_ = 0;
    }

    std::string server_seed_;
    std::string client_seed_;
    std::uint64_t nonce_;
    std::uint64_t cursor_ = 0;
    std::uint8_t block_[32] = {0};
    std::size_t pos_ = 32;   // force first block
};

// Industry-standard float: 4 bytes -> [0, 1) with 32-bit resolution.
inline double FloatFromBytes(const std::uint8_t b[4]) {
    return b[0] / 256.0 + b[1] / 65536.0 + b[2] / 16777216.0 + b[3] / 4294967296.0;
}

// The core Provably Fair generator: Result = RNG(ServerSeed, ClientSeed, Nonce).
class Generator {
public:
    // n floats in [0, 1), industry-compatible mapping.
    static std::vector<double> NextFloats(const std::string& server_seed,
                                          const std::string& client_seed,
                                          std::uint64_t nonce, std::size_t n) {
        ByteStream bs(server_seed, client_seed, nonce);
        std::vector<double> out;
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            std::uint8_t b[4];
            bs.Fill(b, 4);
            out.push_back(FloatFromBytes(b));
        }
        return out;
    }

    // n integers in [0, bound), industry-compatible: floor(f * bound).
    // Bias <= bound/2^32 (documented); use NextIntsUnbiased for exact.
    static std::vector<std::uint64_t> NextInts(const std::string& server_seed,
                                               const std::string& client_seed,
                                               std::uint64_t nonce, std::size_t n,
                                               std::uint64_t bound) {
        auto fs = NextFloats(server_seed, client_seed, nonce, n);
        std::vector<std::uint64_t> out;
        out.reserve(n);
        for (double f : fs) out.push_back(static_cast<std::uint64_t>(f * static_cast<double>(bound)));
        return out;
    }

    // n integers in [0, bound) with ZERO bias: Lemire rejection over the
    // HMAC byte stream (consumes 8 bytes per attempt).
    //
    // Precondition: bound != 0. `(0 - bound) % bound` below is integer
    // division by zero for bound == 0 — a hardware trap, not a C++
    // exception, so it cannot be caught by a caller's try/catch. Unlike
    // Random::NextUInt64(bound) (random.hpp), which treats bound == 0 as a
    // degenerate no-op and returns 0, this path throws: NextIntsUnbiased is
    // reachable directly from untrusted-ish CLI/UI input (rng_verifier,
    // web/verifier.html) where a silent 0 would be a worse failure mode than
    // a clear rejection.
    static std::vector<std::uint64_t> NextIntsUnbiased(const std::string& server_seed,
                                                       const std::string& client_seed,
                                                       std::uint64_t nonce, std::size_t n,
                                                       std::uint64_t bound) {
        if (bound == 0) {
            throw std::invalid_argument("NextIntsUnbiased: bound must be > 0");
        }
        ByteStream bs(server_seed, client_seed, nonce);
        std::vector<std::uint64_t> out;
        out.reserve(n);
        const std::uint64_t t = (0 - bound) % bound;   // 2^64 mod bound
        for (std::size_t i = 0; i < n; ++i) {
            for (;;) {
                const std::uint64_t x = bs.NextUInt64();
                const detail::u128 m = detail::mul64x64(x, bound);
                if (m.lo >= t) { out.push_back(m.hi); break; }
            }
        }
        return out;
    }
};

// The spec's API line verbatim: Result = RNG(ServerSeed, ClientSeed, Nonce).
// One bet, one outcome. A pure alias for the n == 1 case of NextFloats, so it
// cannot drift from the stream every verifier reimplements.
inline double Generate(const std::string& server_seed,
                       const std::string& client_seed,
                       std::uint64_t nonce) {
    return Generator::NextFloats(server_seed, client_seed, nonce, 1)[0];
}

// Server-side session enforcing the protocol order and nonce monotonicity.
//
// Every guarantee below is bound to a test; none of them is a claim made only
// here. (This class previously asserted nonce monotonicity in prose while
// SetClientSeed silently reset the counter — see SECURITY_ANALYSIS.md §5.1.)
//
//   nonce never rewinds            -> TestClientSeedReuseDoesNotReplay
//   overflow refused, not wrapped  -> TestNonceOverflowRefused
//   weak server seed refused       -> TestWeakServerSeedRefused
//   client seed must be explicit   -> TestPlayWithoutClientSeedRefused
//   no play after reveal           -> TestRevealLock
class ServerSession {
public:
    // Length floor on the server seed. The published commitment is a free
    // offline brute-force oracle (enumerate seeds, hash, compare), so a
    // hand-typed seed is recoverable before reveal and hands the player every
    // future outcome. 32 chars = 128 bits IF the seed is hex-encoded, which is
    // what GenerateServerSeed() produces and the only supported path.
    //
    // Length is a PROXY for entropy, not a measure of it: this rejects the
    // realistic failure (a short typed seed) and cannot detect a long seed
    // derived from a counter. Use GenerateServerSeed().
    static constexpr std::size_t kMinServerSeedChars = 32;

    // start_nonce exists for session resumption: a server that restarts
    // mid-session must continue where it left off, because re-instantiating at
    // 0 with the same seed pair replays outcomes the player has already seen —
    // the same defect as the old SetClientSeed reset.
    explicit ServerSession(std::string server_seed, std::uint64_t start_nonce = 0)
        : server_seed_(std::move(server_seed)),
          commitment_(Commitment(server_seed_)),
          next_nonce_(start_nonce) {
        if (server_seed_.size() < kMinServerSeedChars)
            throw std::invalid_argument(
                "ServerSession: server seed shorter than " +
                std::to_string(kMinServerSeedChars) +
                " characters — the published commitment is an offline "
                "brute-force oracle and a weak seed is recoverable before "
                "reveal. Use pf::GenerateServerSeed().");
    }

    const std::string& CommitmentHex() const { return commitment_; }   // publish this first

    // The player's move, and it MUST be the player's: a client seed the
    // operator can predict at commit time lets it grind candidate server seeds
    // and commit to a favourable one. Generate this on the player's device.
    //
    // The nonce deliberately does NOT reset here. Resetting would make a
    // re-selected client seed reproduce outcomes the player has already seen;
    // letting the counter run makes that reuse harmless instead of forbidden,
    // so the guarantee needs no bookkeeping to hold.
    void SetClientSeed(std::string client_seed) {
        client_seed_ = std::move(client_seed);
        client_seed_set_ = true;
    }

    // Each call = one bet; nonce strictly monotonic, never reused.
    std::vector<double> Play(std::size_t n_floats) {
        if (revealed_)
            throw std::runtime_error("ServerSession: Play() called after Reveal() — "
                                     "every future result is publicly computable once "
                                     "the seed is revealed");
        if (!client_seed_set_)
            throw std::runtime_error("ServerSession: Play() before SetClientSeed() — "
                                     "a client seed the operator knows at commit time "
                                     "defeats commit–reveal. Set the player's seed.");
        // Unreachable at 2^64 bets (~585,000 years at 10^6 bets/s), but a
        // silent wrap would reuse nonces, so refuse rather than rely on the
        // arithmetic argument holding for every future caller.
        if (next_nonce_ == std::numeric_limits<std::uint64_t>::max())
            throw std::runtime_error("ServerSession: nonce space exhausted — "
                                     "rotate the server seed rather than wrapping, "
                                     "which would replay earlier outcomes");
        return Generator::NextFloats(server_seed_, client_seed_, next_nonce_++, n_floats);
    }

    std::uint64_t NextNonce() const { return next_nonce_; }

    // End of session: reveal. After this the seed must never be used again —
    // enforced: Play() throws once revealed_ is set. (Player-side replay via
    // the free Generator functions after reveal is fine and expected; only
    // this session object's own generation is locked.)
    const std::string& Reveal() {
        revealed_ = true;
        return server_seed_;
    }

private:
    std::string server_seed_;
    std::string commitment_;
    bool revealed_ = false;
    std::string client_seed_;
    bool client_seed_set_ = false;
    std::uint64_t next_nonce_;
};

} // namespace pf
} // namespace rngsdk
