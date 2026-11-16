// quickstart.cpp — the SDK's API in 60 lines. Build & run: rng_quickstart.
#include <cstdio>

#include "rngsdk/rngsdk.hpp"

int main() {
    using namespace rngsdk;

    // ---- Fast mode: simulations, non-fairness game logic ----
    FastRandom fast(std::uint64_t{12345});           // xoshiro256++
    std::printf("fast  u64    : %llu\n", static_cast<unsigned long long>(fast.NextUInt64()));
    std::printf("fast  u32    : %u\n", fast.NextUInt32());
    std::printf("fast  double : %.17f\n", fast.NextDouble());
    std::printf("fast  float  : %.9f\n", static_cast<double>(fast.NextFloat()));
    std::printf("fast  d6     : %llu\n", static_cast<unsigned long long>(fast.NextUInt64(6) + 1));

    // ---- Crypto mode: SP 800-90A HMAC-DRBG ----
    // Explicit seed = deterministic stream (demo/tests). In production just
    // default-construct: `CryptoRandom rng;` seeds itself from the OS CSPRNG
    // (BCryptGenRandom / getrandom) and throws if that source fails.
    CryptoRandom secure(std::uint64_t{12345});
    std::printf("drbg  u64    : %llu\n", static_cast<unsigned long long>(secure.NextUInt64()));
    std::uint8_t buf[8];
    secure.NextBytes(buf, sizeof buf);
    std::printf("drbg  bytes  : %s\n", crypto::ToHex(buf, sizeof buf).c_str());

    // ---- Provably Fair: commit -> play -> reveal -> verify ----
    // Fixed seed for a reproducible demo; production sessions use
    // pf::GenerateServerSeed() — 256 bits from the OS CSPRNG. Even the demo
    // seed must clear ServerSession::kMinServerSeedChars: a short seed is
    // recoverable from the published commitment by brute force.
    pf::ServerSession session("demo-server-seed-0123456789abcdef");
    std::printf("prod seed ex : %s\n", pf::GenerateServerSeed().c_str());
    std::printf("commitment   : %s\n", session.CommitmentHex().c_str());   // publish FIRST
    session.SetClientSeed("my-client-seed");                                // player's choice
    const auto roll = session.Play(1);                                      // nonce 0
    std::printf("outcome      : %.10f (dice: %d)\n", roll[0], 1 + static_cast<int>(roll[0] * 6));

    // Player-side verification after reveal:
    const std::string revealed = session.Reveal();
    const bool ok = pf::VerifyCommitment(revealed, session.CommitmentHex());
    const auto replay = pf::Generator::NextFloats(revealed, "my-client-seed", 0, 1);
    std::printf("verify       : commitment %s, replay %s\n",
                ok ? "OK" : "FAIL", replay[0] == roll[0] ? "matches" : "MISMATCH");
    return 0;
}
