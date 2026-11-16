// integration_demo.cpp — a complete, correct Provably Fair session, end to end.
// This is the code docs/INTEGRATION_GUIDE.md quotes; it is a build target so
// the guide cannot drift from something that compiles. Build & run:
// rng_integration_demo.
#include <cstdio>
#include <string>

#include "rngsdk/rngsdk.hpp"

using namespace rngsdk;

// Stands in for the operator's durable storage. The nonce MUST outlive the
// process: a restart that re-instantiates ServerSession at 0 replays outcomes
// the player has already seen. See INTEGRATION_GUIDE obligation 2.
struct SessionRecord {
    std::string server_seed;
    std::string commitment;
    std::uint64_t next_nonce = 0;
};

int main() {
    SessionRecord db;

    // 1. BEFORE PLAY — generate a server seed and publish its commitment.
    //    GenerateServerSeed() draws 256 bits from the OS CSPRNG and throws if
    //    that source fails. Never a literal, and never anything derived from a
    //    counter or a timestamp: the published commitment is a free offline
    //    brute-force oracle.
    db.server_seed = pf::GenerateServerSeed();
    pf::ServerSession session(db.server_seed);
    db.commitment = session.CommitmentHex();
    std::printf("published commitment : %s\n", db.commitment.c_str());

    // 2. THE PLAYER sets their own seed, on their device, after seeing the
    //    commitment. Anything the operator generates here is not binding.
    const std::string client_seed = "d4f1a9c3b07e28516a3fbc90d2e847af";
    session.SetClientSeed(client_seed);

    // 3. PLAY — one call per bet; the nonce advances and never rewinds.
    const auto bet0 = session.Play(1);
    const auto bet1 = session.Play(1);
    db.next_nonce = session.NextNonce();     // persist after every bet
    std::printf("bet 0 (nonce 0)      : %.17f -> d6 %d\n",
                bet0[0], 1 + static_cast<int>(bet0[0] * 6));
    std::printf("bet 1 (nonce 1)      : %.17f -> d6 %d\n",
                bet1[0], 1 + static_cast<int>(bet1[0] * 6));
    std::printf("persisted next nonce : %llu\n",
                static_cast<unsigned long long>(db.next_nonce));

    // 4. END OF SESSION — reveal. Play() refuses to run after this point,
    //    because every subsequent outcome would be publicly computable.
    const std::string revealed = session.Reveal();
    std::printf("revealed server seed : %s\n", revealed.c_str());

    // 5. ANYONE can now verify, with no access to the operator's systems.
    const bool commitment_ok = pf::VerifyCommitment(revealed, db.commitment);
    const auto replay0 = pf::Generator::NextFloats(revealed, client_seed, 0, 1);
    const auto replay1 = pf::Generator::NextFloats(revealed, client_seed, 1, 1);
    std::printf("commitment           : %s\n", commitment_ok ? "OK" : "MISMATCH");
    std::printf("replay               : %s\n",
                (replay0[0] == bet0[0] && replay1[0] == bet1[0]) ? "matches" : "MISMATCH");

    // 6. RESUMPTION after a restart: continue from the persisted nonce.
    //    Starting at 0 here is the SA-01 replay defect by another route.
    pf::ServerSession resumed(db.server_seed, db.next_nonce);
    resumed.SetClientSeed(client_seed);
    std::printf("resumed at nonce     : %llu\n",
                static_cast<unsigned long long>(resumed.NextNonce()));
    return 0;
}
