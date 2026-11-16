// rngsdk/crypto/ctr_drbg_engine.hpp — CtrDrbg behind the shared
// BufferedDrbgEngine adapter (drbg_engine.hpp), so both crypto engines are
// drop-in interchangeable behind Random<Engine> and share one buffering path.
//
// The only CTR-specific part is the 64-bit seed expansion: the no-df variant
// needs exactly seedlen = 48 bytes, so a short seed is never quietly
// zero-padded. Same secure default as the HMAC engine: `CtrRandom rng;`
// draws OS entropy and throws if that fails.
//
// License: MIT.
#pragma once
#include <cstdint>
#include <cstring>

#include "ctr_drbg.hpp"
#include "drbg_engine.hpp"
#include "sha256.hpp"

namespace rngsdk {
namespace crypto {
namespace detail {

// 64-bit seed -> 48 bytes (seedlen) from two domain-separated SHA-256 blocks.
inline Bytes CtrSeedFrom64(std::uint64_t seed) {
    Bytes material(sizeof(seed) + 16);
    std::memcpy(material.data(), "rngsdk-ctr-seed!", 16);
    std::memcpy(material.data() + 16, &seed, sizeof(seed));
    const auto h1 = Sha256::Hash(material);
    material[15] ^= 0x01;         // domain-separate the 2nd block from the 1st
    const auto h2 = Sha256::Hash(material);
    Bytes seed_bytes;
    seed_bytes.reserve(CtrDrbg::kSeedLen);
    seed_bytes.insert(seed_bytes.end(), h1.begin(), h1.end());          // 32
    seed_bytes.insert(seed_bytes.end(), h2.begin(), h2.begin() + 16);   // +16 = 48
    return seed_bytes;
}

} // namespace detail

using CtrDrbgEngine = BufferedDrbgEngine<CtrDrbg, &detail::CtrSeedFrom64>;

} // namespace crypto
} // namespace rngsdk
