// rngsdk.hpp — umbrella header for the RNG-SDK prototype.
//
// Two modes, one API (see README.md):
//   Fast:   rngsdk::FastRandom   (xoshiro256++ default) / rngsdk::Pcg64Random
//   Crypto: rngsdk::CryptoRandom (HMAC-SHA256-DRBG, NIST SP 800-90A)
//           rngsdk::CtrRandom    (AES-256-CTR-DRBG, SP 800-90A) — OpenSSL builds only
//   Fair:   rngsdk::pf::*        (commit–reveal Provably Fair)
//
// License: MIT.
#pragma once

#include "detail/uint128.hpp"
#include "splitmix64.hpp"
#include "xoshiro256pp.hpp"
#include "pcg64.hpp"
#include "crypto/sha256.hpp"
#include "crypto/hmac_sha256.hpp"
#include "crypto/hmac_drbg.hpp"
#include "crypto/drbg_engine.hpp"
#if defined(RNGSDK_USE_OPENSSL)
#include "crypto/ctr_drbg.hpp"          // AES comes from OpenSSL; never hand-rolled
#include "crypto/ctr_drbg_engine.hpp"
#endif
#include "random.hpp"
#include "provably_fair.hpp"

namespace rngsdk {

using FastRandom   = Random<Xoshiro256pp>;
using Pcg64Random  = Random<Pcg64>;
using CryptoRandom = Random<crypto::HmacDrbgEngine>;
#if defined(RNGSDK_USE_OPENSSL)
using CtrRandom    = Random<crypto::CtrDrbgEngine>;
#endif

constexpr const char* kVersion = "0.1.0-prototype";

} // namespace rngsdk
