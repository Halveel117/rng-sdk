// c_api/src/engine_box.hpp — internal type erasure over rngsdk::Random<E>.
//
// NOT part of the ABI and NOT installed. It exists because the four
// Random<E> instantiations share no base class, so a single opaque C handle
// needs one supplied.
//
// THE BULK RULE. Every virtual here takes a count and fills a buffer. There
// is deliberately no `virtual std::uint64_t NextU64()`. Crossing the library
// boundary and dispatching a virtual costs about as much as generating a
// xoshiro word (~1.5 ns), so a one-value-per-call design would make the fast
// tier measure at a fraction of its real throughput. With the loop inside
// EngineBoxT<E>, E is concrete, r.NextUInt64() inlines, and the crossing is
// amortised over n. The scalar C functions are bulk calls with n == 1.
//
// License: MIT.
#pragma once
#include <cstddef>
#include <cstdint>
#include <utility>

#include "rngsdk/rngsdk.hpp"

namespace rngsdk_c_detail {

struct EngineBox {
    virtual ~EngineBox() = default;
    virtual void Seed(std::uint64_t seed) = 0;
    virtual void FillU64(std::uint64_t* out, std::size_t n) = 0;
    virtual void FillU32(std::uint32_t* out, std::size_t n) = 0;
    virtual void FillDouble(double* out, std::size_t n) = 0;
    virtual void FillFloat(float* out, std::size_t n) = 0;
    virtual void FillBoundedU64(std::uint64_t bound, std::uint64_t* out, std::size_t n) = 0;
    virtual void FillBoundedU32(std::uint32_t bound, std::uint32_t* out, std::size_t n) = 0;
    virtual void FillIntRange(std::int64_t lo, std::int64_t hi, std::int64_t* out, std::size_t n) = 0;
    virtual void FillBytes(std::uint8_t* out, std::size_t n) = 0;
};

template <class E>
struct EngineBoxT final : EngineBox {
    rngsdk::Random<E> r;

    // Default: whatever E's default constructor does. For the DRBG engines
    // that is OS entropy (the secure default); for the fast tier it is the
    // fixed constant, which is why rngsdk_random_create_secure never uses
    // this path for xoshiro/PCG — see rngsdk_c.cpp.
    EngineBoxT() = default;

    // Caller constructed the engine (seeded, or state-seeded from OS bytes).
    // By value + move so it also accepts move-only engines such as
    // CtrDrbgEngine.
    explicit EngineBoxT(E e) : r(std::move(e)) {}

    void Seed(std::uint64_t seed) override { r.Seed(seed); }

    void FillU64(std::uint64_t* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextUInt64();
    }
    void FillU32(std::uint32_t* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextUInt32();
    }
    void FillDouble(double* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextDouble();
    }
    void FillFloat(float* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextFloat();
    }
    void FillBoundedU64(std::uint64_t bound, std::uint64_t* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextUInt64(bound);
    }
    void FillBoundedU32(std::uint32_t bound, std::uint32_t* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextUInt32(bound);
    }
    void FillIntRange(std::int64_t lo, std::int64_t hi, std::int64_t* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextInt(lo, hi);
    }
    // Already bulk in the C++ — one call, no loop here.
    void FillBytes(std::uint8_t* out, std::size_t n) override { r.NextBytes(out, n); }
};

} // namespace rngsdk_c_detail
