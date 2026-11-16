# C ABI wrapper — design (OPEN_RESEARCH item #8, third bullet)

Date: 2026-09-02. Status: approved, pre-implementation.

## 1. Purpose

The SDK is a header-only C++17 library. That is the right shape for a C++
integrator and the wrong shape for almost everyone else: a casino platform is
typically C#, Java, Node, Go, or Python, and none of those languages can call
C++ across a binary boundary. Not "with difficulty" — at all. There is no
stable C++ ABI to target: symbol names are mangled differently by every
compiler, `std::string`'s layout differs between libstdc++, libc++, MSVC
debug and MSVC release, templates are not code until instantiated, and an
exception unwinding into a foreign frame is undefined behaviour rather than
an error. Every one of those obstacles disappears in C, whose ABI has been
stable for decades and which every language on the list already speaks
through its own FFI (ctypes/cffi, DllImport, JNI/Panama, cgo, N-API).

This item adds a thin C-linkage translation layer over the existing C++ so
the SDK can be consumed as a binary by any of them. It changes nothing about
the C++ core.

Four reasons it earns its place:

* **It converts "a C++ library" into "an SDK".** Today integration means
  adopting a source dependency and a C++17 toolchain. After this it means
  dropping in one shared library and one header. That is the difference
  between a component and a product.
* **Most of the target market cannot use the SDK at all right now.** This is
  not an inconvenience to be documented; it is an unusable deliverable for
  the majority of the platforms it is meant to be licensed to.
* **The exported symbol list becomes a machine-checkable spec.** A
  header-only template library structurally cannot promise "v1.x will not
  break your binary" — there is no binary. A C ABI can, and that promise is
  worth real money to a licensee planning a multi-year deployment.
* **It adds a fourth axis to the Provably Fair cross-check, and a
  qualitatively better one.** The existing three-way check (Python / C++ / JS)
  compares three *reimplementations*. The Python ctypes binding in §7 has
  another language calling the **actual shipped library**, so it validates the
  artifact a licensee receives rather than a parallel description of it.

## 2. Scope

**In scope:** the full SDK surface — all four engines, the complete mapping
layer, the stateless Provably Fair generator functions, and `ServerSession` —
exposed through a C header and built as both a shared and a static library.
Plus the three verification layers in §7.

**Explicitly not in scope:** any change to the C++ core. `include/rngsdk/`
is not modified by this item. If the wrapper needs behaviour the C++ does not
have, that is a finding to record, not a licence to edit the core inside a
wrapper task.

**Deferred (recorded, not silently dropped):** an exported-symbol snapshot
test (dump `dumpbin`/`nm` output, diff against a committed baseline so an
accidental ABI change fails the build). Considered and declined for this pass
— it needs platform-specific tooling in the build for a guarantee nothing yet
depends on. It becomes worth doing at the point a version is actually shipped
to a licensee under a compatibility promise.

## 3. Why the design is shaped the way it is

Four constraints drove every decision below. They are recorded here because
each one is a place where the obvious C API is wrong.

### 3.1 `Random<Engine>` is a template, so there is nothing to export

`FastRandom`, `Pcg64Random`, `CryptoRandom` and `CtrRandom` are four
instantiations of one template (`rngsdk.hpp:29-34`). A template is not code
until instantiated, and a binary interface needs concrete, already-generated
functions. The wrapper must therefore pick which instantiations become real
exported symbols — and it must do so in a way that does not force an ABI
break when a fifth engine is added later. Hence §4's single opaque handle
with a runtime engine tag, rather than one handle type per engine.

### 3.2 Crossing the boundary costs more than generating a number

`xoshiro256++` benchmarks at 6.4e8 u64/s — about 1.5 ns per value. A
non-inlinable cross-library call plus a virtual dispatch is of the same order
or larger. A naive one-value-per-call C API would therefore make the fast
tier measure at a fraction of its real throughput, and a licensee
benchmarking through the wrapper would reasonably conclude the SDK's
published performance figures are fiction. Through Python's ctypes, where per
call overhead is ~1 µs, the loss is roughly three orders of magnitude.

The fix is structural, not an optimisation to add later: **every generator
call has an array form**, and the loop lives *inside* the wrapper where the
concrete `Random<E>` is visible and fully inlinable. One boundary crossing
and one virtual dispatch are then amortised over `n` values. The scalar forms
remain for convenience and are documented as such — not for use in loops, and
not for benchmarking.

### 3.3 Secure-by-default must survive the translation

`HmacDrbgEngine()` and `CtrDrbgEngine()` default-construct from OS entropy;
`Xoshiro256pp()` and `Pcg64()` default-construct from a fixed constant
(`0xDEFA017DEFA017`). Item #1's whole point was that `CryptoRandom rng;` can
never silently mean "seed 0". A single `create(kind, seed, seed_len)` where a
null seed pointer means "unseeded" would collapse that distinction into an
easy-to-miss argument. Creation is therefore split into three explicitly
named functions (§5.2) where the caller cannot express "secure" and
"deterministic" ambiguously.

`CtrDrbgEngine::SeedBytes` additionally requires **exactly** 48 bytes — it
rejects short entropy rather than zero-extending it, which was one of the two
SP 800-90A conformance defects the CTR-DRBG review caught. That rejection
must surface as its own status code, not fold into a generic error.

### 3.4 The C++ error model is not internally consistent, and one enum exposes it

`Random::NextUInt64(0)` returns 0, documented in-place as "degenerate;
document as caller error" (`random.hpp:73`). `pf::Generator::NextIntsUnbiased`
with `bound == 0` throws `std::invalid_argument` (`provably_fair.hpp:171`),
because there the zero would reach a hardware divide trap that no `catch` can
intercept. Both choices are defensible in C++ and each is documented where it
lives.

Behind a single C status enum they are not defensible: two functions with
identically-shaped arguments would behave differently for the same input,
with nothing at the C level to explain why. **Resolution: the C ABI returns
`RNGSDK_ERR_INVALID_BOUND` for `bound == 0` everywhere**, including the
`next_bounded` family whose underlying C++ would have returned 0. This is a
deliberate narrowing at the boundary — the wrapper refuses to forward an
input the C++ itself already labels a caller error — and it is documented as
such in the header. It is the one place the wrapper's behaviour differs from
the C++ it wraps, and the equivalence tests (§7.2) assert it deliberately
rather than treating it as a mismatch.

## 4. Architecture

```
include/rngsdk/          unchanged, still header-only C++17
c_api/
  include/rngsdk_c.h     the public C header — the only file a licensee's
                         compiler ever parses
  src/rngsdk_c.cpp       the translator: includes rngsdk.hpp and rngsdk_c.h,
                         implements every function with C linkage
  src/engine_box.hpp     internal type-erasure over Random<E> (not installed)
  tests/c_parse_test.c   compiled by the C compiler (§7.1)
bindings/python/
  rngsdk.py              ctypes binding (§7.3)
  cross_check.py         validates the binding against docs/pf_test_vectors.json
```

`rngsdk_c.cpp` is compiled **as C++** — it has to be, since it calls C++
classes — but everything it exports carries `extern "C"` linkage. This is the
single most commonly misunderstood point about the pattern and the header
comment will say so plainly: the file is C++; only its interface is C.

**Type erasure.** The four `Random<E>` instantiations share no base class. An
internal abstract base supplies one:

```cpp
struct EngineBox {
    virtual ~EngineBox() = default;
    virtual void FillU64(std::uint64_t* out, std::size_t n) = 0;
    virtual void FillDouble(double* out, std::size_t n) = 0;
    // ... one per generator operation, all in bulk form
};
template <class E> struct EngineBoxT final : EngineBox {
    rngsdk::Random<E> r;
    void FillU64(std::uint64_t* out, std::size_t n) override {
        for (std::size_t i = 0; i < n; ++i) out[i] = r.NextUInt64();  // inlined
    }
};
```

The virtual functions are **bulk by construction** — there is deliberately no
`virtual uint64_t NextU64()`. The scalar C functions are implemented as bulk
calls with `n == 1`. This is what makes §3.2's amortisation real rather than
aspirational: the per-value work happens inside `EngineBoxT<E>` where `E` is
concrete and the call inlines away.

`std::variant` was considered and rejected: `CtrDrbgEngine` is move-only
while `HmacDrbgEngine` is copyable (an inconsistency already recorded under
OPEN_RESEARCH #2), and a variant would drag that asymmetry into the wrapper's
own type. A `std::unique_ptr<EngineBox>` behind the opaque handle sidesteps
it entirely.

**Handles.** `rngsdk_random` (generators) and `rngsdk_pf_session`
(`pf::ServerSession`) are opaque: declared as `typedef struct X X;` in the
header and never defined there. The Provably Fair generator functions are
stateless free functions with no handle at all, mirroring `pf::Generator`'s
static methods.

**Build.** A new CMake target `rngsdk_c`, built as a shared library
(`.dll`/`.so`/`.dylib`) and as a static library, privately linking the
existing `rngsdk` INTERFACE target. The INTERFACE target is untouched, so the
"one folder of MIT headers, no binary artifacts" story remains true for C++
consumers; the binary is an addition, not a replacement.

**Symbol visibility.** `RNGSDK_C_API` expands to
`__declspec(dllexport)`/`__declspec(dllimport)` on MSVC (switched by a
`RNGSDK_C_BUILDING` define set only when building the library) and to
`__attribute__((visibility("default")))` elsewhere, with
`-fvisibility=hidden` on the target so nothing else leaks. Calling convention
is left as the platform default (cdecl); the header does not attempt to
support 32-bit Windows stdcall callers, and says so.

## 5. The C API surface

All functions return `rngsdk_status`; results are returned through
out-parameters. All buffers are **caller-owned** — the library never returns
a pointer the caller must free, so there is no `rngsdk_free_*` and no
cross-heap allocate/free mismatch is possible by construction.

### 5.1 Status codes

```c
typedef enum {
    RNGSDK_OK = 0,
    RNGSDK_ERR_NULL_ARG,          /* a required pointer argument was NULL   */
    RNGSDK_ERR_INVALID_BOUND,     /* bound == 0 (§3.4)                      */
    RNGSDK_ERR_INVALID_ENGINE,    /* engine enum value out of range         */
    RNGSDK_ERR_INVALID_SEED_LEN,  /* AES_CTR_DRBG byte seed != 48 bytes     */
    RNGSDK_ERR_UNSUPPORTED,       /* engine/operation absent in this build  */
    RNGSDK_ERR_BUFFER_TOO_SMALL,  /* out_cap too small for the string       */
    RNGSDK_ERR_WEAK_SEED,         /* ServerSession seed < 32 chars          */
    RNGSDK_ERR_NO_CLIENT_SEED,    /* play() before set_client_seed()        */
    RNGSDK_ERR_REVEALED,          /* play() after reveal()                  */
    RNGSDK_ERR_NONCE_EXHAUSTED,   /* nonce space exhausted                  */
    RNGSDK_ERR_ENTROPY,           /* OS entropy source failed               */
    RNGSDK_ERR_INTERNAL           /* std::exception or unknown; catch-all   */
} rngsdk_status;
```

`RNGSDK_OK` is 0 and every error is non-zero, so `if (rngsdk_...(...))` is a
valid error check. Values are append-only: a future version may add codes but
never renumbers existing ones, since a licensee's compiled binary holds the
numeric values.

The exception→status mapping is exhaustive by construction. Each wrapper body
catches the specific `std::invalid_argument`/`std::runtime_error` cases whose
messages the C++ documents (weak seed, no client seed, revealed, nonce
exhausted, invalid bound), then `catch (const std::exception&)` and
`catch (...)` both fall to `RNGSDK_ERR_INTERNAL`. The C++ throws
`std::runtime_error` with distinct *messages* rather than distinct *types* for
the three `ServerSession::Play` failures (`provably_fair.hpp:246-263`), so the
wrapper distinguishes them by checking the precondition itself **before**
calling `Play()` — it does not parse exception text, which would break the
moment a message is reworded. The `try`/`catch` remains as the backstop.

### 5.2 Creation, destruction, seeding

```c
typedef enum {
    RNGSDK_ENGINE_XOSHIRO256PP = 0,
    RNGSDK_ENGINE_PCG64,
    RNGSDK_ENGINE_HMAC_DRBG,
    RNGSDK_ENGINE_AES_CTR_DRBG
} rngsdk_engine;

rngsdk_status rngsdk_random_create_seeded(rngsdk_engine kind, uint64_t seed,
                                          rngsdk_random** out);
rngsdk_status rngsdk_random_create_seeded_bytes(rngsdk_engine kind,
                                                const uint8_t* seed, size_t seed_len,
                                                rngsdk_random** out);
rngsdk_status rngsdk_random_create_secure(rngsdk_engine kind, rngsdk_random** out);
rngsdk_status rngsdk_random_seed(rngsdk_random* h, uint64_t seed);
void          rngsdk_random_destroy(rngsdk_random* h);   /* NULL is a no-op */
```

* `_create_seeded` — deterministic, all four engines, mirrors `Seed(uint64_t)`.
* `_create_seeded_bytes` — deterministic from raw bytes; DRBG engines only
  (`RNGSDK_ERR_UNSUPPORTED` for the fast tier, which has no such constructor).
  `AES_CTR_DRBG` requires exactly 48 bytes; anything else is
  `RNGSDK_ERR_INVALID_SEED_LEN`.
* `_create_secure` — OS-seeded. For the DRBG engines this is
  `HmacDrbgEngine()`/`CtrDrbgEngine()` directly (48 OS bytes via
  `SecureEntropy()`). For the fast tier it must **not** use the default
  constructor, which would silently hand back the fixed-constant stream from
  `0xDEFA017DEFA017` — a function named `_secure` returning a predictable
  sequence is exactly the kind of trap this SDK exists not to contain.
  Instead it seeds the **full engine state** from OS entropy:
  `Xoshiro256pp::SeedState` with 32 OS bytes (four `uint64_t`, rejecting the
  all-zero state xoshiro forbids and redrawing), and `Pcg64::SeedState` with
  32 OS bytes as two `u128` values. Seeding via `Seed(uint64_t)` from 8 OS
  bytes was rejected: it would cap a 256-bit state at 64 bits of entropy for
  no saving. The header states plainly that this makes the fast tier
  *unpredictable at instantiation*, not *cryptographically secure*, and
  points at SA-09 — the fast tier must never carry paid outcomes regardless
  of how it was seeded.
* `_destroy` accepts `NULL` (matching `free`), so cleanup paths need no guard.

### 5.3 Generators

Each has a scalar and an array form; the array form is the documented default.

```c
rngsdk_status rngsdk_next_u64      (rngsdk_random* h, uint64_t* out);
rngsdk_status rngsdk_next_u64_array(rngsdk_random* h, uint64_t* out, size_t n);
rngsdk_status rngsdk_next_u32      (rngsdk_random* h, uint32_t* out);
rngsdk_status rngsdk_next_u32_array(rngsdk_random* h, uint32_t* out, size_t n);
rngsdk_status rngsdk_next_double      (rngsdk_random* h, double* out);
rngsdk_status rngsdk_next_double_array(rngsdk_random* h, double* out, size_t n);
rngsdk_status rngsdk_next_float       (rngsdk_random* h, float* out);
rngsdk_status rngsdk_next_float_array (rngsdk_random* h, float* out, size_t n);

rngsdk_status rngsdk_next_bounded_u64      (rngsdk_random* h, uint64_t bound,
                                            uint64_t* out);
rngsdk_status rngsdk_next_bounded_u64_array(rngsdk_random* h, uint64_t bound,
                                            uint64_t* out, size_t n);
rngsdk_status rngsdk_next_bounded_u32      (rngsdk_random* h, uint32_t bound,
                                            uint32_t* out);
rngsdk_status rngsdk_next_bounded_u32_array(rngsdk_random* h, uint32_t bound,
                                            uint32_t* out, size_t n);
rngsdk_status rngsdk_next_int_range        (rngsdk_random* h, int64_t lo, int64_t hi,
                                            int64_t* out);   /* inclusive, mirrors NextInt */
rngsdk_status rngsdk_next_bytes            (rngsdk_random* h, uint8_t* out, size_t n);
```

`n == 0` is valid and a no-op returning `RNGSDK_OK` (so callers need no
special case), provided `out` is non-NULL. `bound == 0` is
`RNGSDK_ERR_INVALID_BOUND` — see §3.4.

### 5.4 Provably Fair — stateless

Hex strings are 64 characters plus NUL; the header defines
`RNGSDK_HEX_BUF (65)` so callers never hard-code it.

```c
rngsdk_status rngsdk_pf_commitment(const char* server_seed,
                                   char* out_hex, size_t out_cap);
rngsdk_status rngsdk_pf_verify_commitment(const char* server_seed,
                                          const char* commitment_hex, int* out_ok);
rngsdk_status rngsdk_pf_generate_server_seed(char* out_hex, size_t out_cap);

rngsdk_status rngsdk_pf_next_floats(const char* server_seed, const char* client_seed,
                                    uint64_t nonce, size_t n, double* out);
rngsdk_status rngsdk_pf_next_ints(const char* server_seed, const char* client_seed,
                                  uint64_t nonce, size_t n, uint64_t bound,
                                  uint64_t* out);
rngsdk_status rngsdk_pf_next_ints_unbiased(const char* server_seed,
                                           const char* client_seed, uint64_t nonce,
                                           size_t n, uint64_t bound, uint64_t* out);
```

`out_ok` is `int` rather than `bool` — `<stdbool.h>`'s `bool` is C99+ and its
size is not fixed across every toolchain a licensee might use. `0`/`1` is
unambiguous everywhere.

Seeds cross as NUL-terminated `const char*`, matching the C++ which takes
`std::string` and uses the seed's **ASCII bytes** as the HMAC key — the
hex-string-as-key convention that §3.1 of the web verifier spec identified as
the primary reimplementation trap. The header comment repeats that warning
verbatim, because a C caller holding 32 raw bytes will otherwise pass them
directly and get a different, silently wrong stream.

### 5.5 Provably Fair — session

```c
rngsdk_status rngsdk_pf_session_create(const char* server_seed, uint64_t start_nonce,
                                       rngsdk_pf_session** out);
void          rngsdk_pf_session_destroy(rngsdk_pf_session* h);
rngsdk_status rngsdk_pf_session_commitment(rngsdk_pf_session* h,
                                           char* out_hex, size_t out_cap);
rngsdk_status rngsdk_pf_session_set_client_seed(rngsdk_pf_session* h,
                                                const char* client_seed);
rngsdk_status rngsdk_pf_session_play(rngsdk_pf_session* h, size_t n_floats,
                                     double* out);
rngsdk_status rngsdk_pf_session_next_nonce(rngsdk_pf_session* h, uint64_t* out);
rngsdk_status rngsdk_pf_session_reveal(rngsdk_pf_session* h,
                                       char* out_hex, size_t out_cap);
```

`start_nonce` is a required argument with no default, unlike the C++ where it
defaults to 0. C has no default arguments, and this is a case where that is
an advantage: obligation 2 of the integration guide is "persist the nonce
with the server seed", and forcing the caller to type a value makes the
resumption decision explicit at every call site rather than something they
can omit into a replay.

### 5.6 Introspection

```c
typedef struct {
    const char* version;          /* rngsdk::kVersion, static storage */
    const char* crypto_backend;   /* "bundled" or "openssl" */
    int         has_aes_ctr_drbg; /* 0 or 1 */
} rngsdk_build_info_t;

void        rngsdk_build_info(rngsdk_build_info_t* out);
const char* rngsdk_status_message(rngsdk_status s);   /* static storage, never NULL */
```

`rngsdk_build_info` is the runtime answer to "which flavour of this binary am
I holding" — see §6. `rngsdk_status_message` returns a static English string
for logging; it is a convenience, and the status code, not the string, is the
contract.

## 6. The OpenSSL flavours

`CtrRandom` exists only under `RNGSDK_USE_OPENSSL` (`rngsdk.hpp:32-34`). In a
header-only world that is a compile-time switch the licensee can flip; once a
binary ships they cannot. The wrapper therefore makes it a **runtime**
property:

* `rngsdk_random_create_*(RNGSDK_ENGINE_AES_CTR_DRBG, ...)` is exported in
  **both** flavours. In a bundled build it returns `RNGSDK_ERR_UNSUPPORTED`.
* Both flavours export an **identical symbol list**, so a caller that loads
  either one needs no runtime symbol probing and no conditional compilation.
* `rngsdk_build_info()` reports which flavour the binary is. This is also an
  audit surface: a reviewer can ask the shipped artifact which crypto backend
  it was built with instead of trusting a build log.

**OpenSSL is linked statically** into the OpenSSL flavour. The licensee
receives one file and needs no OpenSSL installed, present, or even known
about. The cost is ours and is accepted: an OpenSSL CVE means we rebuild and
reship, rather than a licensee's system update silently fixing (or breaking)
our binary. Given the target market's compliance posture, "exactly one file,
whose contents we control and can attest to" is worth more than transparent
patching we cannot verify happened.

## 7. Test strategy

Three layers, all of which run in the normal build. Every one exists because
of a specific failure this project has already seen once.

### 7.1 C-compiler parse test (`c_api/tests/c_parse_test.c`)

A `.c` file compiled by the **C** compiler that includes `rngsdk_c.h`,
creates a handle of each engine, calls a representative function from each
group, and destroys it. Its job is not behavioural coverage — §7.2 does that
— but to prove the header is genuinely C. Without it, `rngsdk_c.h` is only
ever parsed by a C++ compiler, and a stray `//`-only construct, a `bool`, a
default argument, a `namespace`, or an accidental C++ keyword ships
undetected and fails first on the licensee's machine. Added as its own CMake
target with `LANGUAGES C` enabled at the project level.

### 7.2 In-suite equivalence tests (`tests/test_main.cpp`)

For each engine and each generator function: seed a C++ object and a C handle
identically, draw the same count, assert **bit-identical** output. Doubles and
floats are compared by bit pattern, not by tolerance — the claim is that this
is the same code, so anything but exact equality is a defect.

Also asserted:

* Scalar and array forms agree: `n` scalar calls produce the same sequence as
  one array call of length `n`. This is the test that would catch a bulk path
  that accidentally diverges from the scalar one, which is precisely the risk
  created by §4's decision to implement scalar in terms of bulk.
* Every documented error path returns its status code and **does not throw**.
  An exception escaping into a C frame is undefined behaviour, so this is a
  correctness test, not a politeness test.
* §3.4's deliberate divergence: `rngsdk_next_bounded_u64(h, 0, &v)` returns
  `RNGSDK_ERR_INVALID_BOUND` where the C++ returns 0. Asserted explicitly and
  commented as intentional, so a future reader does not "fix" it.
* `rngsdk_random_destroy(NULL)` is a no-op.
* PF vectors: the C path reproduces `docs/pf_test_vectors.json`.

### 7.3 Python ctypes binding and cross-check (`bindings/python/`)

`rngsdk.py` loads the built shared library and wraps it in idiomatic Python;
`cross_check.py` validates it against `docs/pf_test_vectors.json` — the same
canonical file the C++ test and the web verifier consume.

This is the layer that makes the item's fourth-axis claim real: Python,
C++ and JS currently agree because three people implemented the same
specification. Here another language calls the **shipped artifact**, so a
defect in the wrapper — not in anyone's understanding of the scheme — is
detectable. It doubles as the integration example every non-C++ licensee will
copy, so it is written to be read, not merely to pass.

Run manually (like `tools/web_selftest.js`), not wired into `ctest`, since it
requires a Python interpreter and a built shared library. The runbook command
is recorded in the deliverables.

## 8. Deliverables

1. `c_api/include/rngsdk_c.h` — the public C header, fully commented.
2. `c_api/src/rngsdk_c.cpp` — the translator.
3. `c_api/src/engine_box.hpp` — internal type erasure (not installed).
4. `c_api/tests/c_parse_test.c` + CMake target.
5. Equivalence tests appended to `tests/test_main.cpp`.
6. `bindings/python/rngsdk.py` + `bindings/python/cross_check.py`.
7. CMake changes: `LANGUAGES CXX C`, the `rngsdk_c` shared/static targets,
   visibility flags, the C parse-test target.
8. A section in `docs/INTEGRATION_GUIDE.md` covering the C ABI: which flavour
   to ship, the batching rule from §3.2, the caller-owned-buffer contract, the
   per-thread handle rule, and — stated plainly rather than implied — that
   `SECURITY_ANALYSIS.md` and the statistical results apply unchanged because
   the wrapper contains no cryptographic logic of its own.
9. OPEN_RESEARCH item #8 updated to close the third bullet.

## 9. Acceptance criteria

* Both existing configurations still build warning-free and pass at their
  current counts (669,935 bundled / 892,661 OpenSSL) plus the new equivalence
  checks.
* `rngsdk_c` builds shared and static in both flavours, warning-free.
* `c_parse_test.c` compiles with the C compiler and runs clean.
* Every C generator call is bit-identical to its C++ counterpart for the same
  seed, for all four engines (three in the bundled flavour, with
  `AES_CTR_DRBG` returning `RNGSDK_ERR_UNSUPPORTED`).
* `bindings/python/cross_check.py` passes against `docs/pf_test_vectors.json`.
* No exception can escape any exported function — every body ends in a
  `catch (...)`.
* `include/rngsdk/` is byte-identical to its pre-item state.

## 10. Risks

* **The wrapper drifting into a second implementation.** The single largest
  risk, and the one that would undo the item's value: a wrapper that
  re-derives a bound, re-does a mapping, or "improves" a calculation is no
  longer a translation layer, and the security and statistical analyses stop
  transferring. Mitigation: every body is null-check → `try` → one C++ call →
  catch → return, and §7.2's bit-identity tests fail the moment that stops
  being true. §3.4's bound narrowing is the *only* sanctioned divergence and
  it is a rejection, never a computation.
* **Thread safety is documented, not enforced.** Handles are not thread-safe,
  matching the C++ objects underneath. Enforcing it would require a mutex the
  C++ does not have and would misrepresent the library's real threading
  story (one engine per thread — OPEN_RESEARCH #9). The header says so
  explicitly; a licensee sharing a handle across threads is a documentation
  failure we can prevent only by writing it down clearly.
* **Bulk-path divergence.** Implementing scalar in terms of bulk means a bug
  in the bulk loop is a bug everywhere. Deliberate: one path to get right,
  and §7.2 cross-checks scalar against array so a divergence cannot pass.
* **ABI stability is claimed but not yet checked.** The deferred symbol
  snapshot test (§2) is what would make it enforceable. Until then the
  promise rests on review discipline, and the spec should not overstate it.
* **`rngsdk_status_message` returning static storage** is safe but easy to
  misuse from a language that assumes it must free returned strings. The
  Python binding demonstrates the correct handling.

## 11. Out of scope

* Any change to `include/rngsdk/` (§2).
* Bindings for languages other than Python. The C ABI is what makes C#, Go,
  Java and Node possible; writing those bindings is the licensee's work, and
  the Python one exists as a worked example and a test, not as the first of a
  set we commit to maintaining.
* The exported-symbol snapshot test (§2, deferred with reasons).
* 32-bit Windows stdcall support (§4).
* Resolving the `HmacDrbgEngine` copyable / `CtrDrbgEngine` move-only
  asymmetry (OPEN_RESEARCH #2). The wrapper sidesteps it via
  `unique_ptr<EngineBox>`; fixing it is a core change and belongs to that item.
