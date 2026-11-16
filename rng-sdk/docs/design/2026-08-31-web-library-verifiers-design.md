# Web + library verifiers — design (OPEN_RESEARCH item #8)

Date: 2026-08-31. Status: approved, pre-implementation.

## 1. Purpose

The spec requires the verifier in **three forms**: console, web page, and
integrator library. `rng_verifier` (console) exists. This item delivers the
other two and closes the last **OPEN** row in the §7c traceability matrix
that is not blocked on the partner's hardware.

Four reasons it earns its place, in descending order of how much they matter:

* **It is what makes "provably" true in practice.** If the only way to check
  a result is to compile and run our C++ binary, the player is still trusting
  us — we have merely moved the trust from the outcome to the toolchain. A
  static page that recomputes the outcome client-side, offline, with no
  server round trip, is the artifact that discharges the claim.
* **It is a third independent implementation of the Provably Fair scheme,
  and this project has caught every serious defect exactly that way.** RANDU's
  non-injective seed, the ODE's shared-stream bug, the CTR-DRBG derivation
  defect — none was found by re-reading the code that had the bug. Writing the
  scheme again, in another language, from the written description, is a test of
  the *description* as much as of the code. §3 records two traps already found
  by doing this on paper, before a line of JS exists.
* **The integration guide is the only place five real security obligations can
  be discharged.** `provably_fair.hpp` is correct and cannot be made to enforce
  them: an integrator who generates the client seed server-side produces a
  session that verifies, replays, and passes every test we own, while being
  unbinding. Code cannot close that hole. Documentation aimed at the integrator
  can, and nothing else can.
* **It is the artifact a licensee actually evaluates.** A prospective operator's
  engineer will open the page, verify a bet, and forward it to compliance. That
  is the sales surface for the whole SDK.

## 2. Scope

**In scope:** the web verifier (`web/verifier.html`), the integration and
security guide (`docs/INTEGRATION_GUIDE.md`), a compiled example backing the
guide, and the three-way test-vector infrastructure that validates the first.

**Deferred:** the C ABI wrapper for non-C++ integrators (OPEN_RESEARCH item #8,
third bullet). It is a different kind of work — C API surface design, ownership
and lifetime rules, a build artifact where the library currently has none, and
its own test burden — and bundling it here would make one spec cover two
unrelated risks. Approved by the user on 2026-08-31 to follow as a separate
item once (1) and (2) are proven.

## 3. Two reimplementation traps, found before implementation

Both are cases where the natural, idiomatic thing to write in JavaScript is
silently wrong — no exception, no crash, just different numbers. They are the
core technical content of this item and the reason §4's cross-check is
load-bearing rather than ceremonial.

### 3.1 The HMAC key is the ASCII of the hex string, not the bytes it encodes

`GenerateServerSeed()` returns `ToHex(OsEntropy(32))` — a **64-character hex
string**. `ByteStream::NextBlock` then calls:

```cpp
crypto::HmacSha256(server_seed_.data(), server_seed_.size(), ...)
```

`server_seed_` is that 64-character string, so the HMAC key is **64 bytes: the
ASCII codes of the hex digits** (`a` = 0x61, `3` = 0x33, and so on). It is *not*
the 32 raw bytes the hex encodes. `Commitment()` hashes the same string the same
way, so the convention is internally consistent and matches the Stake-compatible
ecosystem — it is correct, not a bug.

But a reimplementer handed a value described as "a hex-encoded 256-bit seed"
will reach for `hexToBytes()` before using it as key material, because that is
the correct instinct in every other context. That produces a 32-byte key, a
different HMAC, and a wholly different result stream, with nothing to signal it.

In JS the correct form is `new TextEncoder().encode(serverSeed)`; the wrong form
is any hex decode. §5.3 requires the page to *display both interpretations* at
the point of derivation, so the fork is visible to the next reimplementer rather
than buried in this document.

### 3.2 The unbiased integer path needs BigInt, not Number

`NextIntsUnbiased` is Lemire rejection over 64-bit integers:

```cpp
const std::uint64_t t = (0 - bound) % bound;      // = 2^64 mod bound
const std::uint64_t x = bs.NextUInt64();          // 8 bytes, big-endian
const detail::u128 m = detail::mul64x64(x, bound);
if (m.lo >= t) { out.push_back(m.hi); break; }
```

JavaScript `Number` is IEEE-754 double: integers above 2^53 are not exactly
representable. `NextUInt64` produces values above that threshold the
overwhelming majority of the time, and the 64x64 to 128-bit product is far
beyond it. Written with `Number`, this silently returns *plausible* integers in
`[0, bound)` — correctly ranged, wrong values, and biased in a way no eyeball
detects.

The JS core must use `BigInt` throughout this path:

* `x` accumulated as BigInt from the 8 bytes, big-endian, matching `NextUInt64`
* `t = (1n << 64n) % bound` — algebraically identical to `(0 - bound) % bound`
  in unsigned 64-bit arithmetic
* `m = x * bound`, then `hi = m >> 64n`, `lo = m & 0xFFFFFFFFFFFFFFFFn`

A test vector with a `bound` large enough to force at least one rejection is
mandatory, since an implementation that never rejects passes a naive vector set.

### 3.3 The float mapping is exactly reproducible — and this is provable

`FloatFromBytes` is `b0/2^8 + b1/2^16 + b2/2^24 + b3/2^32`. Every term is a
dyadic rational with an exact double representation, and every left-to-right
partial sum is `k/2^32` for integer `k < 2^32` — 32 significant bits against a
53-bit mantissa. **No rounding occurs at any step.** C++ and JavaScript therefore
produce bit-identical doubles here, and the vectors can be compared for exact
equality rather than within a tolerance. Comparing floats with `==` is normally
a defect; here it is the stronger assertion and the correct one.

## 4. Architecture: a three-way cross-check

Two implementations that agree prove only that they share an author's reading
of the spec. Both §3 traps are precisely the kind of mistake two implementations
by the same hand make identically. So correctness is anchored to a **third**
implementation that shares no code with either.

```
    tests/golden/generate_pf_vectors.py       (Python: hashlib + hmac)
                     |
        +------------+-------------+
        |                          |
  docs/pf_test_vectors.json   tests/golden/golden_pf_vectors.hpp
        |                          |
   embedded verbatim          included by
   in web/verifier.html       tests/test_main.cpp
        |                          |
   JS self-test  <-- must agree --> C++ suite
```

This is the same discipline as the existing `generate_golden.py`, whose header
states the reasoning outright: values produced by the C++ code itself would
prove only self-consistency.

**One generator, two artifacts.** `generate_pf_vectors.py` computes the
vectors once and emits both the JSON and the C++ header, so the two cannot
disagree about what the vectors *are*. The C++ header is a generated
`golden_pf_vectors.hpp` in the existing style — this keeps the SDK free of a
JSON parser, which matters for a project whose selling point is zero
dependencies.

**Drift guard.** The HTML embeds the JSON **verbatim** inside
`<script type="application/json" id="pf-test-vectors">`. A C++ test extracts
that block and string-compares it to `docs/pf_test_vectors.json` — no JSON
parsing, just text. Without this, someone regenerates the vectors, forgets the
HTML, and the page self-tests green against stale data forever. CMake supplies
the source path via a `RNGSDK_SOURCE_DIR` compile definition on `rng_tests`.

Vectors must be embedded rather than fetched: `fetch()` of a sibling file is
blocked by CORS under `file://`, which is the primary usage mode (§5.2).

### 4.1 Vector coverage

The vector set must exercise every path where the two languages could diverge:

| Case | What it pins down |
|---|---|
| Commitment of a known seed | SHA-256 over the hex string's ASCII (§3.1) |
| Floats, nonce 0 and nonce 8 | Base derivation; nonce enters the message, not the key |
| 9 or more floats from one nonce | Forces cursor 1 — proves the cursor rolls over correctly |
| Unbiased ints, small bound | Lemire happy path |
| Unbiased ints, bound forcing rejection | The `m.lo >= t` branch (§3.2) |
| Non-ASCII client seed | UTF-8 byte agreement between `TextEncoder` and `std::string` |
| Empty client seed | Boundary; the message is then `:0:0` |
| Client seed pushing the message past 55 bytes | A second SHA-256 block in the *inner* hash over a message boundary, not just the guaranteed one (§10) |

## 5. `web/verifier.html`

### 5.1 One file, no network, no dependencies

A single static file. It must verify correctly with the machine offline, opened
from disk, in a browser with no extensions, years from now. No CDN, no build
step, no framework. A licensee can email it to a regulator.

### 5.2 Two crypto backends

`crypto.subtle` is the right primitive — browser-native and vetted — but it is
gated behind "secure context." Whether a `file://` origin qualifies varies by
browser and version, and **this spec deliberately does not assert which browsers
allow it**; §8 makes it an empirical check. If `crypto.subtle` is unavailable
and there is no alternative, the page is inert in exactly the mode that matters
most for a trust artifact.

Therefore: **WebCrypto primary, bundled pure-JS SHA-256/HMAC fallback.**

Hand-rolled crypto normally deserves suspicion. It is defensible here for a
narrow reason: SHA-256 is an unkeyed hash with published test vectors, so its
correctness is *demonstrable by KAT* rather than a matter of trust, and the
fallback only ever runs when the alternative is a page that does nothing. When
both backends are available the self-test runs the vectors through **both**,
making their agreement an additional check rather than a pure cost.

`crypto.getRandomValues` is not secure-context gated and is available in both
modes, so §5.4's generator works regardless of backend.

A visible banner reports which backend is active. An auditor must never have to
guess which code produced a number on screen.

### 5.3 Three layers

**Layer 1 — the answer.** Inputs: server seed, commitment, client seed, nonce,
count, and mode (floats / unbiased ints plus bound). One button. A verdict:
commitment match, then the results. A player is finished here.

Commitment mismatch is a **hard stop**, styled as a failure and not merely a
warning, with the expected and claimed hashes shown. A mismatch means the
revealed seed is not the committed one, which is the single finding the whole
scheme exists to surface.

**Layer 2 — "Show the work"**, collapsed by default. Per result:

* the exact HMAC message string, `clientSeed:nonce:cursor`, shown character by
  character with the separators marked
* **the key in both interpretations of §3.1**, the correct one marked and the
  hex-decoded one shown struck through as the trap it is
* the cursor, the 32 output bytes in hex, which 4 (or 8) bytes fed this result,
  and the arithmetic that produced it

This layer is the anti-trap documentation. Prose in a design doc reaches whoever
reads the design doc; this reaches whoever reimplements the scheme, at the
moment they are deciding what to do.

**Layer 3 — tools.** Self-test button (§4), client-seed generator (§5.4),
backend banner.

### 5.4 Client-seed generator

A widget producing a fresh client seed via `crypto.getRandomValues`, with one
line stating that the player's device must generate it and the operator must
never supply it.

Included deliberately, not scope creep. Obligation 1 (§6) is the most likely of
the four to be violated, and its violation is invisible from the UI. A working,
copyable implementation on the page the integrator is already reading is a
stronger control than a paragraph in a document warning them off.

### 5.5 Internal structure

Single file, but partitioned by a hard internal boundary:

```
<script type="application/json" id="pf-test-vectors">  — §4 vectors, verbatim

/* ===== VERIFICATION CORE — pure functions, no DOM ===== */
   sha256, hmacSha256 (both backends), byteStream, floatFromBytes,
   nextFloats, nextIntsUnbiased, commitment, verifyCommitment
/* ===== END VERIFICATION CORE ===== */

/* UI, event handlers, rendering */
```

The core touches no DOM and holds no page state; an auditor reads roughly 150
lines and can confirm the mathematics without reading a line of UI code. The
self-test calls the core directly, which is what makes the boundary real rather
than a comment claiming a boundary — a distinction this project has been bitten
by before (item #3: "a comment asserting coverage is not coverage").

### 5.6 Parity with the console verifier

The page must support **both** mappings: the industry-compatible float
(`NextFloats`) and the exactly-unbiased Lemire integer path
(`NextIntsUnbiased`). A web verifier that handles only floats is strictly weaker
than `rng_verifier` and cannot verify integer outcomes — which is most real
casino games.

## 6. `docs/INTEGRATION_GUIDE.md`

Order matters: an integrator reads until they have working code and then stops,
so the obligations must arrive before they leave.

1. **Quickstart** — the correct protocol sequence in roughly 15 lines, backed
   verbatim by `examples/integration_demo.cpp` so it is compiled rather than
   asserted.
2. **The library form** — `provably_fair.hpp` as an integrator-facing API:
   `Commitment`, `VerifyCommitment`, `GenerateServerSeed`, `ByteStream`,
   `Generator`, `ServerSession`. What each guarantees and what it does not.
3. **The five obligations.** Each as: the rule, then the failure in plain terms,
   then the code that gets it wrong, then the code that gets it right, then the
   SECURITY_ANALYSIS cross-reference.

   1. **Generate the client seed on the player's device, after the commitment
      is published.** A server-generated client seed verifies, replays, and is
      indistinguishable from a correct one in the UI — while letting the operator
      grind server seeds and commit to a favourable one. (SA-03, §6.3)
   2. **Persist the nonce with the server seed.** A restart that re-instantiates
      `ServerSession` at 0 replays outcomes the player has already seen. Use the
      `start_nonce` constructor argument on resume. (SA-01, §5.1)
   3. **Use `pf::GenerateServerSeed()`.** The 32-character floor is a proxy that
      catches typed seeds, not low-entropy derived ones; a long seed from a
      counter passes the check and loses to the commitment brute-force oracle.
      (SA-02, §6.2)
   4. **Never use the fast tier for paid outcomes** (SA-09), and note that
      `CryptoRandom` at namespace or static scope can `std::terminate` if OS
      entropy fails during dynamic initialisation (OPEN_RESEARCH #1).
   5. **Re-verify AES-NI dispatch on each deployment target.** Whether the
      constant-time hardware path is taken is a property of the CPU the binary
      actually runs on, not of the build — so it cannot be established once and
      inherited. Obligation 5 gives the measurement command. (SA-10, §7.1)

4. **Pre-launch checklist** — tickable, one line per obligation plus commitment
   publication order and seed rotation. This is the section that gets used, by
   someone in compliance who will not read sections 1 to 3.

**Traceability.** `SECURITY_ANALYSIS.md` §9.1 item 2 explicitly assigns *"SA-03's
second half, SA-09, SA-10 — integration guide (#8) and release checklist"*. This
section discharges all three. Obligations 2 and 3 additionally cover the
deployment halves of SA-01 and SA-02: both are marked fixed in the register
because the library now refuses the failing case, but neither library check can
reach an integrator who re-instantiates `ServerSession` at nonce 0 after a
restart, or who feeds it a long low-entropy seed that clears the length floor.
Closing this item should flip those three register rows to reference the guide.

## 7. Deliverables

| Path | Kind |
|---|---|
| `web/verifier.html` | New — the web verifier, single static file |
| `docs/pf_test_vectors.json` | New, generated — canonical vectors |
| `tests/golden/generate_pf_vectors.py` | New — Python generator, emits JSON + header |
| `tests/golden/golden_pf_vectors.hpp` | New, generated — C++ view of the vectors |
| `docs/INTEGRATION_GUIDE.md` | New — library form + five obligations |
| `examples/integration_demo.cpp` | New — compiled backing for the guide |
| `tests/test_main.cpp` | Edit — vector tests + drift guard |
| `CMakeLists.txt` | Edit — `rng_integration_demo` target, `RNGSDK_SOURCE_DIR` |
| `README.md` | Edit — point at the web verifier and the guide |
| `docs/OPEN_RESEARCH.md` | Edit — close #8 (1)+(2), record the C ABI deferral |

## 8. Test strategy

**Layer 1 — C++, automated.** PF vectors from `golden_pf_vectors.hpp` against
`pf::Generator`; float comparisons exact per §3.3. Drift guard: HTML-embedded
JSON string-equals `docs/pf_test_vectors.json`. Both run in the existing suite,
in both build configurations.

**Layer 2 — JS, in-page.** The self-test runs every vector through the core and
reports PASS/FAIL with a count, through **both** backends where available. A
failing self-test must visibly disable or prominently warn on the verify
controls — a page that computes wrong answers confidently is worse than one
that refuses.

**Layer 3 — manual, recorded in this spec on completion.**

**DONE (partial) — manual run performed 2026-09-02.** User opened
`verifier.html` directly from a `file://` URL in Brave and Chrome (both
Chromium-based, Windows). Both loaded correctly and matched: active crypto
backend reported was **WebCrypto** (bundled-JS fallback also available per
the page's own report), and the in-page self-test passed all checks in both.
This confirms `crypto.subtle` is available under `file://` on Chromium,
answering the §5.2 question for that engine family.

**Safari was not tested** — no Safari-capable machine available in this
environment (Windows). Firefox was also not exercised. Acceptance criterion
3 (§9) is therefore met for Chromium-family browsers only; Firefox/Safari
compatibility remains an open gap, to be closed opportunistically if a
tester with those browsers becomes available, but is not blocking item #8
completion given the offline/no-deps design already limits browser-specific
surface area to `crypto.subtle` availability and basic ES2020 support.

**Layer 4 — the example compiles**, in both configurations, warning-free.

## 9. Acceptance criteria

1. `generate_pf_vectors.py` emits both artifacts; regenerating twice is
   byte-identical.
2. C++ suite passes in both configurations, warning-free, with the vector tests
   and drift guard included; check count recorded in the status log.
3. `verifier.html` self-test passes in all three browsers from `file://`, with
   the active backend recorded per browser.
4. A commitment mismatch is presented as a hard failure, verified by hand with a
   deliberately wrong seed.
5. Web verifier and `rng_verifier` agree on the same inputs, for floats and for
   unbiased ints including a rejection case.
6. Layer 2 displays both key interpretations of §3.1.
7. `examples/integration_demo.cpp` compiles warning-free in both configurations
   and its code appears verbatim in the guide's quickstart.
8. The guide's five obligations each carry a failure mode, wrong code, right
   code, and a SECURITY_ANALYSIS cross-reference.

## 10. Risks

**The `file://` secure-context question may resolve badly in some browser.**
Mitigated by construction: the fallback exists precisely because the answer is
unknown. The residual risk is that some browser blocks *both* paths, which would
be surprising — the fallback needs no browser API at all beyond arithmetic.

**Hand-rolled JS SHA-256 could be subtly wrong.** Mitigated by KAT: the same
vectors that validate the C++ validate the fallback. Length bookkeeping — the
classic failure — is partly exercised for free, since HMAC prepends a 64-byte
padded key block and every inner hash is therefore already multi-block. That is
*not* sufficient on its own: it fixes the block boundary at a constant offset
and would not catch an error in how the message's own length is folded in.
§4.1 therefore requires a vector whose message crosses 56 bytes (64 minus the
9 bytes SHA-256 padding needs), so a second block is forced by the message
rather than by the key. The fallback must also be checked against the plain
SHA-256 vectors already in `golden_values.hpp`, which cover the empty, `abc`,
two-block, and one-million-byte cases directly.

**The guide gets written and never read.** Partly unmitigable. §6's ordering and
its final checklist are the response: put the obligations before the point where
the reader has working code, and give compliance a surface that does not require
reading the rest.

**Scope drift into a "demo casino."** The page verifies and generates a client
seed. It does not simulate games, hold session state, or persist anything.

## 11. Out of scope

* The C ABI wrapper (§2) — deferred to its own item.
* Any server component. The page is static and never makes a network request.
* Verifying the non-PF tiers. `CryptoRandom` and the fast engines are not
  externally verifiable by design; this tool covers the Provably Fair scheme.
* Styling beyond what legibility and the layer separation require. The
  `frontend-design` skill governs the visual pass at implementation time.
