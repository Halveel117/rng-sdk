# Integration guide: Provably Fair library

This is the "library form" of the verifier: how to embed the RNG-SDK's
Provably Fair scheme in an operator's stack. It is written for the engineer
wiring `pf::ServerSession` into a game backend, and for whoever signs off on
that integration before it ships.

**Read section 3 before you ship.** The library enforces what it can, namely nonce
monotonicity, the reveal lock, a server-seed length floor, a client-seed
presence check. It cannot enforce the other half of the same guarantees,
because from inside a `std::string` argument the library cannot tell a
player-generated value from an operator-generated one, or a CSPRNG seed from
a disguised counter. That half is discharged here, in prose, because there is
nowhere else for it to live.

---

## 1. Quickstart

`examples/integration_demo.cpp` is a complete, correct session, end to end.
It is a build target (`rng_integration_demo`), so this listing cannot drift
from something that compiles:

```
cmake --build build --target rng_integration_demo
./build/rng_integration_demo          # (Windows: build\Debug\rng_integration_demo.exe)
```

```cpp
    SessionRecord db;

    // 1. BEFORE PLAY: generate a server seed and publish its commitment.
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

    // 3. PLAY: one call per bet; the nonce advances and never rewinds.
    const auto bet0 = session.Play(1);
    const auto bet1 = session.Play(1);
    db.next_nonce = session.NextNonce();     // persist after every bet
    std::printf("bet 0 (nonce 0)      : %.17f -> d6 %d\n",
                bet0[0], 1 + static_cast<int>(bet0[0] * 6));
    std::printf("bet 1 (nonce 1)      : %.17f -> d6 %d\n",
                bet1[0], 1 + static_cast<int>(bet1[0] * 6));
    std::printf("persisted next nonce : %llu\n",
                static_cast<unsigned long long>(db.next_nonce));

    // 4. END OF SESSION: reveal. Play() refuses to run after this point,
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
```

Step 6 is discussed further under obligation 2 below, and it proves less than it
looks like it proves.

---

## 2. API reference: `provably_fair.hpp`

Everything here lives in `rngsdk::pf`. One entry per symbol: what it
guarantees, what it does not.

**The HMAC key convention, to read before writing your own verifier.**
The byte stream is `HMAC-SHA256(key = server_seed, msg = client_seed ":" nonce
":" cursor)`. The key is the server seed **string's own bytes**. If
`server_seed` is `"a3f1..."`, the key is the ASCII characters `'a'`, `'3'`,
`'f'`, `'1'`, ..., not the bytes you'd get by hex-decoding that string into 32
raw bytes. `GenerateServerSeed()` returns a hex-looking string specifically
because it's easy to publish and compare, and hex-decoding a hex-looking key
is the natural instinct, but it produces a completely different, silently
wrong byte stream with no error anywhere. Every value in this scheme
(`server_seed`, `client_seed`) is used as raw text bytes. Only the published
**commitment** is a hex encoding of a hash digest; it is never fed back into
HMAC. (Design spec §3.1; `web/verifier.html` implements both interpretations
side by side, labelled, for exactly this reason.)

- **`Commitment(server_seed) -> hex string`** returns `SHA-256(server_seed)`.
  Guarantees: binds the operator to `server_seed` under SHA-256 collision
  resistance once published. Does not guarantee anything about the seed's
  quality, since a weak seed produces a valid, checkable, brute-forceable
  commitment.
- **`VerifyCommitment(server_seed, commitment_hex) -> bool`** recomputes
  and compares. Guarantees a correct match/mismatch verdict for any input,
  including adversarial ones (this is the function a player runs against a
  possibly-dishonest operator). Does not guarantee the seed was generated
  correctly, only that the revealed value matches what was published.
- **`GenerateServerSeed() -> hex string`** returns 32 bytes (256 bits) from the OS
  CSPRNG, hex-encoded. Guarantees unguessability sufficient that the
  commitment oracle (§3 obligation 3) is infeasible to brute-force. Throws if
  the OS entropy source fails rather than degrading silently. This is the
  **only** supported way to obtain a server seed; nothing else in the API can
  distinguish its output from a hand-typed or derived string of the same
  length.
- **`ByteStream`** is the raw HMAC block generator (`server_seed`,
  `client_seed`, `nonce`) with an internal cursor, extending output past 32
  bytes on demand. Guarantees the exact byte sequence `Generator` and
  `ServerSession` build on. Most integrators want `Generator` or
  `ServerSession` instead; use `ByteStream` directly only when writing a
  custom mapping the SDK doesn't already provide.
- **`Generator::NextFloats(server_seed, client_seed, nonce, n) -> vector<double>`**
  gives `n` values in `[0, 1)`, industry-standard 4-bytes-per-float construction
  (32-bit resolution). This is the free function a player's own verifier
  calls to replay a revealed session, and it needs no `ServerSession`, no
  server-side state, nothing but the three public inputs.
- **`Generate(server_seed, client_seed, nonce) -> double`** is the single-outcome
  form, `Result = RNG(ServerSeed, ClientSeed, Nonce)`. An alias for
  `Generator::NextFloats(..., 1)[0]`, not a second derivation; use whichever
  name reads better at the call site. C: `rngsdk_pf_generate`.
- **`Generator::NextInts(..., bound) -> vector<uint64_t>`** gives `n` values in
  `[0, bound)` via `floor(f * bound)` on top of `NextFloats`. **Carries a bias
  of at most `bound / 2^32`** relative deviation, negligible for game-sized
  bounds but not zero, and exists for ecosystem compatibility with other
  operators' verifiers, which use this same construction. Do not reach for
  this by default; it is a compatibility shim, not the accurate path.
- **`Generator::NextIntsUnbiased(..., bound) -> vector<uint64_t>`** gives `n`
  values in `[0, bound)` via Lemire rejection over the HMAC stream.
  **Exactly unbiased** for any bound, at the cost of not matching the byte
  layout other operators' verifiers expect. Use this when "provably no bias"
  must hold as a mathematical claim (it is what `MATH_JUSTIFICATION.md`
  proves), not when Stake-ecosystem interoperability matters more.
  **Precondition: `bound != 0`.** `bound == 0` throws `std::invalid_argument`
  rather than dividing by zero, so validate any caller-supplied bound (a game
  config value, a CLI/UI argument) before calling this, since the exception
  is the only signal you get.
  `NextInts` and `NextIntsUnbiased` are **not interchangeable outputs for the
  same nonce**, so pick one per game and keep it fixed, since a player
  replaying with the other mapping will not reproduce your result.
- **`ServerSession`** owns protocol order and nonce state for one server
  seed. Guarantees (each backed by a named regression test; see the header
  comment in `provably_fair.hpp`): the nonce never rewinds or repeats within
  the session; `Play()` throws before `SetClientSeed()`; `Play()` throws
  after `Reveal()`; construction throws if `server_seed` is shorter than
  `kMinServerSeedChars` (32). Does **not** guarantee: that the seed passed in
  actually came from `GenerateServerSeed()` (obligation 3); that the client
  seed passed to `SetClientSeed()` actually came from the player (obligation
  1); that the nonce you pass to the resumption constructor is the real
  persisted value (obligation 2); or that the seed hasn't been used in a
  prior, already-revealed session (§5 checklist). All four are string- or
  integer-typed inputs the class cannot audit the provenance of.

---

## 3. The five obligations

The library enforces what code can enforce. These five are what it cannot, and
each one produces a session that verifies correctly, replays correctly, and
passes every test this SDK owns, while being broken in a way nothing in the
UI or the code can show you.

### 1. Generate the client seed on the player's device, after the commitment is published

**Rule.** The client seed must originate on the player's own device,
browser or app, and only after the player has seen the published commitment.
The operator must never choose it, predict it, or default it.

**Wrong:**
```cpp
session.SetClientSeed(RandomString());   // operator-generated, not binding
```

**Right**, generated on the player's device, e.g. `web/verifier.html`'s own
approach:
```js
const bytes = new Uint8Array(16);          // 128 bits is ample for a client seed
crypto.getRandomValues(bytes);
const clientSeed = toHex(bytes);
// ... send clientSeed to the server, which calls SetClientSeed(clientSeed)
```

**The failure, in plain terms.** Commit–reveal binds the operator to the
committed seed, but the operator still chooses *which* seed to commit to. If
the operator can predict the client seed at commit time, it can generate many
candidate server seeds, compute the outcome each one produces against that
predicted client seed, and commit to the most favourable one, and grinding a
1-in-10⁶ outcome costs under a millisecond at commodity hash rates. The
resulting session still verifies: `SHA-256(revealed) == commitment` holds,
and replay matches. Nothing distinguishes it from an honest session, because
nothing about the mechanics changed, only which of the two parties actually
chose the number that was ground for advantage. This is the most likely of
the five obligations to be violated, precisely because violating it produces
output indistinguishable from correct output.

**Cross-reference:** `docs/SECURITY_ANALYSIS.md` SA-03, §6.3.

### 2. Persist the nonce with the server seed; use `start_nonce` on resume

**Rule.** The next unused nonce for a session must be durably stored
alongside the server seed, and any process restart that re-instantiates
`ServerSession` for that seed must pass the persisted value in as
`start_nonce`.

**Wrong:**
```cpp
// after a restart, re-loading the seed but not the nonce
pf::ServerSession session(db.server_seed);      // implicitly start_nonce = 0
```

**Right:**
```cpp
pf::ServerSession session(db.server_seed, db.stored_next_nonce);
```

**The failure, in plain terms.** Restarting at nonce 0 reproduces bets the
player has already seen and already acted on, a replay that is directly
monetisable: a player who recorded which of the first few nonces won can wait
for an operator restart and bet the maximum on exactly those nonces again.

**What step 6 of the quickstart does and does not prove.** The demo's
resumption step constructs `pf::ServerSession resumed(db.server_seed,
db.next_nonce)` and prints `resumed.NextNonce()`, which echoes back
`db.next_nonce` (2, after two bets). That confirms the constructor *stored*
the value it was given, nothing more. It does not call `Play()` on
`resumed`, so it never demonstrates that the next *generated* output actually
lands on nonce 2 rather than colliding with the already-played bets at nonce
0 and 1. If the integrator had instead written `pf::ServerSession
resumed(db.server_seed)` (the wrong code above), `NextNonce()` would print
`0` instead of `2`, and that alone is a visible difference; but the actual
consequence of the bug is silent, because it is not the printed number that
matters, it is the output of the *next* `Play()` call, which would silently
reproduce `bet0`. Echoing the nonce back proves the plumbing carries the
number through the constructor. It does not prove the number governs the
next result. Only a `Play()` call after resumption, checked against a fresh
nonce, would prove that. Do not treat the demo's step 6 as a demonstration
that resumption is replay-safe in your own integration; verify it directly
against your own persistence layer with a `Play()` call, the way the "one
below the ceiling is still a legal bet" sub-case inside
`TestNonceOverflowRefused` (`tests/test_main.cpp`) does: it constructs
`ServerSession ok(seed, max-1)` with an explicit non-zero `start_nonce`,
calls `ok.Play(1)`, and checks `ok.NextNonce() == max`, the nonce advancing
one step past the value the session was resumed at, which is exactly the
`Play()`-backed check the demo's step 6 is missing. Its one limitation: it
exercises resumption at the `uint64_t` overflow boundary (`max-1`), not at an
ordinary mid-range nonce, so it proves the mechanism works rather than
constituting a general resumption test, so treat it as showing the *shape* of
the check to write, not as coverage for every resumption path in your own
integration. (`TestClientSeedReuseDoesNotReplay` is the correct regression
test for the SA-01 client-seed-reset finding cited above; it exercises
re-selecting a client seed within one live session and does not construct a
session with a nonzero `start_nonce`, so it is not evidence for this
resumption claim specifically.)

**Cross-reference:** `docs/SECURITY_ANALYSIS.md` SA-01, §5.1.

### 3. Use `pf::GenerateServerSeed()`, never a literal, never a derived seed

**Rule.** The server seed passed to `ServerSession` must come from
`pf::GenerateServerSeed()` and nothing else.

**Wrong:**
```cpp
pf::ServerSession session("my-fixed-seed-value-thats-long-enough-1234");
pf::ServerSession session(std::to_string(counter++) + "-server-seed-padding");
```

**Right:**
```cpp
pf::ServerSession session(pf::GenerateServerSeed());
```

**The failure, in plain terms.** The published commitment is a free offline
brute-force oracle: an attacker enumerates candidate seeds, hashes each, and
compares against the published commitment, with no rate limit and no way for
the operator to detect the attempt. A low-entropy or structured seed (a
counter, a timestamp, a short hand-typed string) is recoverable this way
before reveal, at which point the attacker knows every future outcome of
the session and the game is over for the operator.

**Note on the length floor.** `ServerSession` rejects any seed shorter than
`kMinServerSeedChars` (32 characters), which catches the first wrong example
above. It does **not** catch the second: a 64-character string derived from a
counter is exactly as long as a real `GenerateServerSeed()` output and is
still a brute-forceable oracle, because the check counts characters, not
entropy. The length floor is a proxy that makes the common accident loud; it
is not a substitute for using the generator.

**Cross-reference:** `docs/SECURITY_ANALYSIS.md` SA-02, §6.2.

### 4. Never use the fast tier for paid outcomes

**Rule.** `FastRandom` (xoshiro256++) and `Pcg64Random` (PCG64) must never
produce an outcome a player is paid on. Use `CryptoRandom` (HMAC-DRBG) or the
Provably Fair layer for anything that touches money.

**Wrong:**
```cpp
rngsdk::FastRandom fast(seed);
auto payout_roll = fast.NextUInt64(100);   // a player is paid on this, wrong tier
```

**Right:**
```cpp
rngsdk::CryptoRandom secure;               // OS-seeded, SP 800-90A HMAC-DRBG
auto payout_roll = secure.NextUInt64(100);
// or, for a verifiable session: pf::ServerSession / pf::Generator
```

**The failure, in plain terms.** Both fast engines are recoverable from
their output, PCG64 practically so (published attack: full state recovery
from 512 bytes of output, ~20,000 CPU-hours) and xoshiro256++ at minimum
information-theoretically (its 256-bit state is fully determined by four
consecutive outputs). Once an attacker recovers the state, every future
output is predictable, deterministically, forever, from that point. The SDK
does not and cannot block this at the type level: `FastRandom` is a public
type, and nothing prevents wiring it into a payout path.

**The `CryptoRandom`-at-static-scope caveat.** `CryptoRandom`'s
default constructor seeds itself from the OS CSPRNG and **throws if that
source fails**. A `CryptoRandom` declared at namespace or static scope runs
that throwing constructor during dynamic initialization, before `main`
starts and before any `try`/`catch` in your code is in scope, and a failure
there calls `std::terminate`, not a handler you can write. Construct
`CryptoRandom` instances inside a function (or behind lazy/explicit
initialization you control) where a thrown exception has somewhere to go, not
as a global or `static` variable at file scope.

**Cross-reference:** `docs/SECURITY_ANALYSIS.md` SA-09, §2.1, for the fast-tier
finding; §7.4 for the static-scope caveat (recorded as open, no in-tree usage
exists, filed as an integration-guide item).

### 5. Re-verify AES-NI dispatch on each deployment target

**Rule.** If you build with `-DRNGSDK_USE_OPENSSL=ON` and use the AES-CTR-DRBG
tier, confirm on **each** deployment target, not once, not in CI on a
different machine, that OpenSSL is actually taking the AES-NI hardware path.

**Right:** run OpenSSL's own benchmark against the build you deployed.
```
openssl speed -evp aes-256-ecb
```
Read the largest block size. Above ~800 MB/s is the AES-NI path; a T-table
software path runs ~100 to 250 MB/s, so the gap is an order of magnitude and
needs no precision. On this project's development target the same measurement
gave 4908 to 5707 MB/s (SECURITY_ANALYSIS §7.1).

**The failure, in plain terms.** Whether AES-NI is used is decided by OpenSSL
at runtime from CPU capability flags, and it is not a property of your build,
your compiler flags, or the fact that it was confirmed on the machine you
developed on. A binary built on AES-NI hardware and deployed to a VM, a
container host, or a low-power instance without AES-NI silently falls back to
a table-based software path, and published cache-timing attacks (Cohney et
al., IEEE S&P 2020) recover CTR-DRBG state from that path, in one variant
blind, without ever observing the output. There is no error, no warning, and
no code-level signal that the fallback occurred; only measurement shows it.
The command above exists precisely because this cannot be determined by
reading source.

**Cross-reference:** `docs/SECURITY_ANALYSIS.md` SA-10, §7.1.

---

## 4. The C ABI: integrating from a language that is not C++

`include/rngsdk/` is header-only C++17. If your platform is C#, Java, Node, Go
or Python, you cannot consume it directly, since there is no stable C++ ABI to
target. Use the C wrapper instead: one shared library plus one header
(`c_api/include/rngsdk_c.h`).

### 4.1 Which artifact to ship

Two flavours exist and they export an **identical symbol list**, so your code
needs no conditional compilation and no runtime symbol probing:

| | bundled | openssl |
|---|---|---|
| SHA-256 / HMAC | bundled reference implementation | OpenSSL |
| `RNGSDK_ENGINE_AES_CTR_DRBG` | returns `RNGSDK_ERR_UNSUPPORTED` | available |
| Dependencies at your end | none beyond the C++ runtime | OpenSSL, unless you build it in, see below |

Neither flavour is free of the platform C++ runtime (`MSVCP140.dll` /
`VCRUNTIME140*.dll` on Windows, `libstdc++`/`libc++` elsewhere). And the
OpenSSL row is conditional: the development configuration in this repository
links OpenSSL **dynamically**, so that build imports `libcrypto-3-x64.dll` and
is not a single shippable file. The static recipe below is what makes the
"one file, nothing to install" claim true; run it before you ship, and check
the result with `dumpbin /dependents` (or `ldd`).

Call `rngsdk_build_info()` to ask the binary which one you are holding. That
is also an audit surface: a reviewer can interrogate the shipped artifact
rather than trusting a build log.

For a production deployment that needs AES-CTR-DRBG, ship the OpenSSL flavour
built with OpenSSL linked **statically**, so you receive exactly one file and
need no OpenSSL installed. On Windows with vcpkg that is:

```
vcpkg install openssl:x64-windows-static
cmake -S . -B build-release -DRNGSDK_USE_OPENSSL=ON \
      -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake \
      -DVCPKG_TARGET_TRIPLET=x64-windows-static \
      -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
cmake --build build-release --config Release
```

The trade-off is deliberate: an OpenSSL CVE means we rebuild and reship rather
than a system update silently changing the binary underneath you. For this
market, one file whose contents are attested is worth more than transparent
patching nobody can verify happened.

### 4.2 Batch your calls

Crossing the library boundary costs about as much as generating a random
number, and through a managed FFI such as Python's `ctypes` it costs roughly
a thousand times as much. Every generator function therefore has an `_array`
form, and **that is the one to use**:

```c
uint64_t buf[4096];
rngsdk_next_u64_array(h, buf, 4096);   /* one crossing, 4096 values */
```

The scalar forms exist for convenience. Do not put them in a loop, and do not
benchmark with them, since a benchmark built on `rngsdk_next_u64` measures the FFI,
not the generator, and will make the fast tier look several times slower than
it is.

### 4.3 Memory and lifetime

* **Every buffer is yours.** The library never returns a pointer you must
  free. There is no `rngsdk_free_*`, so a cross-heap allocate/free mismatch
  cannot happen.
* **Handles are freed with their own destroy function**, namely `rngsdk_random_destroy`,
  `rngsdk_pf_session_destroy`. Both accept `NULL`, so cleanup paths need no guard.
* **`rngsdk_status_message` returns static storage.** Never free it. Bindings
  in languages that assume returned strings are owned must copy, not adopt;
  see `bindings/python/rngsdk.py` for the correct handling.
* **String buffers take a capacity and refuse rather than truncate.** Use
  `RNGSDK_HEX_BUF` rather than hard-coding 65; a call that would not fit
  returns `RNGSDK_ERR_BUFFER_TOO_SMALL` and writes nothing.

### 4.4 One handle per thread

Handles are **not** thread-safe, exactly like the C++ objects underneath. Use
one per thread or serialise access yourself. This is documented rather than
enforced: adding an internal mutex would misrepresent the library's real
threading story, which is one engine per thread.

### 4.5 Errors

Every function returns `rngsdk_status`; `RNGSDK_OK` is 0, so
`if (rngsdk_...(...)) { /* handle */ }` is a valid check. No exception can
escape into your frame. Status values are append-only, so a future version may
add codes but will never renumber existing ones, so a compiled caller stays
correct.

Two inputs are refused by the C ABI that the C++ tolerates, both deliberately:
`bound == 0` on any bounded generator, and `lo > hi` on
`rngsdk_next_int_range`. In both cases the C++ would return a value from an
interval you did not ask for. The C ABI returns `RNGSDK_ERR_INVALID_BOUND`.

### 4.6 The security and statistical analyses apply unchanged

Stated plainly rather than left to inference: **`SECURITY_ANALYSIS.md` and
every statistical-battery result in `docs/statistical_results/` apply to the C
ABI exactly as they do to the C++ SDK.** The wrapper contains no cryptographic
logic of its own, no key derivation, no mapping arithmetic, no rejection
sampling. Every exported function checks its arguments, makes one call into
the C++, and translates the outcome into a status code. The test suite asserts
this by comparing C and C++ output **bit for bit** for every engine the build
supports and every mapping function, so the equivalence is enforced rather
than asserted. (That is all four engines in the OpenSSL flavour; the bundled
flavour compares three and asserts that the fourth reports
`RNGSDK_ERR_UNSUPPORTED` rather than silently substituting another.)

The obligations in section 3 above are unchanged too, and obligation 4 in
particular: `rngsdk_random_create_secure` on `RNGSDK_ENGINE_XOSHIRO256PP` or
`RNGSDK_ENGINE_PCG64` seeds the full engine state from OS entropy, which makes
the stream unpredictable at instantiation. It does **not** make the fast tier
cryptographically secure, and the fast tier must never carry paid outcomes.

### 4.7 Verifying your integration

`bindings/python/` contains a complete `ctypes` binding and `cross_check.py`,
which validates the shared library against `docs/pf_test_vectors.json`, the
same canonical vectors the C++ suite and `web/verifier.html` consume. Run it
against the artifact you intend to ship:

```
python bindings/python/cross_check.py --lib <path to your rngsdk_c library>
```

It is also the reference for writing a binding in another language.

## 5. Pre-launch checklist

One line per item. Do not ship until every line is checked, on the actual
deployment target, not the development machine.

- [ ] Client seed is generated on the player's device, never by the operator
      (obligation 1 / SA-03, §6.3).
- [ ] Commitment is published to the player **before** the client seed is
      accepted or set.
- [ ] The next-unused nonce is persisted alongside the server seed on every
      bet, and any resumed session passes it as `start_nonce`, verified with
      an actual `Play()` call, not just a constructor echo (obligation 2 /
      SA-01, §5.1).
- [ ] Every server seed comes from `pf::GenerateServerSeed()`, with no literals,
      no counters, no derived strings (obligation 3 / SA-02, §6.2).
- [ ] Server seeds are rotated between sessions: one server seed per session,
      discarded after `Reveal()`, never constructed into a new
      `ServerSession` a second time.
- [ ] `Play()` is never called on a session after `Reveal()` has been called
      on it (enforced by the library via `TestRevealLock`, but the checklist
      item exists because the enforcement is per-instance and a fresh
      `ServerSession` built from a revealed seed evades it).
- [ ] No fast-tier engine (`FastRandom`, `Pcg64Random`) reaches any outcome a
      player is paid on (obligation 4 / SA-09, §2.1).
- [ ] No `CryptoRandom` is declared at namespace or static scope
      (obligation 4 static-scope caveat / SA §7.4).
- [ ] AES-NI dispatch has been measured with `openssl speed -evp aes-256-ecb`
      on the actual deployment target, not assumed from the development machine
      (obligation 5 / SA-10, §7.1).
- [ ] The web verifier (`web/verifier.html`) is shipped to players alongside
      the game, so they can check a session without trusting the operator's
      own tooling.
