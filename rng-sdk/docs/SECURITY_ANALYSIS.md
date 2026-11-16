# Security analysis: RNG-SDK

**Version:** 1.2 · **Date:** 2026-09-07 · **Status:** complete for the current
tree, **no findings pending**. SA-01, SA-02, SA-03 and SA-07 were found by this
analysis and **have been fixed**; SA-04 and SA-06 were **accepted without code
change on 2026-09-07** (§4.2, §4.4) and the rest are documented gaps carried
deliberately.

*Changes in 1.2:* the SA-04 / SA-06 acceptance decision (§4.2, §4.4, §9.1), and
a correction to §1, whose summary table and headline still described SA-01 as
unfixed and "must be fixed before release" seventeen days after §5.1, §0 and
the §9 register all recorded it fixed.

Companion to `docs/MATH_JUSTIFICATION.md` (which proves *distributional*
properties) and `docs/DESIGN_NOTES.md` (which records design decisions). This
document addresses *adversarial* properties: what an attacker who wants to
predict, reproduce, or bias outcomes can actually do.

## 0. How to read this document

Every substantive claim carries a label:

| Label | Meaning |
|---|---|
| **Theorem** | Proved here or in `MATH_JUSTIFICATION.md`. |
| **Cited** | Established in the referenced literature; we rely on it. |
| **Empirical** | Measured or demonstrated on this codebase. Command given. |
| **Assumption** | Believed, standard, and *not* proved here. Load-bearing. |
| **Open** | Known gap. Not resolved. |

A security document that reports no gaps is a document that did not look. The
findings register in §9 is the part a reviewer should read first.

### 0.1 Threat model

Three adversaries, deliberately separated because the SDK's two tiers owe them
different duties:

* **A1, the player.** Sees every outcome they play, chooses their own client
  seed, sees the commitment before play and the server seed after reveal. Has
  unlimited offline compute between sessions. Cannot read server memory.
* **A2, the operator.** Chooses and holds the server seed. Wants to bias
  outcomes against the player. Constrained only by the commitment published
  before play. This is the adversary the Provably Fair scheme exists to bind.
* **A3, the co-located attacker.** Runs code on the same host: can observe
  cache timing, and in the worst case read process memory (full state
  compromise). Relevant to the DRBG tier, not to the fairness scheme.

Out of scope, stated explicitly rather than silently: physical attacks, fault
injection, compromise of the OS entropy source itself (§7.4), and the
correctness of the surrounding game logic that consumes our numbers.

---

## 1. Summary of posture

| Property | Fast tier (xoshiro256++, PCG64) | Crypto tier (HMAC-DRBG, CTR-DRBG) | Provably Fair |
|---|---|---|---|
| Seed recovery from output | **Broken by design** (§2.1) | Reduces to HMAC/AES (§2.2) | Reduces to HMAC (§2.2) |
| Next-value prediction | **Trivial after recovery** | Infeasible (§3) | Infeasible (§3) |
| Backtracking resistance | None | HMAC: **gap**, accepted (§4.2); CTR: **unproven** (§4.3) | N/A, stateless (§4.5) |
| Prediction resistance | None | **Not implemented**, accepted (§4.4) | N/A |
| Operator bias (A2) | N/A | N/A | Bound by commit–reveal (§5, §6) |
| Nonce replay | N/A | N/A | ✅ SA-01 **fixed 2026-08-21** (§5.1) |

The headline: **the cryptographic tier is sound against A1 and A2 and has
documented, bounded gaps against A3.** Every finding this analysis rated above
Info has been either fixed (SA-01, SA-02, SA-03, SA-07) or explicitly accepted
with its rationale recorded (SA-04, SA-05, SA-06); none is left pending. The
two A3 gaps are accepted rather than closed, and both are conditional on a
compromise of server process memory that the operator's infrastructure, not
this library, must prevent (§4.2). The fast tier offers zero cryptographic
security and this is a design decision, not a defect; see §2.1.

---

## 2. Seed recovery from output

### 2.1 Fast tier: insecure by design

**Cited + Theorem.** `Xoshiro256pp` has a 256-bit state under an
𝔽₂-linear update. Four consecutive 64-bit outputs carry exactly 256 bits, so
the state is *information-theoretically* determined by them. Whether it is
*efficiently* recoverable depends on the output scrambler:

* **xoshiro256\*\***: output is `rotl(s1*5, 7) * 9`. Odd multipliers are
  invertible mod 2⁶⁴ and rotation is a bijection, so the map is a bijection and
  **a single output yields `s1` outright**. This is the origin of the widely
  quoted "recoverable from 4 outputs" figure.
* **xoshiro256++ (ours)**: output is `rotl(s0 + s3, 23) + s0`. This is one
  64-bit equation in two unknowns and is **not** invertible from a single
  output. Recovery requires solving a system that mixes mod-2⁶⁴ addition with
  the 𝔽₂-linear update, strictly harder than the `**` case.

**Open.** This project has **not** verified a concrete attack cost for
xoshiro256++, and none is claimed. The honest statement is: the state is
determined by four outputs, no efficient recovery is published to our
knowledge, and the generator offers **zero cryptographic security**, which is
the authors' own position (Blackman & Vigna 2019). Treating it as anything
else is the error to avoid. See `include/rngsdk/xoshiro256pp.hpp`, whose
comment was corrected on 2026-08-20 for exactly this reason.

**Cited.** For **PCG64** the picture is sharper and worse. Bouillaguet,
Martinez & Sauvage (*Practical seed-recovery for the PCG Pseudo-Random Number
Generator*, IACR ToSC 2020(3):175–196) give a practical guess-and-determine
plus lattice attack that recovers **all hidden parameters and the successive
internal states** from **512 bytes** of output. Cost: roughly 2⁵² instances of
the Closest Vector Problem, ~20,000 CPU-hours worst case.

Note the nuance, because it is the kind of thing that gets flattened in
marketing copy: PCG64 is **broken but not free**, since 20,000 CPU-hours is a real
expense, unlike xoshiro256\*\*'s single-output inversion. Neither is remotely
adequate for money. Both are entirely adequate for Monte Carlo simulation,
which is what the fast tier is for.

**Consequence (normative).** The fast tier MUST NOT be used for any outcome a
player is paid on. The SDK does not enforce this, since `Random<Xoshiro256pp>` is a
public type, so it is an integration-guide obligation (item #8).

### 2.2 Crypto tier and Provably Fair

**Assumption (load-bearing).** HMAC-SHA256 is a secure PRF; AES-256 is a
secure PRP. These are the standard assumptions underpinning SP 800-90A and are
not proved here.

**Theorem (reduction, informal).** Given the PRF assumption, recovering the
server seed from Provably Fair outputs is at least as hard as recovering an
HMAC-SHA256 key from adaptively chosen-message MAC tags. The player controls
the message half (`client_seed:nonce:cursor`) and the server holds the key
half (`server_seed`), precisely the PRF game. Best known generic attack is
exhaustive key search, 2²⁵⁶ for a `GenerateServerSeed()` seed.

**Empirical.** Avalanche behaviour consistent with a PRF is measured in
`MATH_JUSTIFICATION.md` §6 (≈50.0% output-bit flip rate for a single input-bit
flip).

The same reduction covers the DRBG tier's *output-only* attacker. State
compromise is a different question and is §4.

---

## 3. Next-value prediction

**Fast tier.** Immediate once §2.1's recovery succeeds; the update is public
and deterministic. No further work required by the attacker.

**Crypto tier.** **Theorem (reduction).** Distinguishing the next output block
from random, given all previous output but not the state, is the PRF
distinguishing game for HMAC-SHA256 (resp. the PRP game for AES-256). No
better-than-generic attack is known.

**Provably Fair, the important case.** Outcome `n+1` is
`HMAC-SHA256(server_seed, client_seed:n+1:0)`. The player knows
`client_seed`, knows `n+1`, and has seen outcomes `0…n`. Predicting outcome
`n+1` is therefore *exactly* a chosen-message PRF distinguishing attack on
HMAC-SHA256 with an unknown 256-bit key. This is the cleanest security
statement in the SDK: the fairness layer's unpredictability does not depend on
any DRBG, buffering, or state machine, only on HMAC.

**Note.** `pf::ByteStream` computes HMAC directly and never touches a DRBG.
Every DRBG-related finding in §4 is therefore **inapplicable to the Provably
Fair path**. This separation is deliberate and worth preserving.

---

## 4. State compromise (adversary A3)

### 4.1 Definitions

**Cited** (Dodis, Pointcheval, Ruhault, Vergniaud & Wichs, CCS 2013; Woodage &
Shumow, EUROCRYPT 2019 / ePrint 2018/349). Three properties:

* **Backtracking resistance** (= forward security): if the state is
  compromised at time *t*, outputs generated *before* *t* remain
  indistinguishable from random.
* **Prediction resistance** (= backward security): there exists a later time
  *t′* after which outputs are again indistinguishable, i.e. the generator
  recovers from compromise by absorbing fresh entropy.
* **Robustness**: both, in a single game.

### 4.2 HMAC-DRBG: backtracking resistance gap

**Cited.** Woodage & Shumow §7.1 **disprove** SP 800-90A's backtracking-
resistance claim for HMAC-DRBG **when additional input is omitted**. With
`addin = {}` the `0x01` pass of `Update` is skipped, leaving the post-Generate
state satisfying

```
V* == HMAC(K*, r*)          where r* is the LAST output block returned
```

An attacker holding both the state and the output can test this relation,
giving a forward-security distinguisher with advantage ≈ 1 (their Theorem 3).

**Empirical.** This applies to our code. `HmacDrbgEngine::Refill()`
(`include/rngsdk/crypto/drbg_engine.hpp:90`) calls `drbg_.Generate(buf_,
kBufBytes)` with `additional` defaulted empty.

**Scope, before this is over-weighted.** It is a *distinguisher*, not
recovery of unseen past output. It requires the attacker to already hold the
state, from which *future* output is predictable anyway (strictly worse). And
it does not touch the Provably Fair path (§3). Tracked as OPEN_RESEARCH #12.

**Cited.** Woodage & Shumow §7.2 prove robustness **does** hold when
additional input is supplied on every Generate. The fix is therefore
principled rather than a guess; `HmacDrbg::Generate` already accepts
`additional`; only the adapter declines to pass it.

**DECISION 2026-09-07 (user-approved): accepted, no code change.** Option (a)
of OPEN_RESEARCH #12 was taken: the gap is documented and left in place. The
reasoning, recorded because the conclusion is only defensible together with its
premise:

1. **The precondition is compromise of the server process's memory**, not
   knowledge of our implementation. The attacker needs the live `K`/`V` byte
   arrays out of a running `HmacDrbgEngine`. HMAC-SHA256 and the DRBG
   construction are public NIST standards, so reading our source, our binary,
   or this document grants no advantage whatsoever; the entry cost is a
   memory-disclosure bug, a core dump, an attached debugger, or insider process
   access.
2. **An attacker who has cleared that bar already has strictly more than the
   finding grants.** Holding the state, they can predict every *future* output
   of that instance (§4.4). Theorem 3 adds only the ability to *confirm* a
   state/output pairing after the fact, a refinement of an already-total
   compromise, not a new way in.
3. **The money path is untouched.** `pf::ByteStream` recomputes each block from
   `(server_seed, client_seed, nonce, cursor)` and never touches the DRBG state
   machine (§4.5), so no player-visible, bet-bearing outcome is affected by
   this finding at any severity.

The operative control is therefore **operator-side**: prevent process-memory
disclosure. That is an infrastructure obligation the library cannot discharge
on the integrator's behalf, and it is not a new one, since every secret the server
holds, the server seed included, already depends on it.

**What this decision does not claim.** The gap is real and stays in the
register: the SDK is **not** backtracking-resistant on the crypto tier, and
that must not be asserted to a licensee or in the final report. Nor does it
grant prediction resistance; see §4.4 and SA-06, which this same decision
closes on the same premise, and which likewise must not be claimed as present.

**One useful consequence.** Because nothing changes, the generated byte stream
is unchanged: the `hmac` row of `docs/statistical_results/fingerprints.txt`,
the HMAC-engine golden vectors, and any battery run in flight all remain valid.
The "must not land while item #3's runs are outstanding" constraint that
previously attached to this item is discharged rather than deferred, since it was a
constraint on options (b) and (c), both of which would have altered the stream.

### 4.3 CTR-DRBG: no robustness proof exists

**Cited.** This is the finding most likely to surprise, and it matters for how
we position the two crypto engines. Woodage & Shumow provide robustness proofs
(covering both backtracking and prediction resistance) for the **HMAC and Hash**
constructions, but **were unable to do so for CTR_DRBG**, and instead
identified an **attack against its prediction-resistance property**.

Cohney, Kwong, Paz, Genkin, Heninger, Ronen & Yarom (*Pseudorandom Black
Swans: Cache Attacks on CTR_DRBG*, IEEE S&P 2020, ePrint 2019/996) confirm and
extend this at the design level: **"the NIST-recommended CTR_DRBG design does
not have forward security if an attacker is able to compromise the state via a
side-channel attack."** Their explicit recommendation: *"Where FIPS compliance
is required, HASH_DRBG and HMAC_DRBG give better security guarantees."*

**Consequence for our positioning.** CTR-DRBG's measured **~13×** throughput
advantage over HMAC-DRBG (DESIGN_NOTES §8b) is bought partly with **weaker
provable guarantees**. That trade-off is legitimate and should be stated
plainly to licensees rather than buried: HMAC-DRBG is the better-assured
engine; CTR-DRBG is the faster one. `CryptoRandom` currently aliases
HMAC-DRBG, which on this analysis is the correct default and should stay.

### 4.4 Audit against Cohney et al.'s countermeasures

Their paper closes with four concrete countermeasures for implementers who
keep CTR_DRBG. Auditing our tree against them:

| # | Countermeasure | Status |
|---|---|---|
| 1 | Use AES hardware instructions | ✅ **Verified by measurement**, see §7.1 |
| 2 | Limit data requested in a single call | ✅ 4 KiB max per `Generate` (`kBufBytes`), far under the spec's 2¹⁹-bit ceiling |
| 3 | Reseed frequently | ❌ **Never automatic**, see §4.4 below |
| 4 | Populate `addin` with high-quality entropy | ❌ **Always empty**, same root cause as §4.2 |

Two of four. Both gaps are the same underlying decision (OPEN_RESEARCH #12),
**decided 2026-09-07: accepted without code change** (§4.2). Countermeasures 3
and 4 therefore stay unmet by choice, not by oversight, and both remain in the
register at their measured severity.

**Empirical (finding SA-06).** `Reseed()` exists on both engines
(`BufferedDrbgEngine::Reseed`, `drbg_engine.hpp:71`) but is **caller-driven only**.
Nothing in the SDK reseeds automatically. `Generate` throws once
`reseed_counter_ > 2⁴⁸`, which is a *conformance stop*, not a reseed. The
consequence, stated plainly: **the crypto tier has no prediction resistance and
never recovers from a state compromise.** Once A3 reads the state, every
subsequent output from that instance is predictable, forever, until the process
restarts or the caller reseeds explicitly.

For per-bet casino workloads this is a modest risk (A3 with memory-read access
has already lost you the game), but it is a real gap against the SP 800-90A
"prediction resistance" option and must not be claimed as present.

**DECISION 2026-09-07 (user-approved): accepted, no code change**, on the same
premise as §4.2: the finding is conditional on a state compromise that the
operator's infrastructure must prevent, and an adversary past that point owns
the instance regardless. `Reseed()` stays **available and caller-driven** on
both engines, so a licensee whose threat model does demand prediction
resistance can schedule it without an SDK change; the SDK simply does not do it
for them, and does not claim the SP 800-90A prediction-resistance option.

### 4.5 The Provably Fair layer is stateless

**Theorem.** `pf::ByteStream` holds `(server_seed, client_seed, nonce,
cursor)` and recomputes `HMAC-SHA256(server_seed, client_seed:nonce:cursor)`
from scratch per 32-byte block. There is no evolving secret state. Therefore
backtracking and prediction resistance are **not applicable**: compromising the
"state" means compromising the server seed itself, which is total compromise by
definition and is handled by seed rotation (§6.1), not by DRBG semantics.

This is a genuine architectural strength and is worth saying in the report: the
money path depends on one primitive and one secret, with no state machine to
get wrong.

---

## 5. Nonce attacks

### 5.1 SA-01 (CRITICAL): nonce reset enables outcome replay

**Empirical. Demonstrated on the current tree.**

`pf::ServerSession::SetClientSeed()` (`provably_fair.hpp:179`) sets the client
seed and resets `next_nonce_ = 0`, with **no record of which
`(server_seed, client_seed)` pairs have already been played**:

```cpp
void SetClientSeed(std::string client_seed) {   // player's move, before any bet
    client_seed_ = std::move(client_seed);
    next_nonce_ = 0;   // fresh pair -> nonce restarts
}
```

The comment says "before any bet"; nothing enforces it. A player who
re-selects a client seed they have already used replays the identical outcome
sequence, outcomes they have **already seen**.

**Demonstration** (`nonce_replay.cpp`, run 2026-08-21):

```
round 1 (client seed A, nonces 0..4):
  nonce 0 -> 0.0504284776
  nonce 1 -> 0.6870517486
  nonce 2 -> 0.4673516236
  nonce 3 -> 0.6156957895
  nonce 4 -> 0.9988193305

after re-selecting the same client seed, NextNonce() = 0

round 2 (same client seed, nonce restarts at 0):
  nonce 0 -> 0.0504284776   IDENTICAL
  nonce 1 -> 0.6870517486   IDENTICAL
  ...
VERDICT: REPLAY CONFIRMED - outcomes repeat exactly
```

**Exploit.** Player sets client seed `A`, plays *n* minimum-stake bets, records
which nonces won. Re-selects client seed `A`. Bets maximum stake on exactly the
nonces known to win. The game's edge is not reduced, it is **inverted**. This
is the classic nonce-reuse failure the spec explicitly asks us to defend
against, and it has been exploited in production systems in the wild.

**Severity: critical.** Directly monetisable by an unprivileged player,
requires no cryptanalysis, and needs only the public API.

**Note on our own prior claim.** `OPEN_RESEARCH.md` #6 asserted that nonce
repetition was "blocked by `ServerSession`". That assertion was **false**, and the class's own
header comment describes the invariant it fails to enforce. This is the second
time in this project that a comment asserting a property substituted for a test
of it (cf. the 4 KiB boundary comment found in the 2026-08-18 review). The
lesson generalises: **invariants claimed in prose need a test that fails when
they break.**

**FIXED 2026-08-21.** The nonce no longer resets. `SetClientSeed()` changes
the seed and nothing else; the counter runs monotonically for the life of the
session.

```cpp
void SetClientSeed(std::string client_seed) {
    client_seed_ = std::move(client_seed);
    client_seed_set_ = true;
}
```

Seed A takes nonces 0–4, seed B takes 5–9, and returning to seed A takes
10–14. Since `(A, 10) ≠ (A, 0)`, no input triple ever repeats and the replay is
impossible.

**Why this over the obvious alternative.** The first candidate fix was to
remember used client seeds in a `std::set` and refuse repeats. That works, but
it is unbounded memory (a player spamming seed changes is a slow resource
attack) and, more importantly, it makes the guarantee depend on *bookkeeping
being correct*. Not resetting makes reuse **harmless rather than forbidden**,
a property that holds with no state to maintain and nothing to get wrong. The
cost is a mild divergence from the convention that the nonce is per-(server,
client) pair; verification is unaffected, because the verifier takes
`(server_seed, client_seed, nonce)` explicitly and all three are recorded per
bet.

Regression test: `TestClientSeedReuseDoesNotReplay`, which fails against the
pre-fix code.

**Related vector, closed by the same reasoning (new, 2026-08-21).** A server
that **restarts mid-session** and re-instantiates `ServerSession` with the same
seed would begin again at nonce 0, the identical defect, arriving by a
different route. `ServerSession` therefore takes an optional `start_nonce` so a
resumed session continues where it left off. Operators MUST persist the nonce
alongside the server seed; this is an integration-guide obligation (#8).

**Does this change generated bytes?** No. It rejects misuse and repositions a
counter; it does not alter any byte produced by correct usage. Verified: all
six rows of `docs/statistical_results/fingerprints.txt` regenerate identically
after the fix, `pf` included.

### 5.2 Nonce overflow

**Theorem.** `next_nonce_++` is an unguarded `std::uint64_t`. Wrapping requires
2⁶⁴ ≈ 1.8 × 10¹⁹ bets in one session. At a sustained and wholly unrealistic
10⁶ bets/second that is ~5.8 × 10⁵ years. **Practically unreachable.**

**FIXED 2026-08-21 (SA-07).** Unreachable is not the same as impossible, and
the consequence of a wrap would be silent nonce reuse, the §5.1 failure
again. `Play()` now throws at `UINT64_MAX` rather than wrapping. The cost is
one comparison on a path that already computes an HMAC.

The point is not the arithmetic, which was never in doubt; it is that the
guarantee is now **enforced by the code rather than argued in a comment**. A
reviewer who sees an unguarded counter has to reconstruct the safety argument;
one who sees a guard does not. Regression test:
`TestNonceOverflowRefused`.

### 5.3 Nonce predictability

**Theorem.** The nonce is a public, monotonic counter. This is correct and
requires no defence. Security rests entirely on `server_seed` being unknown
until reveal: for HMAC as a PRF, knowing the message (`client_seed:nonce:
cursor`) confers no advantage without the key. Indeed the nonce **must** be
public, since the player cannot verify outcomes after reveal without it.

A design that tried to hide the nonce would break verifiability while adding
nothing, since PRF security is defined against an adversary who chooses
messages.

---

## 6. Operator bias, commitment grinding, and seed reuse

### 6.1 Commitment binding

**Theorem.** The published `SHA-256(server_seed)` binds the operator to that
seed under collision resistance: producing a second seed with the same
commitment requires a SHA-256 collision (2¹²⁸ generic) or, for a targeted
substitution, a second preimage (2²⁵⁶ generic).

**Theorem.** Recovering the seed *forward* from the commitment before reveal
requires a preimage: 2²⁵⁶ for a `GenerateServerSeed()` seed (32 OS bytes,
hex-encoded). Infeasible.

### 6.2 SA-02 (HIGH): no entropy floor on the server seed

**Empirical.** `ServerSession(std::string)` accepts anything.
`ServerSession("abc")` is silently allowed, though the header documents a
≥128-bit contract.

The commitment is a **free offline brute-force oracle**: enumerate candidate
seeds, hash, compare. Against a low-entropy seed this is trivial. At a
commodity ~10¹⁰ SHA-256/s:

| Server seed | Search space | Time to recover |
|---|---|---|
| `"abc"` (dictionary) | ~2²⁰ | instant |
| 8 chars, lowercase | 26⁸ ≈ 2×10¹¹ | ~20 seconds |
| 12 chars, mixed alphanumeric | 62¹² ≈ 3×10²¹ | ~10⁴ years |
| `GenerateServerSeed()` (256-bit) | 2²⁵⁶ | infeasible |

A player who recovers the server seed before reveal knows **every future
outcome** and the game is over. Note this is worse than ordinary password
cracking: the attacker is offline, unrate-limited, and knows exactly when they
have succeeded.

**FIXED 2026-08-21.** `ServerSession` now enforces
`kMinServerSeedChars = 32` and throws `std::invalid_argument` naming
`GenerateServerSeed()`. 32 characters is 128 bits *if* the seed is
hex-encoded, which is what `GenerateServerSeed()` produces and the only
supported path. Regression test: `TestWeakServerSeedRefused`.

**Stated limitation, deliberately.** Length is a **proxy** for entropy, not a
measure of it. This rejects the realistic failure, a short hand-typed seed,
and **cannot** detect a 64-character seed derived from a counter or a
timestamp. A library that receives a `std::string` has no way to distinguish
those. The real obligation is "use `GenerateServerSeed()`", and the floor only
makes the common accident loud.

### 6.3 SA-03 (MEDIUM): default client seed enables grinding

**Theorem (the grinding argument).** Commit–reveal binds the operator *after*
the commitment, but the operator chooses **which** seed to commit to. Suppose
the operator can predict the client seed at commit time. It may then generate
*G* candidate server seeds, compute the resulting outcomes for the predicted
client seed, and commit to the most favourable. Forcing a specific 1-in-*N*
outcome costs ≈ *N* HMAC evaluations, and at ~10¹⁰/s, a 1-in-10⁶ outcome takes
under a millisecond and a 1-in-10⁹ outcome about a tenth of a second.
**Grinding is essentially free.**

The defence is *not* the commitment. It is that the client seed is chosen
**after** the commitment is published and is unpredictable to the operator: if
the client seed carries *k* bits of entropy, the operator grinding *G* seeds
succeeds with probability ≈ *G*·2⁻ᵏ, because it must guess *k* before it can
evaluate a candidate.

**Empirical (the landmine).** `ServerSession` initialises
`client_seed_ = "default"` (`provably_fair.hpp:208`). An integrator who never
calls `SetClientSeed` gets a **fully known client seed at commit time**, and
the grinding defence collapses entirely. The scheme still *looks* correct,
with commitments verifying and replays checking out, while being completely
broken.

**FIXED 2026-08-21.** The `"default"` literal is gone. `Play()` now throws
until `SetClientSeed()` has been called explicitly. Regression test:
`TestPlayWithoutClientSeedRefused`.

**What this fix does *not* do, to state plainly to licensees.** The SDK receives a
`std::string`. It **cannot** tell whether that string came from the player's
browser or from the operator's own RNG. The fix therefore removes the
*accidental* failure (an integrator who never sets one and ships a fixed
constant to every player forever); it cannot prevent the *deliberate* one.

That half is an integration obligation and belongs in #8 as a **MUST**:

> Generate the client seed on the player's device (`crypto.getRandomValues`),
> after the commitment has been published. Never generate it server-side, and
> never derive it from anything the operator controls.

This matters more than it sounds. On a real slot game the client seed is
pre-filled and most players never open the fairness panel. A browser-generated
default is safe; a server-generated one is theatre, **and the two are visually
identical to the player.** Both show a random-looking string in a box, both
verify, both replay correctly. Only one of them actually binds the operator.

### 6.4 Seed rotation and reuse

**Empirical.** `Reveal()` sets `revealed_` and `Play()` throws thereafter
(item 5b, `TestRevealLock`). This correctly prevents the worst reuse case:
generating outcomes from a seed whose value is public.

**Open.** Nothing prevents constructing a *new* `ServerSession` with a
previously revealed seed. The class cannot detect this, since it has no memory
across instances, so it is an operator obligation: **one server seed per
session, never reused after reveal.** State it in the integration guide.

---

## 7. Side channels

### 7.1 AES implementation dispatch: verified, not assumed

**Cited.** Cohney et al. demonstrate CTR_DRBG state recovery from **~2000
bytes** of output plus concurrent cache observation, against implementations
using **T-table AES**, namely OpenSSL 1.0.2's FIPS module, the NetBSD kernel,
FortiOS (CVE-2019-15703), and mbedTLS-SGX. Under SGX they recover state
*blind*, within three AES encryptions, without seeing output at all. Measured
recovery time averaged 19 s; with the hardware prefetcher disabled the attack
succeeded in 100% of 100 trials.

Their general guidance: *"constant-time code should be used for all
cryptographic applications, unless hardware support (e.g., AES-NI) is
available."*

**Empirical.** Whether *our* build takes the AES-NI path cannot be determined
by reading our source, since EVP dispatches at runtime from CPU capabilities, so it
is a property of the CPU plus the OpenSSL build and must be **measured**.
Asserting "OpenSSL uses AES-NI" without measuring is precisely the unexamined
inheritance that paper documents. Two signals were measured on this target
(2026-08-20, OpenSSL 3.6.3, AMD Athlon Gold 3150U @ 2.4 GHz): `CPUID.1:ECX[25]`
reported AES-NI present, and `EVP_aes_256_ecb` ran at 4908 to 5707 MB/s over
five runs. A licensee reproduces the throughput signal on their own target
with `openssl speed -evp aes-256-ecb` (INTEGRATION_GUIDE obligation 5).

~5300 MB/s is ≈2.3 bytes/cycle at base clock, exactly the Zen ceiling for
AES-256 (14 rounds, two AES pipes → 2·16/14 B/cycle). A T-table software path
runs ~100–250 MB/s. The order-of-magnitude gap makes the dispatch unambiguous.

**Open (SA-10).** This is a **per-target** result, not a property of the SDK.
Any deployment on hardware without AES-NI falls back to a table-based path and
Cohney et al.'s finding **does** apply. Re-run the probe on every deployment
target; make this a release-checklist item. Also note their disclosure outcome:
OpenSSL considered these attacks outside its threat model, so no upstream fix
should be expected.

**Note.** The finding does not implicate HMAC-DRBG (no table lookups) or the
Provably Fair path.

### 7.2 Timing of rejection sampling

`Random<E>::NextUInt64(bound)` and `pf::Generator::NextIntsUnbiased` loop until
a draw is accepted, so their execution time varies. This looks alarming and is
routinely flagged in review, so it is worth settling precisely.

**Theorem.** Let *R* be the number of rejections before acceptance and *Y* the
returned value. Under the assumption that engine words are i.i.d. uniform on
[0, 2⁶⁴), *R* and *Y* are **independent**. Rejection depends only on the low
half of the widening product of the *discarded* words; conditioned on
acceptance, the accepted word is uniform on the accepted set regardless of how
many rejections preceded it. Hence *R* ~ Geometric(1 − *t*/2⁶⁴) carries **no
information about the returned value**.

What *R* does leak is the rejection rate, hence `bound`, which is a public
game parameter (the number of faces, cards, or symbols). Nothing secret leaks.

**Verdict: acceptable; document, do not fix.** Making the loop constant-time
would require either a fixed worst-case iteration count (a large slowdown for
no security gain here) or abandoning exact unbiasedness, and exact
unbiasedness is a headline requirement of the spec (`MATH_JUSTIFICATION.md`
§3, Theorem 3.4). The trade is clearly correct in this direction.

**Caveat.** The independence argument rests on the i.i.d.-uniform word
assumption, which for the crypto tier is the PRF assumption of §2.2 and for the
fast tier is an idealisation. It is not a constant-time guarantee, and this
code should not be reused in a setting where the *bound itself* is secret.

### 7.3 Other side channels

**Open.** Not analysed: memory-access patterns of the mapping layer, branch
prediction in `NextInt`, and compiler-introduced variation. Considered low
priority because the returned outcome becomes public almost immediately in a
gambling workload, since the value being protected has a very short secret lifetime.
The long-lived secret is the server seed, and it is touched only inside HMAC.

### 7.4 Entropy source

**Assumption (delegation, deliberate).** `crypto/os_entropy.hpp` consumes the
platform CSPRNG (`BCryptGenRandom` / `getrandom(2)` / `getentropy(3)` /
`/dev/urandom`), applies **no conditioning**, and has **no fallback**, since it
throws rather than degrade silently. SP 800-90B obligations (noise-source
validation, health tests) are delegated to the platform.

This is a "consume, do not own" position and it is the right one: the OS
sources are full-entropy by their own validation, and post-processing cannot
increase entropy (H(f(X)) ≤ H(X)). The trade-off to state to a licensee: **our
entropy assurance is exactly the platform's**, and a customer requiring
end-to-end SP 800-90B evidence needs it from their OS vendor, not from us.

**Open.** `CryptoRandom` is unsafe at namespace/static scope, since a throwing
default constructor during dynamic initialisation calls `std::terminate` with
no catch site. No such usage exists in-tree; it is an integration-guide item.

---

## 8. What an attacker cannot do

Stated for completeness, because a findings register alone reads more alarming
than the posture warrants:

* **Predict a Provably Fair outcome before reveal** without breaking
  HMAC-SHA256 (§3), given a properly generated server seed (§6.2) and a
  player-chosen client seed (§6.3).
* **Forge a commitment**, i.e. reveal a seed different from the committed one,
  without a SHA-256 second preimage (§6.1).
* **Bias outcomes as the operator** once a high-entropy client seed is supplied
  after the commitment (§6.3).
* **Recover the server seed from any quantity of outputs** without breaking
  HMAC's PRF security (§2.2).
* **Exploit modulo bias**, which is provably absent (`MATH_JUSTIFICATION.md`
  §3, Theorem 3.4) rather than merely small.

---

## 9. Findings register

| ID | Severity | Finding | § | Status |
|---|---|---|---|---|
| **SA-01** | **Critical** | `SetClientSeed` reset the nonce with no reuse check → replay of already-observed outcomes. Demonstrated. | 5.1 | ✅ **Fixed 2026-08-21** |
| **SA-02** | **High** | No entropy floor on the server seed; commitment is an offline brute-force oracle. | 6.2 | ✅ **Fixed 2026-08-21** |
| **SA-03** | **Medium** | Default `client_seed = "default"` silently defeated the anti-grinding defence. | 6.3 | ✅ **Fixed 2026-08-21** (library half); second half discharged by `docs/INTEGRATION_GUIDE.md` (obligation 1) 2026-08-31 |
| SA-04 | Medium | HMAC-DRBG backtracking resistance disproved without additional input. | 4.2 | ✅ **Accepted 2026-09-07**, no code change; conditional on server-memory compromise (§4.2) |
| SA-05 | Medium | CTR-DRBG has no robustness proof; prediction-resistance attack known. | 4.3 | Documented; HMAC stays default |
| SA-06 | Low | No automatic reseed → no prediction resistance, no compromise recovery. | 4.4 | ✅ **Accepted 2026-09-07**, same premise; `Reseed()` stays caller-driven (§4.4) |
| SA-07 | Low | Nonce overflow unguarded (unreachable, but silent if reached). | 5.2 | ✅ **Fixed 2026-08-21** |
| SA-08 | Info | Rejection sampling variable-time; leak proved independent of output. | 7.2 | Accepted, documented |
| SA-09 | Info | Fast tier offers zero cryptographic security. | 2.1 | Discharged by `docs/INTEGRATION_GUIDE.md` (obligation 4) 2026-08-31 |
| SA-10 | Info | AES-NI dispatch is a per-target property; re-verify per deployment. | 7.1 | Discharged by `docs/INTEGRATION_GUIDE.md` (obligation 5) 2026-08-31 |

### 9.1 Remaining work

1. **SA-04 / SA-06**: **resolved 2026-09-07**, as anticipated by one decision
   (OPEN_RESEARCH #12, option (a)): both **accepted without code change**, on
   the ground that each is conditional on a compromise of server process memory
   that hands the attacker more than the finding itself does, and that neither
   reaches the Provably Fair path. Full rationale and the limits of the claim
   are in §4.2; the SA-06 half is in §4.4. The previous entry's blocking
   condition, *must not land while item #3's battery runs are outstanding*,
   **is discharged, not deferred**: it applied to options (b) and (c), which
   would have changed the generated stream. Accepting the finding changes no
   bytes, so the `hmac` fingerprint row, the HMAC-engine golden vectors, and any
   battery run in flight all stay valid, and item #3 is no longer gated by this
   decision in either direction.
2. **SA-03's second half, SA-09, SA-10**: discharged 2026-08-31 by
   `docs/INTEGRATION_GUIDE.md` (item #8): the client-seed provenance rule
   (§6.3, obligation 1), the fast-tier ban (obligation 4), and the AES-NI
   re-verification instruction (obligation 5) are each stated there with a
   failure mode, wrong code, right code, and this document's cross-reference.
   The client-seed provenance rule is still the one a licensee is most likely
   to get wrong, because getting it wrong still looks correct, and the guide
   cannot force compliance, only make the obligation legible. The release
   checklist referenced above is the guide's own §4 pre-launch checklist,
   which includes the AES-NI dispatch measurement as a tickable line.
3. **SA-05**: carry into the final report's engine-comparison section: the
   ~13× CTR-DRBG speed advantage is bought partly with weaker provable
   guarantees.

### 9.2 Verification of the 2026-08-21 fixes

Each fix has a regression test that **was watched failing against the pre-fix
code** (13 failing checks across four tests) before the implementation existed:

| Test | Guards |
|---|---|
| `TestClientSeedReuseDoesNotReplay` | SA-01 |
| `TestNonceOverflowRefused` | SA-07 |
| `TestWeakServerSeedRefused` | SA-02 |
| `TestPlayWithoutClientSeedRefused` | SA-03 |

Suites after the fixes: **666,638 bundled / 889,364 OpenSSL**, both
warning-free. All six determinism fingerprints regenerate byte-identically,
so the batteries in flight are unaffected.

---

## 10. References

1. NIST SP 800-90A Rev. 1, *Recommendation for Random Number Generation Using
   Deterministic Random Bit Generators*, 2015.
2. NIST SP 800-90B, *Recommendation for the Entropy Sources Used for Random Bit
   Generation*, 2018.
3. J. Woodage & D. Shumow, *An Analysis of NIST SP 800-90A*, EUROCRYPT 2019
   (IACR ePrint 2018/349).
4. S. Cohney, A. Kwong, S. Paz, D. Genkin, N. Heninger, E. Ronen & Y. Yarom,
   *Pseudorandom Black Swans: Cache Attacks on CTR_DRBG*, IEEE S&P 2020
   (IACR ePrint 2019/996).
5. Y. Dodis, D. Pointcheval, S. Ruhault, D. Vergniaud & D. Wichs, *Security
   Analysis of Pseudo-Random Number Generators with Input*, CCS 2013.
6. C. Bouillaguet, F. Martinez & J. Sauvage, *Practical Seed-Recovery for the
   PCG Pseudo-Random Number Generator*, IACR ToSC 2020(3):175–196.
7. D. Blackman & S. Vigna, *Scrambled Linear Pseudorandom Number Generators*,
   ACM TOMS, 2021 (xoshiro/xoroshiro).
8. D. Lemire, *Fast Random Integer Generation in an Interval*, ACM TOMACS,
   2019 (arXiv:1805.10941).
