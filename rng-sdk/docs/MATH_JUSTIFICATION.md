# Mathematical justification

**Document status:** draft, 2026-08-20. Companion to `DESIGN_NOTES.md` (which
records *decisions*); this document records *proofs and their limits*.

**Audience:** a technical reviewer acting for a prospective licensee, who is
expected to check the arguments rather than accept them.

Every claim below is labelled by its epistemic status:

| Label | Meaning |
|---|---|
| **Theorem / Proposition** | Proved here, or proved in cited literature and instantiated here with our parameters verified. |
| **Cited result** | Proved elsewhere; we state it, cite it, and check that our configuration satisfies its hypotheses. |
| **Empirical** | Measured, not proved. Sample size and test bound given. |
| **Assumption** | Unproven and unprovable with current mathematics (e.g. "SHA-256 is a PRF"); stated explicitly so it can be audited. |
| **Open** | Not yet established. Listed rather than hidden. |

The distinction matters commercially: a licensee who cannot tell which claims
are proved and which are assumed cannot price the risk.

---

## 1. Scope and notation

Throughout, $M = 2^{64}$ unless stated otherwise, and "uniform" means exactly
uniform on the stated finite set, not approximately uniform.

The SDK exposes two tiers with *deliberately different* security claims:

* **Fast tier**: `Xoshiro256pp`, `Pcg64`. Claims: long period, good
  equidistribution, high throughput. Explicitly claims **no** cryptographic
  security (§7.1).
* **Cryptographic tier**: `HmacDrbgEngine`, `CtrDrbgEngine`. Claims:
  computational unpredictability under standard assumptions (§7.2), NIST
  SP 800-90A conformance.

Two notions must not be conflated:

* **Statistical quality**: the output is hard to distinguish from uniform by
  a *fixed battery of tests*. Both tiers claim this.
* **Computational security**: the output is hard to distinguish from uniform
  by *any* efficient adversary. Only the cryptographic tier claims this.

The fast tier passing BigCrush establishes the first and says nothing about
the second. This document keeps them separate throughout, because conflating
them is the most common error in RNG marketing material and the fastest way
to lose a technical review.

**Terminology (SP 800-90A).** *Backtracking resistance* (equivalently
*forward security*): compromise of the state at time $T$ does not reveal
output produced before $T$. *Prediction resistance*: compromise at time $T$
does not reveal output produced after $T$, and this requires reseeding from a
fresh entropy source and is a property of the *deployment*, not of the
algorithm alone. §7.2 shows one of these is more delicate than the standard
claims.

---

## 2. Algorithm descriptions

### 2.1 xoshiro256++

State $s = (s_0, s_1, s_2, s_3) \in (\mathbb{F}_2^{64})^4$, i.e.
$\mathbb{F}_2^{256}$. One step (`xoshiro256pp.hpp:44`):

$$\text{output} = \big(\mathrm{rotl}(s_0 + s_3,\ 23)\big) + s_0 \pmod{2^{64}}$$

then the state update, with $t = s_1 \ll 17$:

$$s_2 \mathrel{\oplus}= s_0,\quad s_3 \mathrel{\oplus}= s_1,\quad s_1 \mathrel{\oplus}= s_2,\quad s_0 \mathrel{\oplus}= s_3,\quad s_2 \mathrel{\oplus}= t,\quad s_3 = \mathrm{rotl}(s_3, 45)$$

The state update is **$\mathbb{F}_2$-linear**: xor, shift and rotate are all
linear over $\mathbb{F}_2$, so the update is a matrix
$T \in \mathrm{GL}_{256}(\mathbb{F}_2)$ acting on the state vector. This is what
makes the period provable (§4.1) and, equally, what makes the raw state sequence
cryptographically useless (§7.1).

The output function (the "++" scrambler) uses addition mod $2^{64}$, which is
*not* $\mathbb{F}_2$-linear; it exists to destroy the linear artefacts that
would otherwise show up in low-order bits. It is applied to a copy of the
state and does not feed back, so it cannot affect the period.

### 2.2 PCG64 (XSL-RR 128/64, "setseq")

State $x \in \mathbb{Z}_{2^{128}}$, advanced by a linear congruential step
(`pcg64.hpp:61`):

$$x_{n+1} = a\,x_n + c \pmod{2^{128}}, \qquad a = \texttt{0x2360ed051fc65da44385df649fccf645}$$

with $c$ the *stream selector*, forced odd at seeding time by
`detail::shl1_or1` (`pcg64.hpp:41`). Output is the XSL-RR permutation of the
post-step state:

$$\text{output} = \mathrm{rotr}_{64}\big(x_{\text{hi}} \oplus x_{\text{lo}},\ x_{\text{hi}} \gg 58\big)$$

i.e. fold the 128-bit state to 64 bits by xor, then rotate by an amount taken
from the top 6 bits of the state. The rotation amount being *state-dependent*
is the "permuted" in PCG: it breaks the lattice structure that plain LCG
output exhibits.

### 2.3 HMAC-DRBG (SP 800-90A §10.1.2)

State $(K, V) \in \{0,1\}^{256} \times \{0,1\}^{256}$, with a reseed counter.
The three functions, as implemented in `hmac_drbg.hpp`:

**Update**$(\textit{provided})$, `hmac_drbg.hpp:107`:
$$K \leftarrow \mathrm{HMAC}(K, V \Vert \texttt{0x00} \Vert \textit{provided}), \qquad V \leftarrow \mathrm{HMAC}(K, V)$$
and if $\textit{provided} \neq \varepsilon$, a second pass with `0x01`.

**Instantiate**$(\textit{entropy}, \textit{nonce}, \textit{pers})$: set
$K = 0^{256}$, $V = \texttt{0x01}^{32}$, then
$\textbf{Update}(\textit{entropy} \Vert \textit{nonce} \Vert \textit{pers})$.

**Generate**$(n, \textit{addin})$: if $\textit{addin} \neq \varepsilon$,
$\textbf{Update}(\textit{addin})$; then repeatedly
$V \leftarrow \mathrm{HMAC}(K,V)$, emitting $V$ until $n$ bytes are produced;
then $\textbf{Update}(\textit{addin})$ and increment the reseed counter.

Enforced limits (`hmac_drbg.hpp:36-39`): security strength 256 bits,
$\le 2^{19}$ bits per request, reseed interval $2^{48}$ requests, entropy
input $\ge 32$ bytes. Exceeding them **throws** rather than degrading, a
deliberate choice, since a silently over-used DRBG is indistinguishable from
a correct one by inspection of its output.

### 2.4 CTR-DRBG (SP 800-90A §10.2.1, AES-256, no derivation function)

State $(\textit{Key}, V)$ with $\textit{Key} \in \{0,1\}^{256}$,
$V \in \{0,1\}^{128}$; $\textit{seedlen} = 256 + 128 = 384$ bits $= 48$ bytes.
Output blocks are $\mathrm{AES}_{\textit{Key}}(V)$ with $V$ incremented mod
$2^{128}$ per block; after each request the state is replaced by the next two
output blocks xored with the (zero-padded) additional input.

**The no-df choice is a hypothesis, not a shortcut.** The derivation function
exists to condition seed material that is *not* full-entropy or *not* exactly
$\textit{seedlen}$ bits. Our seed material is exactly 48 bytes drawn from the
OS CSPRNG (`os_entropy.hpp`), so both preconditions for omitting it are met.
This is also the configuration for which NIST publishes CAVP vectors, which
is why item #4 could validate it directly. §7.2 records the security caveat
this choice inherits.

---

## 3. Uniformity: the no-bias proofs

This section discharges the spec's requirement of "proof of no systematic
bias". Two of the three results are exact; the third is exact only in its
unbiased variant, and the biased variant's error is bounded explicitly rather
than waved away.

### 3.1 Doubles and floats

**Proposition 3.1.** Let $x$ be uniform on $\{0,\dots,2^{64}-1\}$. Then
`NextDouble()` $= (x \gg 11)\cdot 2^{-53}$ is exactly uniform on the grid
$G = \{k\cdot 2^{-53} : 0 \le k < 2^{53}\} \subset [0,1)$, every grid point is
exactly representable as an IEEE-754 double, and the value $1.0$ is never
returned.

*Proof.* Let $Y = \lfloor x/2^{11} \rfloor$. For each $k \in \{0,\dots,2^{53}-1\}$,
$$\{x : Y = k\} = \{k\cdot 2^{11},\ k\cdot 2^{11}+1,\ \dots,\ k\cdot 2^{11}+2^{11}-1\},$$
a set of exactly $2^{11}$ elements. Hence
$\Pr[Y = k] = 2^{11}/2^{64} = 2^{-53}$, independent of $k$: $Y$ is uniform on
$\{0,\dots,2^{53}-1\}$.

Representability: $Y < 2^{53}$ and the double significand holds 53 bits, so
$Y$ is exact; multiplication by $2^{-53}$ only adjusts the exponent, so
$Y\cdot 2^{-53}$ is exact and the map $k \mapsto k2^{-53}$ is injective on the
grid. The maximum is $(2^{53}-1)2^{-53} = 1 - 2^{-53} < 1$. $\square$

The float path is identical with $24$ bits: $(x \gg 40)\cdot 2^{-24}$, uniform
on $\{k2^{-24}\}$, exact in a 24-bit significand.

**Why the naive construction is wrong.** $x/2^{64}$ with $x$ a 64-bit integer
requires rounding $x$ to 53 bits. Under round-to-nearest the induced
distribution on representable doubles is *not* uniform (the preimage sizes
differ across the exponent range), and $x$ close to $2^{64}$ rounds to exactly
$1.0$, out of range for a $[0,1)$ contract, and a live division-by-zero or
index-out-of-bounds hazard in any consumer computing $\lfloor f\cdot N\rfloor$.
Proposition 3.1 removes both failure modes by construction, not by clamping.

### 3.2 Bounded integers: Lemire rejection

This is the spec's explicit requirement to eliminate modulo bias. We prove
the stronger statement that the result is *exactly* uniform, not merely
low-bias.

**Setup.** Fix $N$ with $1 \le N < M = 2^{64}$. For $x \in \{0,\dots,M-1\}$
define the high and low words of the $128$-bit product:
$$h(x) = \left\lfloor \frac{xN}{M} \right\rfloor, \qquad \ell(x) = xN \bmod M.$$
Write $M = qN + t$ with $q = \lfloor M/N \rfloor$ and $t = M \bmod N$.
The algorithm (`random.hpp:72`) returns $h(x)$, redrawing $x$ whenever
$\ell(x) < t$.

Define the *lane* $L_k = \{x : h(x) = k\}$ for $k \in \{0,\dots,N-1\}$.

**Lemma 3.2.** $|L_k| \in \{q, q+1\}$, and writing $x_k = \min L_k$ and
$\ell_k = \ell(x_k)$, we have $|L_k| = q+1 \iff \ell_k < t$.

*Proof.*
$L_k = \{x : kM \le xN < (k+1)M\} = \{x : \lceil kM/N\rceil \le x < \lceil (k+1)M/N\rceil\}$,
so $x_k = \lceil kM/N \rceil$ and $|L_k| = x_{k+1} - x_k$. From
$\ell_k = x_kN - kM$ and $\ell_{k+1} = x_{k+1}N - (k+1)M$ we get
$$|L_k|\,N = (x_{k+1}-x_k)N = M + \ell_{k+1} - \ell_k = qN + t + \ell_{k+1} - \ell_k .$$
Both $\ell_k, \ell_{k+1} \in [0,N)$ and $t \in [0,N)$, so
$t + \ell_{k+1} - \ell_k \in (-N, 2N)$ and must be a multiple of $N$: either $0$
or $N$. The first gives $|L_k| = q$ and $\ell_{k+1} = \ell_k - t$, which
requires $\ell_k \ge t$; the second gives $|L_k| = q+1$ and
$\ell_{k+1} = \ell_k - t + N$, which requires $\ell_k < t$. $\square$

**Lemma 3.3.** Within a lane, $\ell$ takes the values
$\ell_k, \ell_k + N, \dots, \ell_k + (|L_k|-1)N$. Since $t < N$, at most the
first of these is $< t$; and it is $< t$ exactly when $\ell_k < t$.

*Proof.* Consecutive $x \in L_k$ differ by $1$, and $\ell(x+1) - \ell(x) = N$
provided both lie in $L_k$ (no wrap, since $h$ is constant on the lane). The
rest is immediate from $t < N$. $\square$

**Theorem 3.4 (exact uniformity).** Conditioned on acceptance, the returned
value is exactly uniform on $\{0,\dots,N-1\}$:
$\Pr[\textit{result} = k] = 1/N$ for every $k$.

*Proof.* By Lemmas 3.2 and 3.3, the rejection rule $\ell < t$ discards exactly
one element from each lane with $|L_k| = q+1$ and none from any lane with
$|L_k| = q$. Every lane therefore retains exactly $q$ elements. The accepted
set has $qN = M - t$ elements, uniformly distributed since $x$ was uniform,
so $\Pr[\textit{result}=k \mid \text{accept}] = q/(qN) = 1/N$. $\square$

**Proposition 3.5 (cost).**
$\Pr[\text{reject}] = t/M = (2^{64} \bmod N)/2^{64} < N/2^{64}$, and the
expected number of engine draws per output is $M/(M-t) \le (1 - N/2^{64})^{-1}$.

For every bound a gaming application will ever use, this is unmeasurable, as
verified numerically:

| $N$ | $2^{64} \bmod N$ | $\Pr[\text{reject}]$ | bound $N/2^{64}$ |
|---|---|---|---|
| 6 (die) | 4 | $2.17\times10^{-19}$ | $3.25\times10^{-19}$ |
| 37 (roulette) | 12 | $6.51\times10^{-19}$ | $2.01\times10^{-18}$ |
| 52 (card deck) | 16 | $8.67\times10^{-19}$ | $2.82\times10^{-18}$ |
| $10^6$ | 551616 | $2.99\times10^{-14}$ | $5.42\times10^{-14}$ |

**Proposition 3.6 (the division is nearly always skipped).** The
implementation computes $t$, the only division, solely when $\ell(x) < N$.
This is sound because $t < N$ implies $\{\ell < t\} \subseteq \{\ell < N\}$,
so the fast path can never skip a required rejection. Moreover
$\Pr[\ell(x) < N] = N/2^{64}$ exactly.

*Proof of the probability.* Write $N = 2^{\alpha}N'$ with $N'$ odd. The map
$x \mapsto xN \bmod 2^{64}$ has image the multiples of $2^{\alpha}$, each
attained by exactly $2^{\alpha}$ values of $x$. The number of multiples of
$2^{\alpha}$ below $N$ is $N/2^{\alpha}$, so
$\Pr[\ell < N] = 2^{\alpha}(N/2^{\alpha})/2^{64} = N/2^{64}$. $\square$

This is Lemire's "nearly divisionless" method (ACM TOMACS 2019); the same
algorithm ships in libstdc++, the MSVC STL, Go, Swift, Julia and the Linux
kernel, which is a meaningful independent-review argument in a licensing
context.

**Corroborating measurement.** The test suite does not merely assert the
theorem, it exhibits the bias that the theorem removes: for `byte % 6` the
chi-square statistic is $\approx 252$ on $5$ degrees of freedom, versus
$\approx 5$ for the rejection method, i.e. the naive method is rejected at
overwhelming significance while the correct one sits at its expected value.

The 32-bit path (`random.hpp:86`) is the same argument with $M = 2^{32}$,
drawing its input from the *top* 32 bits of a 64-bit word, for low-bit hygiene,
since the low bits of LCG-family generators are the weakest.

### 3.3 Provably Fair outcome mapping

Two mappings are exposed deliberately, and the difference is exactly a
bias-versus-interoperability trade.

**(a) Industry-compatible mapping.** Four stream bytes give
$f = \sum_{i=0}^{3} b_i\,256^{-(i+1)} = X/2^{32}$ with $X$ uniform on
$[0,2^{32})$; the outcome is $\lfloor f\cdot N \rfloor$.

**Proposition 3.7 (bias bound).** With $q' = \lfloor 2^{32}/N \rfloor$ and
$t' = 2^{32} \bmod N$, exactly $t'$ of the $N$ outcomes have probability
$(q'+1)/2^{32}$ and the remaining $N - t'$ have probability $q'/2^{32}$. The
relative deviation from uniformity is bounded by
$$\left| \frac{\Pr[\textit{result} = k]}{1/N} - 1 \right| \;\le\; \frac{N}{2^{32}} .$$

*Proof.* Lemma 3.2 with $M = 2^{32}$ gives the lane sizes. Then
$N\Pr[k] = N|L_k|/2^{32} \le N(2^{32}/N + 1)/2^{32} = 1 + N/2^{32}$, and
similarly $N\Pr[k] \ge N(2^{32}/N - 1)/2^{32} = 1 - N/2^{32}$. $\square$

For $N = 52$ this is a relative deviation below $1.3\times10^{-8}$; for
$N = 10^4$, below $2.4\times10^{-6}$. Non-zero, bounded, and disclosed,
which is the honest position, since this mapping is retained specifically so
that results remain checkable by the third-party verifiers already deployed
in the industry.

**Proposition 3.8 (floating-point exactness caveat).**
$\lfloor f\cdot N \rfloor$ is computed in IEEE-754 double precision.
$f = X/2^{32}$ is exact. The product $f\cdot N$ is exact iff $XN < 2^{53}$ for
all $X < 2^{32}$, i.e. iff $N \le 2^{21} = 2\,097\,152$. For $N > 2^{21}$
rounding may move a boundary case by one unit in the last place, adding a
further deviation of order $2^{-53}$ relative, negligible beside Proposition
3.7's $N/2^{32}$, but recorded for completeness.

**(b) Unbiased mapping.** `NextIntsUnbiased` (`provably_fair.hpp:151`) runs
the Lemire rejection of §3.2 over the HMAC byte stream, consuming 8 bytes per
attempt. **Theorem 3.4 applies verbatim**, so this mapping is exactly
unbiased for every $N$. Cost: it is not byte-compatible with other operators'
verifiers, which is why both are shipped and the console verifier takes
`--unbiased`.

**Recommendation for licensees.** Use (b) where the regulator or the
marketing claim says "no bias"; use (a) where ecosystem compatibility with
existing Stake-style verifiers dominates. The choice is a business decision
with a quantified cost (Proposition 3.7), which is the form in which it
should be presented to a gaming authority.

---

## 4. Period analysis

### 4.1 xoshiro256++: period $2^{256}-1$

**Cited result** (Blackman & Vigna 2021). The state update $T$ is
$\mathbb{F}_2$-linear on $\mathbb{F}_2^{256}$. Its characteristic polynomial
is primitive over $\mathbb{F}_2$, which is equivalent to $T$ having order
$2^{256}-1$ in $\mathrm{GL}_{256}(\mathbb{F}_2)$. Consequently the nonzero
state space $\mathbb{F}_2^{256}\setminus\{0\}$, of cardinality exactly
$2^{256}-1$, forms a **single orbit** under $T$, and the state sequence from
any nonzero seed has period exactly $2^{256}-1$.

Two consequences worth stating explicitly, because they are what a reviewer
will probe:

1. **The all-zero state is the unique fixed point** ($T\cdot 0 = 0$) and is
   the only state not on the long orbit. It must therefore be unreachable at
   seeding; see Proposition 4.2.
2. **The "++" scrambler does not change the period.** It is applied to a copy
   of the state with no feedback, so the state orbit, and hence the period
   of the output sequence, is unaffected. (The output sequence has period
   *dividing* that of the state; since $2^{256}-1$ is the state period and
   the scrambler is a fixed function, the output period is $2^{256}-1$ unless
   the scrambler happened to be constant on the orbit, which it is not.)

**Proposition 4.2 (the forbidden state is unreachable from `Seed`).**
`Xoshiro256pp::Seed` fills the four state words with four consecutive
SplitMix64 outputs. The all-zero state cannot result.

*Proof.* SplitMix64 advances an internal counter by a fixed odd constant
$\gamma$ and outputs $\mu(\text{counter})$ where $\mu$ is a bijection on
$\{0,1\}^{64}$. Four consecutive calls use four *distinct* counter values, so
by injectivity of $\mu$ they produce four values of which at most one can be
$0$. Hence $(s_0,s_1,s_2,s_3) \ne (0,0,0,0)$. $\square$

(`SeedState` accepts a raw 256-bit state and defends separately by rewriting
an all-zero input to $s_0 = 1$, `xoshiro256pp.hpp:41`.)

**Jump functions.** `Jump()` and `LongJump()` advance the state by $2^{128}$
and $2^{192}$ steps via precomputed polynomials. Because the orbit is a
single cycle of known length, streams obtained by repeated jumping are
**provably non-overlapping** for up to $2^{128}$ threads each consuming fewer
than $2^{128}$ values. This is the fast tier's multithreading argument, and
unlike "seed each thread differently" it carries a guarantee rather than a
birthday-bound hope.

### 4.2 PCG64: period $2^{128}$ per stream

**Theorem 4.3 (Hull–Dobell, instantiated).** The LCG
$x_{n+1} = ax_n + c \bmod 2^{128}$ has full period $2^{128}$ for **every** odd
$c$, with $a = \texttt{0x2360ed051fc65da44385df649fccf645}$.

*Proof.* Hull–Dobell: an LCG modulo $m$ attains full period $m$ iff
(i) $\gcd(c,m) = 1$; (ii) $a - 1$ is divisible by every prime factor of $m$;
(iii) if $4 \mid m$ then $4 \mid a-1$. Here $m = 2^{128}$, whose only prime
factor is $2$.

(i) `SeedState` sets $c$ via `shl1_or1`, i.e. $c = 2\cdot\textit{initseq} + 1$,
which is odd; hence $\gcd(c, 2^{128}) = 1$.
(ii) and (iii): the low hex digits of $a$ are $\texttt{...645}$, and
$\texttt{0x645} = 1605 \equiv 1 \pmod 4$; verified computationally,
$a \bmod 4 = 1$. So $4 \mid a-1$, which also gives $2 \mid a-1$. $\square$

Since $c$ ranges over the $2^{127}$ odd residues mod $2^{128}$, the generator
offers $2^{127}$ distinct streams, each of full period $2^{128}$.

**Caveat on the output sequence.** The XSL-RR output function maps 128 bits to
64 and is therefore *not* injective: individual 64-bit outputs necessarily
repeat (by pigeonhole, on average $2^{64}$ times each over a full period).
The claim "period $2^{128}$" is a statement about the *state* sequence, which
is what determines when the output sequence as a whole repeats. Stating it
loosely as "no output repeats for $2^{128}$ draws" would be false, and a
reviewer will catch it.

### 4.3 The DRBGs: why "period" is the wrong question

A DRBG is not a cycle; it is a keyed function iterated under a
standard-mandated reseed discipline. The relevant quantities are the enforced
limits, not an orbit length.

For HMAC-DRBG as configured (`hmac_drbg.hpp:36-39`):

| Quantity | Value | Enforced at |
|---|---|---|
| Bits per Generate request | $\le 2^{19}$ | `hmac_drbg.hpp:74` (throws) |
| Requests per seed | $\le 2^{48}$ | `hmac_drbg.hpp:76` (throws) |
| Upper bound on bits per seed | $2^{48}\cdot 2^{19} = 2^{67}$ | n/a |
| Bits per seed *as the engine uses it* | $2^{48}\cdot 2^{15} = 2^{63}$ | 4 KiB buffer, `drbg_engine.hpp:47` |

$2^{63}$ bits is $\approx 10^{18}$ bits, or about $1.15\times10^{6}$ TB of
output before a reseed becomes mandatory, unreachable in the lifetime of any
deployment. When it *is* reached the implementation throws rather than
silently continuing (`hmac_drbg.hpp:77`), which is the conservative choice:
the caller must decide where fresh entropy comes from, because the library
cannot know the deployment's entropy policy.

Within those limits the security claim is **not** "the output does not
repeat" but "the output is computationally indistinguishable from uniform",
which is §7.2's subject, and rests on assumptions rather than on counting.

---

## 5. Entropy and collision analysis

### 5.1 Seed-space collisions (the birthday bound)

If $n$ seeds are drawn independently and uniformly from a space of size
$2^{k}$, then
$$\Pr[\text{some collision}] \;\approx\; 1 - \exp\!\left(-\frac{n^{2}}{2^{k+1}}\right),$$
which is $\approx n^2/2^{k+1}$ for small argument.

**This matters because a seed collision is not a statistical curiosity, it is
two players receiving identical outcome sequences.** In a Provably Fair
context it is also publicly detectable after reveal, i.e. it is a
reputational event, not just a technical one.

Computed for the two seed widths the SDK uses:

| Seed space | $n$ for $\Pr \approx 10^{-9}$ | $n$ for $\Pr \approx 10^{-6}$ | $\Pr$ at $n = 10^{9}$ |
|---|---|---|---|
| 64-bit (`Seed(uint64)`) | $1.9\times10^{5}$ | $6.1\times10^{6}$ | $2.7\times10^{-2}$ |
| 256-bit (`GenerateServerSeed`) | $1.5\times10^{34}$ | $4.8\times10^{35}$ | $\approx 0$ |

**Correction to an earlier internal note.** `OPEN_RESEARCH.md` §5 records
"$2^{-64}$ collision at $2^{32}$ seeds". That is incorrect: $n = 2^{32}$ in a
$64$-bit space is precisely the birthday point, giving
$\Pr \approx 1 - e^{-1/2} \approx 39.3\%$. The figure $2^{-64}$ is the
probability that one *specified pair* collides, not that *any* pair does. The
table above supersedes it.

**Consequences, stated as requirements:**

1. The 64-bit `Seed(uint64_t)` entry point is a **reproducibility facility,
   not a security facility.** At $6\times10^{6}$ independently chosen seeds
   the collision probability already reaches $10^{-6}$. It is correct for
   tests, simulations, and the `rng_stream --seed` battery protocol, all of
   which *want* reproducibility.
2. Provably Fair server seeds must not come from it. `GenerateServerSeed()`
   accordingly draws 256 bits directly from the OS CSPRNG
   (`provably_fair.hpp:68`), bypassing the 64-bit path entirely.
3. **The commitment makes seed entropy load-bearing in a second way.**
   Publishing $\mathrm{SHA\text{-}256}(\textit{server\_seed})$ hands an
   adversary a free offline oracle: guess a seed, hash, compare. Against a
   64-bit seed that is a $2^{64}$ search, feasible for a motivated
   adversary, and it would break the scheme *before* reveal, which is exactly
   when it must hold. Against 256 bits it is infeasible. This is the
   strongest single argument for the 256-bit choice, and it is a property of
   the *protocol*, not of the generator.

### 5.2 Output entropy: what can and cannot be claimed

A subtlety worth stating precisely, because it is frequently overclaimed in
this industry:

**A DRBG's output does not have full Shannon entropy.** Its state is finite
($512$ bits for HMAC-DRBG, $384$ for CTR-DRBG no-df), so an output of length
$L \gg 512$ bits carries at most $\approx 512$ bits of true entropy
regardless of $L$, since the output is a deterministic function of the state, and
$H(f(X)) \le H(X)$.

What *is* claimed is **computational** indistinguishability: no efficient
adversary can distinguish the output from uniform with non-negligible
advantage (§7.2). For every operational purpose in gaming this is the
stronger and more relevant property, since a shuffle needs to be unpredictable to
an adversary with bounded resources, not information-theoretically random.

This is also the reason `os_entropy.hpp` performs **no conditioning** of OS
output: since $H(f(X)) \le H(X)$, hashing full-entropy OS bytes cannot add
entropy and would only add a construction requiring its own justification.

---

## 6. Seed sensitivity (avalanche)

**Spec requirement.** One flipped seed bit should flip approximately half the
output bits.

**Theoretical position (cryptographic tier).** This is not an empirical
accident but a consequence of the PRF assumption. Two distinct seeds yield
two distinct instantiations; under the assumption that HMAC-SHA256 is a PRF
(§7.2), the two output streams are computationally indistinguishable from two
*independent* uniform streams. For independent uniform streams each compared
bit differs with probability exactly $1/2$, so the expected Hamming-distance
fraction is exactly $0.5$. Any measurable deviation would itself constitute a
distinguisher, i.e. a break of the assumption.

**Theoretical position (fast tier).** No such argument is available. Here
avalanche is a property of SplitMix64's mixing function composed with the
state update, and is an *empirical* claim only. This asymmetry is stated
rather than smoothed over: it is a real difference in the strength of the
two tiers' guarantees, of exactly the kind this document exists to make
visible.

**Measurement** (`TestAvalanche`, `tests/test_main.cpp:232`). For each of 64
base seeds and 10 bit positions (0, 7, 14, …, 63), two engines are
constructed from seeds differing in that one bit, and 16 successive 64-bit
outputs are compared: $640$ samples $\times\ 1024$ bits $= 655\,360$ bits
compared per engine.

Under the null hypothesis of independent streams the mean flipped fraction
has standard deviation $\sqrt{0.25/655360} = 6.2\times10^{-4}$. Measured:
$\approx 50.0\%$ for all four engines; the test's acceptance band
$(0.47, 0.53)$ is $\approx 49\sigma$ wide.

**Honest reading of that bound.** A $49\sigma$ band is deliberately loose. It
is a *gross-failure detector*: it catches a seeding path that ignores its
argument, or a state that fails to diffuse, rather than a sensitive statistical
test. The sensitive tests are the external batteries (item #3). Presenting
this measurement as strong evidence of statistical quality would be
overclaiming; it is strong evidence only against catastrophic seeding bugs.

---

## 7. Cryptographic security

### 7.1 Fast tier: explicitly not secure

`Xoshiro256pp` and `Pcg64` provide **no** cryptographic security, and the SDK
should say so louder than a licensee expects.

The reason is structural, not incidental. xoshiro's state update is
$\mathbb{F}_2$-linear (§2.1): the entire state sequence satisfies a known
linear recurrence over $\mathbb{F}_2$, so any adversary who recovers the
256-bit state can compute all past and future outputs in closed form, and
recovering that state from output reduces to solving a linear system once the
scrambler is inverted or bypassed. PCG64's LCG is likewise algebraically
transparent, and lattice-based state recovery against truncated LCG output is
classical.

**These generators must never be used for:** Provably Fair outcomes, server
seeds, shuffles whose predictability has monetary value, or anything a player
could profit from predicting.

**They are appropriate for:** Monte Carlo simulation, non-fairness game logic
(visual effects, AI behaviour, procedural content), load generation, and
reproducible test fixtures, cases where the adversary model is empty and
throughput matters.

The SDK enforces the separation by *type*: `Random<Xoshiro256pp>` and
`rngsdk::CryptoRandom` are different types, and the Provably Fair layer
(`pf::`) does not accept an engine parameter at all, since it is hard-wired to
HMAC-SHA256. A configuration error therefore cannot silently downgrade
fairness-critical generation to the fast tier.

**Resolved 2026-08-20: the "4 outputs" figure belonged to a different
variant.** `xoshiro256pp.hpp` previously stated the state is "recoverable from
4 consecutive outputs". Tracing the claim:

* For **xoshiro256\*\***, output $= \mathrm{rotl}(s_1\cdot 5,\,7)\cdot 9$. Odd
  multipliers are invertible mod $2^{64}$ and rotation is a bijection, so the
  output function is a **bijection of $s_1$**: *one* output yields $s_1$
  outright, and four consecutive outputs give $s_1$ at four times, from which
  the $\mathbb{F}_2$-linear update determines the state. "4 outputs" is exact
  here.
* For **xoshiro256++**, which is what this SDK ships, output
  $= \mathrm{rotl}(s_0+s_3,\,23) + s_0$, one 64-bit equation in two 64-bit
  unknowns, hence **not invertible from a single output**. Four outputs carry
  $256$ bits against a $256$-bit state, so the state is
  *information-theoretically* determined; but recovering it means solving a
  system mixing addition mod $2^{64}$ with the $\mathbb{F}_2$-linear update,
  not the plain linear solve the bare figure suggests.

This project has **not** verified a concrete attack cost for the ++ variant
and claims none. The comment has been corrected to say exactly that. The
*conclusion*, zero cryptographic security and never for Provably Fair, is
unchanged, is structural (§7.1 above), and is the authors' own stated
position.

### 7.2 Cryptographic tier: the reduction, and its published caveats

**Assumption A1.** HMAC-SHA256 is a pseudorandom function.
**Assumption A2.** AES-256 is a pseudorandom permutation.

Both are standard, long-scrutinised, and unproven, as is every assumption
underlying deployed cryptography. They are stated explicitly so a reviewer
can see exactly what the security claim rests on.

**Cited result 7.1 (HMAC-DRBG, Woodage & Shumow, EUROCRYPT 2019).** HASH-DRBG
and HMAC-DRBG are proved *robust* (in the sense of Dodis et al., CCS 2013) in
the random oracle model, **with a caveat**. The authors show that *if the
optional additional input is omitted*, HMAC-DRBG does **not** achieve even the
weaker property of forward security, contrary to the claim made in SP 800-90A
itself.

**The mechanism, and why it applies to us.** The attack (their §7.1) is
concrete and can be checked against our source directly. When
$\textit{addin} = \varepsilon$ the final two lines of **Update** are not
executed; in our code, the early `return` at `hmac_drbg.hpp:118` skips the
`0x01` pass. Tracing **Generate** with empty additional input, if $r^*$
denotes the *last output block returned to the caller*, the post-Generate
state $(K^*, V^*)$ satisfies

$$K^* = \mathrm{HMAC}(K,\ r^* \Vert \texttt{0x00}), \qquad \boxed{V^* = \mathrm{HMAC}(K^*,\ r^*)}$$

The boxed relation is *checkable by anyone holding both the output and the
state*. An adversary who requests output and then compromises the state simply
tests it: if it holds the output was real, if not it was random. Woodage &
Shumow's Theorem 3 bounds the resulting advantage below by
$1 - 2\,\mathrm{Adv}^{\mathrm{prf}}_{\mathrm{HMAC}} - 2^{-(\ell-1)}$, i.e.
essentially $1$, using **one** output query and **one** state query.

We verified by inspection that our `Update` (`hmac_drbg.hpp:107`) and
`Generate` (`hmac_drbg.hpp:72`) reproduce this relation exactly, and that
`BufferedDrbgEngine::Refill()` (`drbg_engine.hpp:89`, shared by both engines) calls
`Generate(buf_, kBufBytes)` with `additional` defaulted empty. **The caveat
therefore applies to the SDK as shipped.**

**What it is and is not.** It is a *distinguisher*: post-compromise, an
adversary can confirm that output they already hold came from this DRBG. It
is **not** recovery of past output they never saw. The formal property
nonetheless fails, so the standard's backtracking-resistance claim cannot be
repeated for this call pattern, and the header comment at `hmac_drbg.hpp` has
been corrected accordingly.

**Scope: three separate reasons the commercial impact is contained.**

1. **The Provably Fair path does not use the DRBG at all.** `pf::ByteStream`
   computes HMAC-SHA256 directly (§7.3). The fairness guarantee, the
   licensable core of this product, is entirely untouched by this result.
2. **The adversary must already hold the DRBG state.** An adversary with the
   state can predict all *future* output, which is strictly worse than
   distinguishing past output; forward security is the lesser concern once
   that has happened.
3. **Prediction resistance is a different property** and is not implicated.

**The fix is proved, not guessed.** Woodage & Shumow's §7.2 establishes
robustness, and hence forward security, for HMAC-DRBG *when additional input is
supplied on every* `next` *call*. `HmacDrbg::Generate` already accepts an
`additional` argument; only the adapter declines to pass one, so the change is
local.

> **DECIDED 2026-09-07: accepted, not applied** (OPEN_RESEARCH #12 option (a);
> full rationale in `SECURITY_ANALYSIS.md` §4.2, finding SA-04).
> Supplying additional input changes the generated byte stream. That would
> invalidate the `hmac` row of `docs/statistical_results/fingerprints.txt`,
> the HMAC-engine golden vectors, and any battery run already in flight
> against the current stream. It is a deliberate, versioned break, not a
> drop-in patch. The CAVP vectors are unaffected (they drive `HmacDrbg`
> directly with specified `addin`, bypassing the adapter).
>
> The project accepted the gap rather than taking that break: the attack is
> conditional on the adversary already holding the DRBG's live state out of
> server process memory, from which all future output is predictable in any
> case, and the Provably Fair path never touches the DRBG state machine. The
> consequence for *this* document is narrow but binding: **the crypto tier must
> not be described as backtracking-resistant**, here or in the final report.

**Cited result 7.2 (CTR-DRBG, Hoang & Shen, CRYPTO 2020).** The first
security analysis of NIST CTR-DRBG; it establishes robustness in the sense of
Dodis et al. for the design *after* the countermeasures suggested by prior
work are applied. Confirming precisely which countermeasures our
implementation does and does not include is **open** and belongs to item #6.

**Cited result 7.3 (CTR-DRBG side channels, Cohney et al., IEEE S&P 2020).**
Two distinct findings, which must not be merged:

1. *Design level*: CTR_DRBG does not have forward security if an adversary
   can compromise the state via a side channel.
2. *Implementation level*: widely deployed implementations (OpenSSL's FIPS
   module, NetBSD's kernel) used T-table AES, enabling cache attacks, and
   made parameter choices (notably insufficient reseed entropy) that made
   full exploitation practical.

On (2), a first distinction matters: Cohney et al.'s T-table finding concerns
OpenSSL's **FIPS module**, whereas `ctr_drbg.hpp` uses the standard EVP
interface (`EVP_aes_256_ecb`). That is suggestive but not sufficient, so the
dispatch was **measured rather than assumed** (2026-08-20, AMD Athlon Gold
3150U @ 2.4 GHz):

| Probe | Result |
|---|---|
| OpenSSL version | 3.6.3 (vcpkg, x64-windows) |
| `CPUID.1:ECX[25]` (AES-NI present) | **YES** |
| `EVP_aes_256_ecb` throughput, 256 MiB × 5 runs, idle | **4908–5707 MB/s** |

Two independent readings of that figure agree:

* **Versus software.** A T-table AES-256 runs at roughly 100–250 MB/s on this
  class of core. The measurement is $20$–$50\times$ faster, which no software
  path reaches.
* **Versus the hardware ceiling.** $\approx 5300$ MB/s at the 2.4 GHz base
  clock is $\approx 2.3$ bytes/cycle. AES-256 is 14 rounds, so one `AESENC`
  per cycle would cap at $16/14 \approx 1.14$ B/cycle; Zen has **two** AES
  pipes, giving $\approx 2.3$ B/cycle. The measured value sits precisely at
  the hardware ceiling for this microarchitecture, a coincidence a software
  implementation cannot produce.

**EVP is dispatching to AES-NI, which is constant-time**, so the specific
cache-attack vector of finding (2) does not apply on this hardware.

*Methodology note.* A first measurement returned 1662 MB/s and was discarded:
it was taken while two full CMake builds were competing for the same two
cores. It is retained here only as a caution: a throughput probe used as a
security signal must be run on an idle machine, or it silently understates by
$3\times$ and could, on a faster software path, invert the verdict.

Two limits on that conclusion, stated so it is not over-read: it is a property
of *this CPU and this OpenSSL build*, so it must be re-established for any
target lacking AES-NI (where OpenSSL would fall back to a table-based path and
the finding *would* apply); and it does nothing about finding (1), which is a
design-level property of CTR_DRBG independent of the AES implementation.

**What is established, net of all caveats.** Under A1/A2, and within the
enforced request/reseed limits of §4.3, an adversary without the state cannot
distinguish the cryptographic tier's output from uniform, nor predict future
output, with any non-negligible advantage. The caveats above concern
*post-compromise* properties (what an adversary learns *after* obtaining the
state), not the pre-compromise unpredictability on which the Provably Fair
guarantee rests.

### 7.3 Where the Provably Fair guarantee actually comes from

Worth separating, because it does not depend on the DRBG at all.

The fairness guarantee is a *protocol* property:

$$\textit{result} = \mathrm{HMAC\text{-}SHA256}\big(\textit{server\_seed},\ \textit{client\_seed} : \textit{nonce} : \textit{cursor}\big)$$

* The **commitment** $\mathrm{SHA\text{-}256}(\textit{server\_seed})$,
  published before play, binds the server to its seed. Changing the seed
  afterwards requires a second preimage of SHA-256.
* The **client seed** is chosen by the player, so the server cannot steer the
  outcome by choosing its own seed alone, since it would have to grind against a
  seed it is already committed to.
* The **nonce** is strictly monotonic per (server, client) pair
  (`ServerSession`), so no outcome is ever replayed.
* After reveal, the player recomputes every result independently.

The security of this rests on SHA-256's collision/second-preimage resistance
and HMAC's PRF property, meaning assumptions A1 and standard hash assumptions, and
on the seed entropy argument of §5.1(3). Notably it does **not** rest on the
DRBG engines: `pf::ByteStream` computes HMAC directly.

---

## 8. Summary

| | xoshiro256++ | PCG64 | HMAC-DRBG | CTR-DRBG (AES-256) |
|---|---|---|---|---|
| State | 256 bits | 128 bits (+stream) | 512 bits | 384 bits |
| Period | $2^{256}-1$ (proved, §4.1) | $2^{128}$/stream, $2^{127}$ streams (proved, §4.2) | n/a, reseed-limited, §4.3 | n/a, reseed-limited |
| Output limit per seed | full period | full period | $2^{63}$ bits as configured | $2^{63}$ bits as configured |
| Cryptographic security | **none** (§7.1) | **none** (§7.1) | reduces to A1 (§7.2) | reduces to A2 (§7.2) |
| Post-compromise caveats | n/a | n/a | fwd. security caveat, §7.2 | design + impl. caveats, §7.2 |
| Throughput (MSVC Release, 1 core) | $6.77\times10^{8}$ u64/s | $3.95\times10^{8}$ u64/s | $2.31\times10^{6}$ u64/s | $3.13\times10^{7}$ u64/s |
| Intended use | simulation, game logic | simulation, game logic | Provably Fair, secrets | Provably Fair, secrets |

Throughput figures are from `DESIGN_NOTES.md` §8b (MSVC 19.37 Release, single
core, OpenSSL 3.6.3 via vcpkg); the HMAC-DRBG figure is the **bundled**-backend
row, which is the faster of the two backends at this call pattern. CTR-DRBG is
therefore $\approx 13\times$ HMAC-DRBG, quoted to two significant figures because
two median-of-$N$ sessions on one box gave $12.9\times$ and $13.6\times$ from an
identical CTR numerator. It is not the $27.8\times$ obtained by comparing
against the OpenSSL HMAC row, since that comparison is a measurement artifact of
OpenSSL 3.x's per-call provider fetch (OPEN_RESEARCH #11) and is not cited.

That artifact was removed on 2026-09-13 by caching a per-thread `EVP_MAC_CTX`,
so on a post-fix x86_64 build the OpenSSL HMAC row is the *faster* backend and
the like-for-like CTR ratio is $pprox 6.8	imes$, below the cross-backend
$13	imes$ rather than above it. The paragraph above describes the pre-fix
measurement it cites; $27.8	imes$ remains uncitable and is now also
unreachable. Engine output is bit-identical across the change.

Mapping-layer guarantees, independent of engine:

| Mapping | Guarantee | Reference |
|---|---|---|
| `NextDouble` / `NextFloat` | exactly uniform on the $2^{-53}$ / $2^{-24}$ grid | Prop. 3.1 |
| `NextUInt64(bound)` / `NextUInt32(bound)` | **exactly** uniform, zero bias | Thm. 3.4 |
| PF industry mapping | relative bias $\le N/2^{32}$ | Prop. 3.7 |
| PF unbiased mapping | **exactly** uniform, zero bias | Thm. 3.4 |

### Open items arising from this document

| # | Item | Status |
|---|---|---|
| 1 | Correct the backtracking-resistance comment at `hmac_drbg.hpp` (§7.2) | **DONE** 2026-08-20, replaced with the exact Woodage–Shumow relation and its scope |
| 2 | Substantiate or soften the "4 consecutive outputs" claim at `xoshiro256pp.hpp` (§7.1) | **DONE** 2026-08-20, figure belongs to xoshiro256\*\*; comment corrected, no attack cost claimed for ++ |
| 3 | Verify the deployed OpenSSL build takes an AES-NI path rather than assuming it (§7.2) | **DONE** 2026-08-20, measured ~5300 MB/s, AES-NI confirmed on this target |
| 4 | Decide whether to supply additional input in `HmacDrbgEngine::Refill()` (§7.2) | **DECIDED** 2026-09-07, **accepted, not applied** (OPEN_RESEARCH #12 option (a); `SECURITY_ANALYSIS.md` §4.2, SA-04). Conditional on server-memory compromise; PF path unaffected. Stream unchanged, so fingerprints, golden vectors and item #3's runs stay valid |
| 5 | Determine which of Hoang & Shen's assumed countermeasures our CTR-DRBG implements (§7.2) | **OPEN**, feeds item #6 |
| 6 | Propagate the corrected birthday figures to `OPEN_RESEARCH.md` §5 (§5.1) | **DONE** 2026-08-20 |

---

## References

1. D. Blackman and S. Vigna. *Scrambled Linear Pseudorandom Number
   Generators.* ACM Transactions on Mathematical Software 47(4), 2021.
   DOI 10.1145/3460772. Preprint arXiv:1805.01407.
2. D. Lemire. *Fast Random Integer Generation in an Interval.* ACM
   Transactions on Modeling and Computer Simulation 29(1), Article 3, 2019.
   DOI 10.1145/3230636. Preprint arXiv:1805.10941.
3. T. E. Hull and A. R. Dobell. *Random Number Generators.* SIAM Review 4(3),
   230–254, 1962. (Full-period conditions for linear congruential
   generators.)
4. M. E. O'Neill. *PCG: A Family of Simple Fast Space-Efficient Statistically
   Good Algorithms for Random Number Generation.* Harvey Mudd College
   Technical Report HMC-CS-2014-0905, 2014.
5. J. Woodage and D. Shumow. *An Analysis of NIST SP 800-90A.* Advances in
   Cryptology – EUROCRYPT 2019, LNCS 11477, pp. 151–180. IACR ePrint
   2018/349.
6. V. T. Hoang and Y. Shen. *Security Analysis of NIST CTR-DRBG.* Advances in
   Cryptology – CRYPTO 2020. IACR ePrint 2020/619.
7. S. Cohney, A. Kwong, S. Paz, D. Genkin, N. Heninger, E. Ronen, Y. Yarom.
   *Pseudorandom Black Swans: Cache Attacks on CTR_DRBG.* IEEE Symposium on
   Security and Privacy, 2020. IACR ePrint 2019/996.
8. Y. Dodis, D. Pointcheval, S. Ruhault, D. Vergnaud, D. Wichs. *Security
   Analysis of Pseudo-Random Number Generators with Input.* ACM CCS 2013.
   (The robustness notion used by references 5 and 6.)
9. E. Barker and J. Kelsey. *Recommendation for Random Number Generation
   Using Deterministic Random Bit Generators.* NIST SP 800-90A Rev. 1, 2015.
10. NIST. *Secure Hash Standard (SHS).* FIPS PUB 180-4, 2015.
11. M. Bellare. *New Proofs for NMAC and HMAC: Security without
    Collision-Resistance.* CRYPTO 2006. (HMAC's PRF security, assumption A1.)
