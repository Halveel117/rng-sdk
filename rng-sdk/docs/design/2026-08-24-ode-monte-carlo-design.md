# ODE Monte Carlo — design (OPEN_RESEARCH item #7)

Date: 2026-08-24. Status: approved, pre-implementation.

## 1. Purpose

Spec additional task #2: solve `y'' + y = 0`, `y(0)=0`, `y'(0)=1` by Monte
Carlo and compare against the exact solution `sin x`.

This is an **application** test, not a randomness test. The batteries (#3)
ask "do these bits look random?". This asks a different and complementary
question: *when the stream is consumed by a real numerical method, does the
answer come out right, and does the error obey the law theory predicts?*

Three reasons it earns its place in the report:

* It is the only deliverable that measures the RNG **through a consumer**.
  A defect that survives both CAVP conformance and a battery would have to
  show up here or nowhere.
* It supplies the spec's required demonstration (task #4) that a bad
  generator's hidden correlations cause **systematic** error — error that
  more sampling does not remove. See §7 for the honest caveat on this.
* It is the mathematically deepest item in the project and the most
  defensible piece of thesis-quality material in the final report.

`rng_pi` (existing) covers the same brief for integration in 2-D and 3-D.
This item covers it for an *integral equation*, which is a strictly harder
and more structured consumer of randomness.

## 2. Mathematical basis

### 2.1 Volterra form

Integrating the IVP twice and applying Dirichlet's formula
(`∫₀ˣ∫₀ˢ y(u) du ds = ∫₀ˣ (x−u) y(u) du`):

```
y(x) = x − ∫₀ˣ (x−t)·y(t) dt                                          (1)
```

Write `y = f + Ky` with `f(x) = x` and `(Kg)(x) = −∫₀ˣ (x−t) g(t) dt`.

### 2.2 Neumann series is the Taylor series

By induction, `Kⁿf(x) = (−1)ⁿ x^(2n+1)/(2n+1)!`:

* base: `K⁰f = x`;
* step: `∫₀ˣ (x−t) t^(2n+1) dt = x^(2n+3) / [(2n+2)(2n+3)]`, so
  `K^(n+1)f = (−1)^(n+1) x^(2n+3)/(2n+3)!`.

Hence `Σ Kⁿf = x − x³/3! + x⁵/5! − … = sin x`. The Neumann series and the
Taylor series are the same object reached from two directions. This identity
is the deterministic backbone of the test suite (§5, Layer 1) — it lets us
validate the estimator's *expectation* with no RNG involved at all.

### 2.3 Importance-sampled random-walk estimator

Naive sampling (`t ~ U(0,x)`) gives weight `−(x−t)·x/q`, which varies with
`t` and can exceed 1. Instead sample from

```
p(t | x) = 2(x−t)/x²        on (0, x)                                 (2)
```

(normalised: `∫₀ˣ 2(x−t)/x² dt = 1`). The `(x−t)` factor cancels exactly:

```
−(x−t)·g(t) / p(t|x) = −(x²/2)·g(t)
```

so the weight collapses to the **constant** `W(x) = −x²/2`, independent of
`t`. Sampling is closed-form by inverse CDF: `F(t) = (2xt − t²)/x²`, giving

```
t = x·(1 − √v),        v ~ U(0,1)                                     (3)
```

— one uniform and one square root per step. Because `t < x` always, the walk
moves monotonically toward the origin and the weights shrink as it goes.

### 2.4 Russian roulette and exact unbiasedness

With survival probability `q ∈ (0,1)`, define the score `S(x)`:

```
draw B ~ Bernoulli(q)
if B = 0:  return f(x)
if B = 1:  draw t ~ p(·|x);  return f(x) + (W(x)/q)·S(t)
```

Then

```
E[S(x)] = f(x) + q·(1/q)·E_t[W(x)·y(t)]
        = f(x) + ∫₀ˣ [2(x−t)/x²]·(−x²/2)·y(t) dt
        = f(x) − ∫₀ˣ (x−t) y(t) dt
        = f(x) + (Ky)(x)  =  y(x)                                     (4)
```

**The estimator is exactly unbiased — not approximately.** This is the single
most important design decision in the item, and it is why roulette was chosen
over truncating the series at fixed depth. Fixed-depth truncation would
introduce a bias of our own making; when a bad RNG then produced a wrong
answer we could not attribute the error. With (4), *every* observed deviation
from `sin x` is variance or RNG defect. Nothing else. That attribution is the
entire value of the exercise.

Note also there is **no discretisation error**: unlike Euler or Runge–Kutta
there is no step size `h` and no `O(hᵏ)` truncation term. Each `x` is
evaluated independently and exactly in expectation.

### 2.5 Variance is finite, and grows with x

The second moment satisfies its own Volterra equation:

```
M(x) = x² + 2x·(Ky)(x) + (x²/2q)·∫₀ˣ (x−t) M(t) dt                    (5)
```

Volterra equations with continuous kernels on a finite interval have
convergent Neumann series for *every* kernel magnitude (the iterated kernels
carry factorial decay), so `M(x) < ∞` for all `x` and all `q ∈ (0,1)`.
Finite, however, is not small: the `x²/2q` factor means variance climbs with
`x`. This is a real limitation of the method and will be reported rather
than hidden (§4, `x = π` column).

No numeric variance figure is asserted here. `σ̂` is **measured** at run time
from the sample and reported alongside every estimate.

## 3. Acceptance criteria

There is deliberately **no fixed error threshold**. A bound like "error <
10⁻³" would be arbitrary — it depends on `N`, on `x`, and on a variance we
have not yet measured. Since §2.4 establishes bias is exactly zero, the
correct criterion is *statistical consistency*:

1. **Layer-1 exactness (deterministic).** The estimator's expectation
   truncated at depth `n` equals the `n`-th Taylor partial sum of `sin`, to
   machine precision. No RNG involved. Proves the derivation and the code.
2. **Coverage.** Across the `x`-grid, `|est − sin x| < 1.96·σ̂/√N` for
   ≈95% of cells. A sound engine hits ~95%; a correlated one falls short,
   because its true variance exceeds what the i.i.d. formula predicts.
3. **Rate.** `|err|·√N` stays `O(1)` and roughly flat as `N` runs 10⁴ → 10⁷.
   For a defective engine it **grows** — the signature of an error floor
   that sampling cannot remove.
4. **RMSE and max error** over the grid, reported per engine per `N`
   (spec-mandated metrics).
5. Results committed as CSV under `docs/`, so the table is auditable rather
   than asserted.

Criterion 3 is the report's headline. A bad RNG does not fail by being
wildly wrong; it fails by having error that stops shrinking.

## 4. Experiment matrix

| Axis | Values |
|---|---|
| Engines | `xoshiro256++`, `pcg64`, `hmac-drbg`, `RANDU(bad)` |
| `N` | 10⁴, 10⁵, 10⁶, 10⁷ |
| `x` grid | 8 points on `(0, π/2]`, plus one extra at `x = π` |
| `q` | 0.5 default, CLI-tunable |

The `x = π` column is included specifically to demonstrate the §2.5 variance
growth. It is expected to be visibly worse and that is the point — an honest
limitation, documented.

`q` is exposed but not swept. There is a variance/cost trade-off (larger `q`
⇒ deeper walks ⇒ more work per sample but lower variance per sample) and a
weight-window heuristic (`q` matched to `|W(x)|`) is a plausible refinement.
Both are noted as future work rather than built. YAGNI.

## 5. Test strategy — two layers

The layers exist so that a failure is *attributable*:

**Layer 1 — deterministic, no RNG.** Verify `Kⁿf` against the closed form
`(−1)ⁿ x^(2n+1)/(2n+1)!`, and the depth-`n` partial sums against `sin x`'s
Taylor polynomial. Also verify the inverse-CDF sampler (3) reproduces the
density (2) by checking its CDF at fixed points analytically.

**Layer 2 — statistical.** With a known-good engine at a fixed seed, the
sample mean converges to `sin x` within a tolerance derived from the
*measured* `σ̂`, not from a hardcoded constant.

If Layer 1 passes and Layer 2 fails, the fault is the RNG, not the
derivation. That separation is why both exist.

Per the comment-audit convention (`docs/COMMENT_AUDIT.md`), every
claim-bearing comment in the new code names the test that holds it up.

## 6. Deliverables

| Artefact | Content |
|---|---|
| `tools/ode_monte_carlo.cpp` → `rng_ode` | engine-templated driver, CSV out, results table + "how to read this" footer, mirroring `rng_pi`'s structure |
| `tests/test_main.cpp` additions | Layer 1 + Layer 2 tests |
| `docs/ODE_MONTE_CARLO.md` | derivation, unbiasedness proof, results, discussion |
| `docs/ode_results.csv` | raw matrix |

`RanduBad` is reused from `tools/randu_bad.hpp` — it stays out of
`include/rngsdk/` for the reason given in that header.

## 7. Risk: RANDU may not fail this task

**This is the main open risk and it is recorded before measurement, not
after.** `rng_pi` already found that RANDU largely *passes* smooth
low-dimensional volume integrals; its planar defect only surfaced under the
targeted serial 3-D box test. The same could happen here: each walk step
consumes two uniforms (one roulette, one position) in a geometrically-varying
alignment, and the final estimate averages a smooth 1-D functional — a
forgiving consumer.

Mitigation, in order:

1. Report what is measured, whatever it is. "RANDU passes" is a legitimate
   and already-precedented finding, and reinforces `rng_pi`'s existing
   conclusion: *passing one Monte Carlo task is weak evidence.*
2. If RANDU passes, add a targeted diagnostic on the within-step uniform
   pair, which is where an LCG lattice would bite.
3. Only if both are inconclusive, add a second control constructed to fail
   (e.g. a low-modulus LCG), clearly labelled as constructed rather than
   historical.

What will **not** happen: quietly tuning the experiment until RANDU fails.
The demonstration is worth having only if the experiment was fixed first.

## 8. Constraint: no effect on the statistical batteries

Item #3's runs are in flight on the partner's machine. This item adds a new
tool and new tests; it must not alter any generated byte. Verification:
regenerate all six rows of `docs/statistical_results/fingerprints.txt` and
diff against the committed file before commit. Same discipline as the
comment audit.

## 9. Out of scope

* Boundary-value reformulation / walk-on-spheres. `y'' = −y` is Helmholtz,
  not Laplace; the zeroth-order term forces a path weight that grows rather
  than decays, so variance behaves far worse and the clean theory stops
  being clean. Defensible as an appendix, weak as the main result.
* Feynman–Kac. Same Helmholtz issue plus more machinery. The spec lists it
  as optional.
* Multithreading. Item #9 owns that; `Jump()` gives the fast tier
  non-overlapping per-thread streams when it lands.
