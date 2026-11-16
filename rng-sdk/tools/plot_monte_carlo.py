#!/usr/bin/env python3
"""Plots required by spec 10.1 (Monte Carlo pi) and 10.2 (Monte Carlo ODE).

Pure post-processing: reads the CSVs already produced by rng_pi and rng_ode
and runs no RNG itself, so the figures cannot disagree with the committed
numbers.

Each figure answers ONE question:

  pi_error.png        How does pi's error depend on the number of trials?
  pi_convergence.png  Is the convergence rate actually O(1/sqrt(N))?
  ode_solution.png    Does the MC solution reproduce sin x, and what does a
                      broken RNG do to it?
  ode_error.png       How does ODE error depend on N and on x, per engine?

Usage: python tools/plot_monte_carlo.py
"""
import csv
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DOCS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs")
OUT = os.path.join(DOCS, "plots")
os.makedirs(OUT, exist_ok=True)

SOUND_ENGINES = ["xoshiro256++", "pcg64", "hmac-drbg", "mt19937_64", "rand()-builtin"]
BROKEN_ENGINES = ["RANDU(bad)", "LCG5(bad)"]
ALL_ENGINES = SOUND_ENGINES + BROKEN_ENGINES
COLORS = {
    "xoshiro256++": "tab:blue",
    "pcg64": "tab:orange",
    "hmac-drbg": "tab:green",
    "mt19937_64": "tab:purple",
    "rand()-builtin": "tab:brown",
    "RANDU(bad)": "tab:red",
    "LCG5(bad)": "black",
}


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def style(engine):
    """Sound engines: solid + circles. Broken controls: dotted + squares."""
    if engine in BROKEN_ENGINES:
        return {"marker": "s", "linestyle": ":", "linewidth": 1.8, "markersize": 7}
    return {"marker": "o", "linestyle": "-", "linewidth": 1.2, "markersize": 6}


# ================================================================== pi ====
#
# The estimator is est = (2*d) * k/N with k ~ Binomial(N, p), where
#   2D: p = pi/4, prefactor 4;  3D: p = pi/6, prefactor 6.
# So sd(est) = prefactor * sqrt(p(1-p)/N), and the 95% half-width is
# 1.96 * that -- a known constant over sqrt(N), with no fitting involved.
# Verified against the rng_pi ci95 column: 3.219/sqrt(N) and 5.873/sqrt(N).
PI_DIMS = [
    ("2", "2D quarter disc", math.pi / 4.0, 4.0),
    ("3", "3D sphere octant", math.pi / 6.0, 6.0),
]


def pi_ci95_constant(p, prefactor):
    return 1.96 * prefactor * math.sqrt(p * (1.0 - p))


def plot_pi_error(rows):
    """|estimate - pi| vs N, log-log, against the theoretical 95% band.

    The band is the point: a single unaveraged run's error is a random
    draw, so it bounces rather than descending monotonically. Without the
    band a reader mistakes ordinary scatter for a defect.
    """
    fig, axes = plt.subplots(1, 2, figsize=(13, 6.2))
    handles = []
    for i, (ax, (dim, title, p, prefactor)) in enumerate(zip(axes, PI_DIMS)):
        sub = [r for r in rows if r["dim"] == dim]
        ns = sorted(set(int(r["n"]) for r in sub))
        for engine in ALL_ENGINES:
            pts = sorted(
                ((int(r["n"]), float(r["abs_err"])) for r in sub if r["engine"] == engine),
                key=lambda q: q[0],
            )
            if not pts:
                continue
            xs, ys = zip(*pts)
            ln, = ax.plot(xs, ys, label=engine, color=COLORS[engine], alpha=0.75, **style(engine))
            if i == 0:
                handles.append(ln)
        c = pi_ci95_constant(p, prefactor)
        ref, = ax.plot(
            ns, [c / math.sqrt(n) for n in ns],
            color="gray", linestyle="--", linewidth=2.2,
            label=f"95% CI half-width = {c:.2f}/sqrt(N)",
        )
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("N (trials)")
        ax.set_ylabel("|estimate - pi|")
        ax.set_title(title)
        ax.grid(True, which="both", alpha=0.25)
        ax.legend(handles=[ref], fontsize=8, loc="lower left", framealpha=0.9)
    fig.suptitle("Monte Carlo pi: error vs. trials (one unaveraged run per point -- scatter inside the band is expected)")
    fig.tight_layout(rect=(0.0, 0.09, 1.0, 0.96))
    fig.legend(handles=handles, labels=[h.get_label() for h in handles],
               loc="lower center", ncol=4, fontsize=9, frameon=False)
    fig.savefig(os.path.join(OUT, "pi_error.png"), dpi=150)
    plt.close(fig)


def plot_pi_convergence(rows):
    """err * sqrt(N) vs N -- the convergence rate itself.

    If error really falls as O(1/sqrt(N)), this product is scale-free and
    should sit flat under the 95% bound rather than trending. A rising
    trend is an error floor that sampling is not removing.
    """
    fig, axes = plt.subplots(1, 2, figsize=(13, 6.2))
    handles = []
    for i, (ax, (dim, title, p, prefactor)) in enumerate(zip(axes, PI_DIMS)):
        sub = [r for r in rows if r["dim"] == dim]
        for engine in ALL_ENGINES:
            pts = sorted(
                (
                    (int(r["n"]), float(r["abs_err"]) * math.sqrt(int(r["n"])))
                    for r in sub
                    if r["engine"] == engine
                ),
                key=lambda q: q[0],
            )
            if not pts:
                continue
            xs, ys = zip(*pts)
            # Connecting lines are drawn faint and markers solid, in separate
            # calls: with one unaveraged run per N these are four independent
            # points, and a bold polyline would read as a trend that is not
            # in the data. The markers are the measurement.
            st = style(engine)
            ax.plot(xs, ys, color=COLORS[engine], alpha=0.3, linewidth=1.0,
                    linestyle=st["linestyle"])
            ln, = ax.plot(xs, ys, label=engine, color=COLORS[engine], linestyle="none",
                          marker=st["marker"], markersize=st["markersize"])
            if i == 0:
                handles.append(ln)
        c = pi_ci95_constant(p, prefactor)
        ref = ax.axhline(c, color="gray", linestyle="--", linewidth=2.2,
                         label="95% bound (flat & below => O(1/sqrt(N)))")
        if i == 0:
            handles.append(ref)
        ax.set_xscale("log")
        # Log y, not linear. LCG5(bad) reaches 168 (2D) and 388 (3D) while the
        # sound engines live in 0.05-8, so a linear axis flattens all five of
        # them onto the baseline and the figure loses everything except "LCG5
        # is large". Log keeps both readable, and it is the honest scale for
        # this panel anyway: the quantity of interest is whether err*sqrt(N)
        # STAYS BOUNDED, so unbounded growth should appear as a straight rising
        # line (slope +1/2 per decade of N) rather than as a wall. No zeros in
        # the data (min 0.048), so nothing is lost off the bottom.
        ax.set_yscale("log")
        ax.set_xlabel("N (trials)")
        ax.set_ylabel("|estimate - pi| * sqrt(N)")
        # Bound value lives in the title, not a legend box, so no box can sit
        # on top of a data point (it hid hmac-drbg's N=1e5 peak when it did).
        ax.set_title(f"{title}   --   95% bound = {c:.2f}")
        ax.grid(True, which="both", alpha=0.25)
    fig.suptitle("Monte Carlo pi: convergence rate (scale-free -- no trend and under the bound means error ~ 1/sqrt(N))")
    fig.tight_layout(rect=(0.0, 0.09, 1.0, 0.96))
    fig.legend(handles=handles, labels=[h.get_label() for h in handles],
               loc="lower center", ncol=4, fontsize=9, frameon=False)
    fig.savefig(os.path.join(OUT, "pi_convergence.png"), dpi=150)
    plt.close(fig)


# ================================================================= ode ====

def plot_ode_solution(rows):
    """Numerical vs analytical, with error bars -- spec 10.2's first figure.

    Deliberately NOT all seven engines: six of them agree with sin x to
    ~1e-4 at N=1e7, so overlaying them all produces a figure carrying one
    bit of information. This shows the method converging (one engine at two
    sample sizes, with its own 95% CIs) and one broken control for contrast.
    Per-engine comparison is ode_error.png's job.

    The contrast that matters: at N=1e7 LCG5's error bars are ~1e-4 wide
    while it sits 0.14 away from the curve -- confidently wrong. That is
    bias, not noise, and it is what an error floor looks like.
    """
    grid = [r for r in rows if r["regime"] == "grid"]
    n_lo, n_hi = "10000", "10000000"

    xs_exact = sorted(set(float(r["x"]) for r in grid))
    dense = [xs_exact[0] + i * (xs_exact[-1] - xs_exact[0]) / 200.0 for i in range(201)]

    def series(engine, n):
        pts = sorted(
            (
                (float(r["x"]), float(r["estimate"]), float(r["ci95"]))
                for r in grid
                if r["engine"] == engine and r["n"] == n
            ),
            key=lambda q: q[0],
        )
        return zip(*pts) if pts else ((), (), ())

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.plot(dense, [math.sin(x) for x in dense], color="gray", linewidth=2.5,
            zorder=1, label="y = sin x  (exact)")

    x1, y1, e1 = series("xoshiro256++", n_lo)
    ax.errorbar(x1, y1, yerr=e1, fmt="o", markersize=8, capsize=5, zorder=3,
                color="tab:cyan", markerfacecolor="none", markeredgewidth=1.8,
                label="xoshiro256++, N=1e4  (95% CI)")

    x2, y2, e2 = series("xoshiro256++", n_hi)
    ax.errorbar(x2, y2, yerr=e2, fmt="o", markersize=8, capsize=5, zorder=4,
                color="tab:blue", label="xoshiro256++, N=1e7  (95% CI)")

    x3, y3, e3 = series("LCG5(bad)", n_hi)
    ax.errorbar(x3, y3, yerr=e3, fmt="s", markersize=8, capsize=5, zorder=5,
                color="black", label="LCG5(bad), N=1e7  (95% CI)")

    # No arrow: any leader line from here to the LCG5 points crosses the data.
    # The note names the series, and LCG5 is the only one leaving the curve.
    ax.text(
        0.44, 0.26,
        "LCG5(bad) at N=1e7 sits 0.14 above the curve\n"
        "with a CI of +/-0.0005 -- confidently wrong.\n"
        "That is bias: more samples shrink the bars,\n"
        "not the error. xoshiro's N=1e4 bars are visible\n"
        "at large x and gone by N=1e7.",
        transform=ax.transAxes, fontsize=9, ha="left", va="center",
        bbox=dict(boxstyle="round,pad=0.45", facecolor="white", edgecolor="0.6", alpha=0.95),
    )

    ax.set_xlabel("x")
    ax.set_ylabel("y(x)")
    ax.set_title("ODE y'' + y = 0: Monte Carlo solution vs. exact y = sin x")
    ax.grid(True, alpha=0.25)
    ax.legend(fontsize=9, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "ode_solution.png"), dpi=150)
    plt.close(fig)


def plot_ode_error(rows):
    """Spec 10.2's error graph, two panels.

    (a) RMSE vs N, against the theoretical prediction RMS(sigma)/sqrt(N).
        The reference line is theory, not a fitted anchor.
    (b) |z| = |estimate - sin x| / stderr per grid point at N=1e7. This is
        the coverage statistic made visual: sound engines should sit under
        1.96 about 95% of the time, whatever their variance. Normalising by
        each point's own stderr is what lets all seven engines share one
        axis despite variance growing with x.
    """
    grid = [r for r in rows if r["regime"] == "grid"]
    n_hi = "10000000"

    sigmas = [float(r["stddev"]) for r in grid if r["engine"] in SOUND_ENGINES]
    rms_sigma = math.sqrt(sum(s * s for s in sigmas) / len(sigmas))

    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(13, 6.2))
    handles = []

    # -- (a) RMSE vs N ------------------------------------------------
    by_key = {}
    for r in grid:
        by_key.setdefault((r["engine"], int(r["n"])), []).append(float(r["abs_err"]))
    ns = sorted(set(int(r["n"]) for r in grid))
    for engine in ALL_ENGINES:
        pts = []
        for n in ns:
            errs = by_key.get((engine, n))
            if errs:
                pts.append((n, math.sqrt(sum(e * e for e in errs) / len(errs))))
        if not pts:
            continue
        xs, ys = zip(*pts)
        ln, = ax_a.plot(xs, ys, label=engine, color=COLORS[engine], alpha=0.8, **style(engine))
        handles.append(ln)
    ref_a, = ax_a.plot(
        ns, [rms_sigma / math.sqrt(n) for n in ns],
        color="gray", linestyle="--", linewidth=2.2,
        label=f"theory: RMS(sigma)/sqrt(N), RMS(sigma)={rms_sigma:.3f}",
    )
    ax_a.set_xscale("log")
    ax_a.set_yscale("log")
    ax_a.set_xlabel("N (walks per grid point)")
    ax_a.set_ylabel("RMSE over the 8-point grid")
    ax_a.set_title("(a) RMSE vs. N")
    ax_a.grid(True, which="both", alpha=0.25)
    ax_a.legend(handles=[ref_a], fontsize=8, loc="lower left", framealpha=0.9)

    # -- (b) |z| per grid point at N=1e7 ------------------------------
    for engine in ALL_ENGINES:
        pts = sorted(
            (
                (float(r["x"]), abs(float(r["abs_err"])) / float(r["stderr"]))
                for r in grid
                if r["engine"] == engine and r["n"] == n_hi and float(r["stderr"]) > 0.0
            ),
            key=lambda q: q[0],
        )
        if not pts:
            continue
        xs, zs = zip(*pts)
        ax_b.plot(xs, zs, label=engine, color=COLORS[engine], alpha=0.8, **style(engine))
    ref_b = ax_b.axhline(1.96, color="gray", linestyle="--", linewidth=2.2,
                         label="1.96 (95% threshold)")
    ax_b.set_yscale("log")
    ax_b.set_xlabel("x")
    ax_b.set_ylabel("|estimate - sin x| / stderr")
    ax_b.set_title("(b) Deviation in units of its own standard error, N=1e7")
    ax_b.grid(True, which="both", alpha=0.25)
    ax_b.legend(handles=[ref_b], fontsize=8, loc="center left", framealpha=0.9)

    fig.suptitle("ODE y'' + y = 0: error vs. trials, and per-point deviation (influence of RNG quality)")
    fig.tight_layout(rect=(0.0, 0.09, 1.0, 0.95))
    fig.legend(handles=handles, labels=[h.get_label() for h in handles],
               loc="lower center", ncol=4, fontsize=9, frameon=False)
    fig.savefig(os.path.join(OUT, "ode_error.png"), dpi=150)
    plt.close(fig)


def main():
    pi_rows = read_csv(os.path.join(DOCS, "pi_results.csv"))
    ode_rows = read_csv(os.path.join(DOCS, "ode_results.csv"))
    plot_pi_error(pi_rows)
    plot_pi_convergence(pi_rows)
    plot_ode_solution(ode_rows)
    plot_ode_error(ode_rows)
    print(f"wrote 4 figures to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
