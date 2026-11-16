#!/usr/bin/env python3
"""Run rng_bench R times and report the per-row MEDIAN and spread.

Why this exists. A single rng_bench sample is not evidence: on the 2-core
development laptop this project used until 2026-09-11 the CTR-DRBG row alone
ranged 1.67e7-2.96e7 across one day, so a lone reading can put the CTR-vs-HMAC ratio anywhere from ~8x to
~15x even with nothing else running. The standing rule in DESIGN_NOTES 8b is
median of >=4 idle runs, and until 2026-08-27 that rule was stated in
docs/benchmark_results.txt while the tables in the same file were single
runs -- taken, moreover, by launching both backends back-to-back in one
shell, so the two binaries contended with each other. Those tables landed
outside the idle ranges printed higher up the same file.

This script exists so the committed tables are produced the way the file
says to produce them. It runs ONE binary at a time and never overlaps runs.

Usage:  python tools/bench_median.py <path-to-rng_bench.exe> [runs]

License: MIT.
"""
import re
import subprocess
import statistics
import sys

# "xoshiro256++ (ours)   6.342e+08   3.234e+08"  -- trailing "-" means the
# row has no doubles variant (mt19937_64), which must stay distinct from 0.
ROW = re.compile(r"^(.*?)\s{2,}([\d.]+e[+-]\d+|-)\s+([\d.]+e[+-]\d+|-)\s*$")
HEADER_KEYS = ("compiler:", "arch:", "build:", "crypto:", "iterations:")


def parse(text):
    """-> (ordered row names, {name: (u64, dbl)}, provenance lines)"""
    rows, order, prov = {}, [], []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(HEADER_KEYS):
            prov.append(s)
            continue
        if not s or s.startswith("generator"):
            continue
        m = ROW.match(line.rstrip())
        if not m:
            continue
        name = m.group(1).strip()
        if not name or name.startswith("="):
            continue
        val = lambda g: None if g == "-" else float(g)
        rows[name] = (val(m.group(2)), val(m.group(3)))
        order.append(name)
    return order, rows, prov


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    exe = sys.argv[1]
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 4

    order, samples, prov = None, {}, []
    for i in range(runs):
        out = subprocess.run([exe], capture_output=True, text=True, check=True).stdout
        o, rows, p = parse(out)
        if order is None:
            order, prov = o, p
        elif o != order:
            sys.exit("row set changed between runs -- refusing to aggregate")
        for k, v in rows.items():
            samples.setdefault(k, []).append(v)
        print(f"  run {i + 1}/{runs} done", file=sys.stderr)

    for line in prov:
        print(line)
    print()
    print(f"{'generator':<30}{'uint64/s':>14}{'doubles/s':>17}"
          f"{'u64 spread':>13}")
    for name in order:
        cols = []
        for idx in (0, 1):
            vals = [s[idx] for s in samples[name] if s[idx] is not None]
            cols.append(statistics.median(vals) if vals else None)
        u64 = [s[0] for s in samples[name] if s[0] is not None]
        spread = (max(u64) / min(u64)) if u64 and min(u64) > 0 else float("nan")
        fmt = lambda v: f"{v:.3e}" if v is not None else "-"
        print(f"{name:<30}{fmt(cols[0]):>14}{fmt(cols[1]):>17}"
              f"{spread:>12.2f}x")

    print(f"\n(median and spread over {runs} runs, one binary at a time)")


if __name__ == "__main__":
    main()
