#!/usr/bin/env python3
"""Validate the C ABI shared library against docs/pf_test_vectors.json.

Why this file exists. The SDK already agrees with itself across three
implementations — C++, the JavaScript in web/verifier.html, and the Python in
tests/golden/generate_pf_vectors.py. But all three are REIMPLEMENTATIONS of
the same written specification: they agree because three people read the same
document. This script is different. It calls the actual shared library a
licensee receives, from a language that is not C++, through the same FFI
mechanism they will use. A defect in the wrapper itself — not in anyone's
understanding of the scheme — shows up here and nowhere else.

Usage (from the repository root, after building):
    python bindings/python/cross_check.py
    python bindings/python/cross_check.py --lib build-openssl/Release/rngsdk_c.dll
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rngsdk  # noqa: E402


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", ".."))
    default_vectors = os.path.join(repo, "docs", "pf_test_vectors.json")

    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", default=None,
                    help="path to the rngsdk_c shared library "
                         "(default: search the usual build directories)")
    ap.add_argument("--vectors", default=default_vectors)
    args = ap.parse_args()

    lib = rngsdk.load(args.lib)
    info = lib.build_info()
    print(f"library : {lib.path}")
    print(f"version : {info.version}   backend: {info.crypto_backend}   "
          f"aes_ctr_drbg: {info.has_aes_ctr_drbg}")
    print(f"vectors : {args.vectors}")

    with open(args.vectors, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    checks = 0
    failures = []

    def check(ok, what):
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    for case in vectors["commitment_cases"]:
        got = lib.commitment(case["server_seed"])
        check(got == case["commitment"], f"commitment/{case['name']}: {got}")
        check(lib.verify_commitment(case["server_seed"], case["commitment"]),
              f"verify_commitment/{case['name']}")
        check(not lib.verify_commitment(case["server_seed"], "00" * 32),
              f"verify_commitment_negative/{case['name']}")

    for case in vectors["float_cases"]:
        got = lib.pf_next_floats(case["server_seed"], case["client_seed"],
                                 case["nonce"], case["count"])
        # Exact equality, not a tolerance. Both sides are IEEE-754 doubles
        # produced by the same construction; a near-miss is a defect, not
        # rounding.
        check(got == case["expected"], f"floats/{case['name']}")
        # pf_generate is the spec-named one-outcome alias; same value, exactly.
        check(lib.pf_generate(case["server_seed"], case["client_seed"],
                              case["nonce"]) == case["expected"][0],
              f"generate/{case['name']}")

    for case in vectors["int_cases"]:
        # bound/expected are JSON STRINGS in the vector file, not numbers:
        # uint64 values exceed what a JS/JSON number can hold exactly (the
        # same reason the web verifier uses BigInt), so the generator emits
        # them as decimal strings. Convert here — this is a JSON-encoding
        # detail of the fixture, not a recomputation of anything the library
        # does.
        bound = int(case["bound"])
        expected = [int(v) for v in case["expected"]]
        got = lib.pf_next_ints_unbiased(case["server_seed"], case["client_seed"],
                                        case["nonce"], case["count"], bound)
        check(got == expected, f"ints/{case['name']}")
        check(all(0 <= v < bound for v in got), f"ints_in_range/{case['name']}")

    # The bound == 0 rejection is part of the C contract, so it is part of what
    # a binding must surface. It has to raise, not return a plausible number.
    try:
        lib.pf_next_ints_unbiased("a" * 64, "c", 0, 1, 0)
        check(False, "bound_zero_should_raise")
    except rngsdk.RngSdkError as e:
        check(e.status == rngsdk.Status.INVALID_BOUND, f"bound_zero_status: {e.status}")

    # A deterministic generator handle reaching Python at all: same seed, same
    # sequence, across two independently created handles.
    a = lib.Random(rngsdk.Engine.XOSHIRO256PP, seed=12345)
    b = lib.Random(rngsdk.Engine.XOSHIRO256PP, seed=12345)
    check(a.next_u64_array(64) == b.next_u64_array(64), "deterministic_u64_array")
    check(all(0.0 <= x < 1.0 for x in a.next_double_array(64)), "double_range")
    a.close()
    b.close()

    # The session, end to end, exactly as an operator would drive it: commit,
    # take the player's seed, play, reveal, and let the player recompute the
    # bets from the revealed seed alone.
    seed = lib.generate_server_seed()
    session = lib.PfSession(seed, start_nonce=0)
    published = session.commitment()
    session.set_client_seed("player-chosen-seed")
    bets = [session.play(4) for _ in range(3)]
    revealed = session.reveal()
    session.close()

    check(lib.verify_commitment(revealed, published), "session_commitment_verifies")
    for i, bet in enumerate(bets):
        replay = lib.pf_next_floats(revealed, "player-chosen-seed", i, 4)
        check(replay == bet, f"session_bet_replays/{i}")

    # A seed LONGER than the 64 hex characters generate_server_seed() emits.
    # rngsdk_pf_session_create accepts any seed of 32 characters or more, and a
    # binding that sizes reveal()'s buffer from RNGSDK_HEX_BUF instead of from
    # the seed bricks the session here: the reveal latch has already fired, so
    # the session cannot play, and the seed can never be handed over, leaving
    # the bets already placed permanently unverifiable. Pinned because it is a
    # commit-reveal failure reachable from a documented-legal input.
    long_seed = "f" * 100
    session = lib.PfSession(long_seed, start_nonce=0)
    published = session.commitment()
    session.set_client_seed("player-chosen-seed")
    bet = session.play(2)
    revealed = session.reveal()
    session.close()
    check(revealed == long_seed, "long_seed_reveal_round_trips")
    check(lib.verify_commitment(revealed, published), "long_seed_commitment_verifies")
    check(lib.pf_next_floats(revealed, "player-chosen-seed", 0, 2) == bet,
          "long_seed_bet_replays")

    print(f"\n{'FAILED' if failures else 'PASSED'}: "
          f"{checks - len(failures)}/{checks} checks")
    for f in failures:
        print(f"  FAIL {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
