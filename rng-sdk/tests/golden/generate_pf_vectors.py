#!/usr/bin/env python3
"""Generate Provably Fair test vectors from an INDEPENDENT implementation.

Rationale (same as generate_golden.py): vectors produced by our own C++ would
prove only self-consistency. These come from Python's hashlib/hmac, so they
catch a porting bug in EITHER the C++ or the JavaScript verifier. Two
implementations agreeing proves only that they share an author's misreading —
and the two traps in the design spec (§3.1 hex-vs-ASCII key, §3.2 BigInt) are
exactly the mistake one author makes twice.

Emits two artifacts from one computation, so they cannot disagree:
  docs/pf_test_vectors.json        — embedded verbatim in web/verifier.html
  tests/golden/golden_pf_vectors.hpp — included by tests/test_main.cpp

Run:  python3 tests/golden/generate_pf_vectors.py
"""
import hashlib
import hmac as hmac_mod
import json
import os

# The server seed is used as the HMAC key AS ITS OWN BYTES — the ASCII of the
# hex string, not the 32 bytes that hex encodes. This mirrors ByteStream and
# the Stake-compatible ecosystem. See design spec §3.1: hex-decoding here is
# the single most likely reimplementation error, and it fails silently.
SERVER_HEX = "a3f9c1e07b8d2456901fbe34ac57d8e21093b6f4c8a70d5e2f6b19c48307ad52"
SERVER_SHORT = "s3cret-server-seed"

CLIENT_BASIC = "player-seed"
CLIENT_EMPTY = ""
CLIENT_UNICODE = "joueur-café-日本語-🎲"
# 60 chars: makes the message "<seed>:0:0" 64 bytes, past the 56-byte point
# where SHA-256 needs a second block for the MESSAGE (not merely for HMAC's
# padded key block, which is always present and sits at a fixed offset).
CLIENT_LONG = "abcdefghij0123456789abcdefghij0123456789abcdefghij0123456789"

# 2^63 + 1. Chosen so 2^64 mod bound = 2^63 - 1, giving ~50% rejection per
# draw: a handful of samples is then near-certain to exercise the rejection
# branch. An implementation that never rejects passes a naive vector set.
BOUND_REJECT = (1 << 63) + 1
BOUND_SMALL = 37


class ByteStream:
    """Mirrors rngsdk::pf::ByteStream."""

    def __init__(self, server_seed, client_seed, nonce):
        self.key = server_seed.encode("utf-8")
        self.client_seed = client_seed
        self.nonce = nonce
        self.cursor = 0
        self.block = b""
        self.pos = 32

    def next_block(self):
        msg = f"{self.client_seed}:{self.nonce}:{self.cursor}".encode("utf-8")
        self.block = hmac_mod.new(self.key, msg, hashlib.sha256).digest()
        self.cursor += 1
        self.pos = 0

    def next_byte(self):
        if self.pos == 32:
            self.next_block()
        b = self.block[self.pos]
        self.pos += 1
        return b

    def next_u64(self):
        x = 0
        for _ in range(8):
            x = (x << 8) | self.next_byte()
        return x


def pf_floats(server_seed, client_seed, nonce, count):
    """Mirrors Generator::NextFloats. Every term is a dyadic rational and every
    partial sum is k/2^32 with k < 2^32, so no rounding occurs — the result is
    bit-identical in C++, Python and JavaScript (design spec §3.3)."""
    bs = ByteStream(server_seed, client_seed, nonce)
    out = []
    for _ in range(count):
        b = [bs.next_byte() for _ in range(4)]
        out.append(b[0] / 2**8 + b[1] / 2**16 + b[2] / 2**24 + b[3] / 2**32)
    return out


def pf_ints_unbiased(server_seed, client_seed, nonce, count, bound):
    """Mirrors Generator::NextIntsUnbiased (Lemire rejection).

    C++ computes the threshold as (0 - bound) % bound in unsigned 64-bit
    arithmetic, which equals 2^64 mod bound since 2^64 - bound is congruent to
    2^64 modulo bound. Returns (values, rejection_count) so the caller can
    assert the rejection branch was actually taken.
    """
    bs = ByteStream(server_seed, client_seed, nonce)
    t = (1 << 64) % bound
    out = []
    rejections = 0
    for _ in range(count):
        while True:
            x = bs.next_u64()
            m = x * bound
            hi, lo = m >> 64, m & ((1 << 64) - 1)
            if lo >= t:
                out.append(hi)
                break
            rejections += 1
    return out, rejections


def build():
    commitment_cases = [
        {"name": "hex_seed", "server_seed": SERVER_HEX},
        {"name": "short_seed", "server_seed": SERVER_SHORT},
    ]
    for c in commitment_cases:
        c["commitment"] = hashlib.sha256(c["server_seed"].encode("utf-8")).hexdigest()

    float_specs = [
        # 12 floats = 48 bytes > 32, so the cursor must advance to 1.
        ("basic_cursor_rollover", SERVER_HEX, CLIENT_BASIC, 0, 12),
        # Same inputs, different nonce: proves the nonce enters the message and
        # not the key, and that outcomes do not replay across nonces.
        ("nonce_8", SERVER_HEX, CLIENT_BASIC, 8, 12),
        ("empty_client_seed", SERVER_HEX, CLIENT_EMPTY, 0, 4),
        ("unicode_client_seed", SERVER_HEX, CLIENT_UNICODE, 3, 4),
        ("long_message_two_blocks", SERVER_HEX, CLIENT_LONG, 0, 4),
        ("short_server_seed", SERVER_SHORT, CLIENT_BASIC, 7, 4),
    ]
    float_cases = []
    for name, srv, cli, nonce, count in float_specs:
        float_cases.append({
            "name": name, "server_seed": srv, "client_seed": cli,
            "nonce": nonce, "count": count,
            "expected": pf_floats(srv, cli, nonce, count),
        })

    int_specs = [
        ("small_bound", SERVER_HEX, CLIENT_BASIC, 0, 16, BOUND_SMALL),
        ("bound_forcing_rejection", SERVER_HEX, CLIENT_BASIC, 0, 16, BOUND_REJECT),
    ]
    int_cases = []
    for name, srv, cli, nonce, count, bound in int_specs:
        values, rejections = pf_ints_unbiased(srv, cli, nonce, count, bound)
        int_cases.append({
            "name": name, "server_seed": srv, "client_seed": cli,
            "nonce": nonce, "count": count,
            # Strings: these exceed 2^53 and JSON.parse would round them.
            "bound": str(bound),
            "expected": [str(v) for v in values],
            "rejections": rejections,
        })

    reject_case = next(c for c in int_cases if c["name"] == "bound_forcing_rejection")
    if reject_case["rejections"] == 0:
        raise SystemExit("bound_forcing_rejection took no rejections — "
                         "the branch it exists to cover is untested")

    return {
        "_comment": ("AUTO-GENERATED by tests/golden/generate_pf_vectors.py — "
                     "do not edit. Computed by an independent Python "
                     "implementation; see that script for the reasoning."),
        "commitment_cases": commitment_cases,
        "float_cases": float_cases,
        "int_cases": int_cases,
    }


def cpp_escape(s):
    """Escape for a C++ narrow string literal, as UTF-8 bytes. Non-ASCII is
    emitted as \\xNN with string-literal concatenation breaks, because a hex
    escape in C++ consumes as many hex digits as follow it — "\\xc3a" is one
    (overflowing) escape, not "\\xc3" then 'a'."""
    out = []
    for byte in s.encode("utf-8"):
        ch = chr(byte)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= byte < 0x7F:
            out.append(ch)
        else:
            out.append('\\x%02x""' % byte)
    return '"' + "".join(out) + '"'


def emit_header(data):
    L = []
    L.append("// AUTO-GENERATED by tests/golden/generate_pf_vectors.py — do not edit.")
    L.append("// Provably Fair vectors from an independent Python implementation.")
    L.append("// The same values are in docs/pf_test_vectors.json, which")
    L.append("// web/verifier.html embeds verbatim; a drift guard keeps them equal.")
    L.append("#pragma once")
    L.append("#include <cstddef>")
    L.append("#include <cstdint>")
    L.append("namespace golden_pf {")
    L.append("")
    L.append("struct CommitmentCase { const char* name; const char* server_seed; const char* commitment; };")
    L.append("struct FloatCase { const char* name; const char* server_seed; const char* client_seed;")
    L.append("                   std::uint64_t nonce; std::size_t count; const double* expected; };")
    L.append("struct IntCase { const char* name; const char* server_seed; const char* client_seed;")
    L.append("                 std::uint64_t nonce; std::size_t count; std::uint64_t bound;")
    L.append("                 const std::uint64_t* expected; };")
    L.append("")

    L.append("inline constexpr CommitmentCase kCommitmentCases[] = {")
    for c in data["commitment_cases"]:
        L.append("    {%s, %s, \"%s\"}," % (cpp_escape(c["name"]),
                                            cpp_escape(c["server_seed"]),
                                            c["commitment"]))
    L.append("};")
    L.append("inline constexpr std::size_t kCommitmentCaseCount = %d;"
             % len(data["commitment_cases"]))
    L.append("")

    for c in data["float_cases"]:
        body = ", ".join(repr(f) for f in c["expected"])
        L.append("inline constexpr double kFloats_%s[] = {%s};" % (c["name"], body))
    L.append("inline constexpr FloatCase kFloatCases[] = {")
    for c in data["float_cases"]:
        L.append("    {%s, %s, %s, %dull, %d, kFloats_%s},"
                 % (cpp_escape(c["name"]), cpp_escape(c["server_seed"]),
                    cpp_escape(c["client_seed"]), c["nonce"], c["count"], c["name"]))
    L.append("};")
    L.append("inline constexpr std::size_t kFloatCaseCount = %d;" % len(data["float_cases"]))
    L.append("")

    for c in data["int_cases"]:
        body = ", ".join("%sull" % v for v in c["expected"])
        L.append("inline constexpr std::uint64_t kInts_%s[] = {%s};" % (c["name"], body))
    L.append("inline constexpr IntCase kIntCases[] = {")
    for c in data["int_cases"]:
        L.append("    {%s, %s, %s, %dull, %d, %sull, kInts_%s},"
                 % (cpp_escape(c["name"]), cpp_escape(c["server_seed"]),
                    cpp_escape(c["client_seed"]), c["nonce"], c["count"],
                    c["bound"], c["name"]))
    L.append("};")
    L.append("inline constexpr std::size_t kIntCaseCount = %d;" % len(data["int_cases"]))
    L.append("")
    L.append("} // namespace golden_pf")
    return "\n".join(L) + "\n"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))   # tests/golden -> tests -> repo
    data = build()

    json_path = os.path.join(root, "docs", "pf_test_vectors.json")
    # Explicit "\n" newline and UTF-8: the drift guard compares this file's
    # bytes against the copy embedded in the HTML, and a platform-dependent
    # line ending here would make that comparison depend on the checkout.
    with open(json_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    hpp_path = os.path.join(here, "golden_pf_vectors.hpp")
    with open(hpp_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(emit_header(data))

    print("wrote %s" % json_path)
    print("wrote %s" % hpp_path)


if __name__ == "__main__":
    main()
