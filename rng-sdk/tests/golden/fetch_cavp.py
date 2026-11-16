#!/usr/bin/env python3
"""Fetch NIST CAVP DRBG test vectors and emit them as a C++ header.

These are the *authoritative* known-answer vectors: published by the standards
body itself, not produced by any implementation of ours. That makes them a
strictly stronger reference than the cross-implementation golden values in
generate_golden.py -- those catch porting bugs between two readings of the
spec, these catch a wrong reading shared by both.

Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
        -> drbgtestvectors.zip -> drbgvectors_no_reseed.zip
             -> HMAC_DRBG.rsp  [SHA-256]
             -> CTR_DRBG.rsp   [AES-256 no df]

"no_reseed" matches how the SDK instantiates: seed once, generate, never
reseed mid-stream. The CAVP procedure for each COUNT block is:

    Instantiate(EntropyInput, Nonce, PersonalizationString)
    Generate(ReturnedBitsLen)      # first output is DISCARDED
    Generate(ReturnedBitsLen)      # second output == ReturnedBits

Run:  python fetch_cavp.py > golden_cavp.hpp
"""
import io
import re
import sys
import urllib.request
import zipfile

URL = ("https://csrc.nist.gov/CSRC/media/Projects/"
       "Cryptographic-Algorithm-Validation-Program/documents/drbg/"
       "drbgtestvectors.zip")

# NIST rejects the default urllib UA with 403.
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

VECTORS_PER_SECTION = 6   # enough to catch systematic errors; keeps the header small


def download():
    req = urllib.request.Request(URL, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        outer = zipfile.ZipFile(io.BytesIO(r.read()))
    inner = zipfile.ZipFile(io.BytesIO(outer.read("drbgvectors_no_reseed.zip")))
    return (inner.read("HMAC_DRBG.rsp").decode("utf-8", "replace"),
            inner.read("CTR_DRBG.rsp").decode("utf-8", "replace"))


def section_starts(lines, header):
    return [i for i, l in enumerate(lines) if l.strip() == header]


def peek_params(lines, start):
    """Read the [Key = Value] parameter block immediately after a section header."""
    p = {}
    for x in lines[start + 1:]:
        s = x.strip()
        if not s:
            continue
        if not s.startswith("["):
            break
        k, _, v = s[1:-1].partition(" = ")
        p[k] = v
    return p


def parse_section(text, header, want=None):
    """Return (params, [vector dicts]) for a [header] block of a .rsp file.

    A .rsp repeats the same header many times with different parameter blocks
    (personalization / additional-input lengths). `want` selects by those
    parameters rather than by ordinal, so an upstream reordering cannot
    silently swap which vectors we validate against.
    """
    lines = text.splitlines()
    candidates = section_starts(lines, header)
    if not candidates:
        raise SystemExit(f"section {header!r} not found")

    start = None
    for c in candidates:
        p = peek_params(lines, c)
        if want is None or all(p.get(k) == v for k, v in want.items()):
            start = c
            break
    if start is None:
        raise SystemExit(f"no {header!r} section matching {want}")

    params, vectors, current = {}, [], None
    for line in lines[start + 1:]:
        s = line.strip()
        if not s:
            continue
        if s.startswith("["):
            # A new [Foo] after we've started collecting = next section.
            if vectors or current:
                break
            k, _, v = s[1:-1].partition(" = ")
            params[k] = v
            continue
        key, _, val = s.partition(" = ")
        key, val = key.strip(), val.strip()
        if key == "COUNT":
            if current:
                vectors.append(current)
                if len(vectors) >= VECTORS_PER_SECTION:
                    return params, vectors
            current = {"COUNT": val, "AdditionalInput": []}
        elif current is not None:
            if key == "AdditionalInput":
                current["AdditionalInput"].append(val)
            else:
                current[key] = val
    if current and len(vectors) < VECTORS_PER_SECTION:
        vectors.append(current)
    return params, vectors


def cpp_array(name, vectors, fields):
    """Emit one C++ struct array. Empty hex strings stay empty (means absent).

    AdditionalInput is a 2-element list per vector (one per Generate call);
    it is emitted as two separate fields.
    """
    out = [f"inline constexpr CavpVector {name}[] = {{"]
    for v in vectors:
        vals = []
        for f in fields:
            if f == "AdditionalInput0":
                vals.append(v["AdditionalInput"][0] if v["AdditionalInput"] else "")
            elif f == "AdditionalInput1":
                vals.append(v["AdditionalInput"][1] if len(v["AdditionalInput"]) > 1 else "")
            else:
                vals.append(v.get(f, ""))
        out.append("    {" + ", ".join(f'"{x}"' for x in vals) + "},")
    out.append("};")
    return "\n".join(out)


def check(params, expect, label):
    """Fail loudly if the upstream file no longer matches what the C++ encodes."""
    for k, v in expect.items():
        if params.get(k) != v:
            raise SystemExit(f"{label}: expected {k}={v}, got {params.get(k)!r}")


FIELDS = ("EntropyInput", "Nonce", "PersonalizationString",
          "AdditionalInput0", "AdditionalInput1", "ReturnedBits")


def main():
    hmac_txt, ctr_txt = download()

    # Two sections per engine. The "plain" one pins the core Update/Generate
    # machinery; the "full" one (non-empty personalization AND additional
    # input) is what actually exercises the seed-material construction and the
    # additional-input branch of Update. Validating only the plain section
    # leaves the paths most likely to be wrong completely uncovered -- for
    # CTR_DRBG no-df in particular, personalization is XORed into the seed
    # material (SP 800-90A 10.2.1.3.1), and with a zero-length string XOR and
    # concatenation are indistinguishable.
    hmac_plain_p, hmac_plain = parse_section(
        hmac_txt, "[SHA-256]",
        {"PersonalizationStringLen": "0", "AdditionalInputLen": "0"})
    hmac_full_p, hmac_full = parse_section(
        hmac_txt, "[SHA-256]",
        {"PersonalizationStringLen": "256", "AdditionalInputLen": "256"})
    ctr_plain_p, ctr_plain = parse_section(
        ctr_txt, "[AES-256 no df]",
        {"PersonalizationStringLen": "0", "AdditionalInputLen": "0"})
    ctr_full_p, ctr_full = parse_section(
        ctr_txt, "[AES-256 no df]",
        {"PersonalizationStringLen": "384", "AdditionalInputLen": "384"})

    # Everything the C++ side assumes, asserted here so a re-fetch against a
    # changed upstream fails loudly instead of silently testing less.
    for p, label in ((hmac_plain_p, "hmac plain"), (hmac_full_p, "hmac full")):
        check(p, {"EntropyInputLen": "256", "NonceLen": "128",
                  "ReturnedBitsLen": "1024", "PredictionResistance": "False"}, label)
    for p, label in ((ctr_plain_p, "ctr plain"), (ctr_full_p, "ctr full")):
        check(p, {"EntropyInputLen": "384", "NonceLen": "0",
                  "ReturnedBitsLen": "512", "PredictionResistance": "False"}, label)
    check(hmac_full_p, {"PersonalizationStringLen": "256",
                        "AdditionalInputLen": "256"}, "hmac full")
    check(ctr_full_p, {"PersonalizationStringLen": "384",
                       "AdditionalInputLen": "384"}, "ctr full")
    for vecs, label in ((hmac_plain, "hmac plain"), (hmac_full, "hmac full"),
                        (ctr_plain, "ctr plain"), (ctr_full, "ctr full")):
        if len(vecs) != VECTORS_PER_SECTION:
            raise SystemExit(f"{label}: got {len(vecs)} vectors, want {VECTORS_PER_SECTION}")

    print("// golden_cavp.hpp - GENERATED by fetch_cavp.py. Do not edit by hand.")
    print("//")
    print("// NIST CAVP known-answer vectors (drbgvectors_no_reseed, pr=false).")
    print("// Procedure per vector:")
    print("//   Instantiate(entropy, nonce, personalization)")
    print("//   Generate(n, additional_input_0)   <- DISCARDED")
    print("//   Generate(n, additional_input_1)   == returned_bits")
    print("//")
    print("// Two sections per engine: *Plain has zero-length personalization and")
    print("// additional input; *Full has both non-empty, which is the only thing")
    print("// that distinguishes a correct seed-material construction from a wrong")
    print("// one (with an empty string, XOR and concatenation agree).")
    print("#pragma once")
    print()
    print("namespace golden {")
    print()
    print("struct CavpVector {")
    print("    const char* entropy;         // hex")
    print("    const char* nonce;           // hex, empty if unused")
    print("    const char* personalization; // hex, empty if unused")
    print("    const char* additional0;     // hex, additional input, 1st Generate")
    print("    const char* additional1;     // hex, additional input, 2nd Generate")
    print("    const char* returned_bits;   // hex, output of the 2nd Generate")
    print("};")
    print()
    print(f"// HMAC_DRBG [SHA-256]: entropy {hmac_plain_p['EntropyInputLen']} bits, "
          f"nonce {hmac_plain_p['NonceLen']} bits, "
          f"returns {hmac_plain_p['ReturnedBitsLen']} bits.")
    print(f"inline constexpr int kCavpHmacReturnedBytes = "
          f"{int(hmac_plain_p['ReturnedBitsLen']) // 8};")
    print(cpp_array("kCavpHmacSha256Plain", hmac_plain, FIELDS))
    print(cpp_array("kCavpHmacSha256Full", hmac_full, FIELDS))
    print()
    print(f"// CTR_DRBG [AES-256 no df]: entropy {ctr_plain_p['EntropyInputLen']} bits "
          f"(= seedlen = keylen 256 + blocklen 128), returns "
          f"{ctr_plain_p['ReturnedBitsLen']} bits.")
    print(f"inline constexpr int kCavpCtrReturnedBytes = "
          f"{int(ctr_plain_p['ReturnedBitsLen']) // 8};")
    print(cpp_array("kCavpCtrAes256NoDfPlain", ctr_plain, FIELDS))
    print(cpp_array("kCavpCtrAes256NoDfFull", ctr_full, FIELDS))
    print()
    print("} // namespace golden")


if __name__ == "__main__":
    main()
