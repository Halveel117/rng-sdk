"""Python binding for the RNG-SDK C ABI (c_api/include/rngsdk_c.h).

This is both a working binding and the worked example for any language with a
C FFI. The three things worth copying:

  1. BATCH. Crossing the FFI boundary costs roughly a microsecond through
     ctypes, while xoshiro256++ generates a value in about 1.5 nanoseconds.
     Always call the *_array forms. The C API's scalar forms (rngsdk_next_u64
     and friends) exist for convenience and are three orders of magnitude
     slower per value, which is why this binding deliberately wraps only the
     array forms.
  2. BUFFERS ARE YOURS. Every function writes into memory you allocate. The
     library never hands back a pointer you must free, so there is nothing to
     release except the handles themselves.
  3. STRINGS ARE STATIC. rngsdk_status_message returns a pointer into the
     library's own read-only data. Never free it.

Handles are not thread-safe: one per thread, or serialise access yourself.
"""
import ctypes
import enum
import os
import sys
from typing import NamedTuple


class Status(enum.IntEnum):
    OK = 0
    NULL_ARG = 1
    INVALID_BOUND = 2
    INVALID_ENGINE = 3
    INVALID_SEED_LEN = 4
    UNSUPPORTED = 5
    BUFFER_TOO_SMALL = 6
    WEAK_SEED = 7
    NO_CLIENT_SEED = 8
    REVEALED = 9
    NONCE_EXHAUSTED = 10
    ENTROPY = 11
    INTERNAL = 12


class Engine(enum.IntEnum):
    XOSHIRO256PP = 0     # fast tier — NOT cryptographic
    PCG64 = 1            # fast tier — NOT cryptographic
    HMAC_DRBG = 2
    AES_CTR_DRBG = 3     # OpenSSL builds only


HEX_BUF = 65


class RngSdkError(RuntimeError):
    def __init__(self, status, message, where):
        super().__init__(f"{where}: {message} (status {int(status)})")
        # A status the library added after this binding was written must not
        # turn a real error into a ValueError from the enum lookup.
        try:
            self.status = Status(status)
        except ValueError:
            self.status = status
        self.where = where


class BuildInfo(ctypes.Structure):
    _fields_ = [("version", ctypes.c_char_p),
                ("crypto_backend", ctypes.c_char_p),
                ("has_aes_ctr_drbg", ctypes.c_int)]


class BuildInfoView(NamedTuple):
    """The FROZEN rngsdk_build_info_t, decoded. See rngsdk_c.h."""
    version: str
    crypto_backend: str
    has_aes_ctr_drbg: bool


def _candidate_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", ".."))
    if sys.platform == "win32":
        names = ["rngsdk_c.dll"]
    elif sys.platform == "darwin":
        names = ["librngsdk_c.dylib"]
    else:
        names = ["librngsdk_c.so"]
    dirs = [os.path.join(repo, "build", "Release"),
            os.path.join(repo, "build-openssl", "Release"),
            os.path.join(repo, "build"),
            os.path.join(repo, "build-openssl")]
    return [os.path.join(d, n) for d in dirs for n in names]


def load(path=None):
    """Load the shared library. Pass an explicit path, set RNGSDK_C_LIB, or
    let it search the repository's usual build directories."""
    if path is None:
        path = os.environ.get("RNGSDK_C_LIB")
    if path is None:
        for candidate in _candidate_paths():
            if os.path.exists(candidate):
                path = candidate
                break
    if path is None:
        raise FileNotFoundError(
            "rngsdk_c shared library not found. Build it "
            "(cmake --build build --config Release) or pass --lib / set "
            "RNGSDK_C_LIB.")
    return Rngsdk(path)


class Rngsdk:
    """The loaded library. Everything else hangs off an instance of this."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        # Windows trap: ctypes.CDLL does NOT automatically search the loaded
        # DLL's own directory for its dependencies (the OpenSSL-flavour
        # rngsdk_c.dll needs libcrypto-3-x64.dll sitting right next to it).
        # Without this, loading fails with a bare "could not be found" error
        # that names the wrong DLL. os.add_dll_directory is the documented
        # remedy (Python >= 3.8, Windows >= 10 1709 / with the KB that adds
        # AddDllDirectory support).
        self._dll_dir_handle = None
        if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
            self._dll_dir_handle = os.add_dll_directory(os.path.dirname(self.path))
        self._lib = ctypes.CDLL(self.path)
        self._declare()

    # -- ctypes prototypes ------------------------------------------------
    def _declare(self):
        L = self._lib
        u64, u32, sz = ctypes.c_uint64, ctypes.c_uint32, ctypes.c_size_t
        p = ctypes.c_void_p
        st = ctypes.c_int

        L.rngsdk_build_info.restype = None
        L.rngsdk_build_info.argtypes = [ctypes.POINTER(BuildInfo)]
        L.rngsdk_status_message.restype = ctypes.c_char_p
        L.rngsdk_status_message.argtypes = [st]

        L.rngsdk_random_create_seeded.restype = st
        L.rngsdk_random_create_seeded.argtypes = [st, u64, ctypes.POINTER(p)]
        L.rngsdk_random_create_seeded_bytes.restype = st
        L.rngsdk_random_create_seeded_bytes.argtypes = [
            st, ctypes.POINTER(ctypes.c_uint8), sz, ctypes.POINTER(p)]
        L.rngsdk_random_create_secure.restype = st
        L.rngsdk_random_create_secure.argtypes = [st, ctypes.POINTER(p)]
        L.rngsdk_random_seed.restype = st
        L.rngsdk_random_seed.argtypes = [p, u64]
        L.rngsdk_random_destroy.restype = None
        L.rngsdk_random_destroy.argtypes = [p]

        L.rngsdk_next_u64_array.restype = st
        L.rngsdk_next_u64_array.argtypes = [p, ctypes.POINTER(u64), sz]
        L.rngsdk_next_u32_array.restype = st
        L.rngsdk_next_u32_array.argtypes = [p, ctypes.POINTER(u32), sz]
        L.rngsdk_next_double_array.restype = st
        L.rngsdk_next_double_array.argtypes = [p, ctypes.POINTER(ctypes.c_double), sz]
        L.rngsdk_next_float_array.restype = st
        L.rngsdk_next_float_array.argtypes = [p, ctypes.POINTER(ctypes.c_float), sz]
        L.rngsdk_next_bounded_u64_array.restype = st
        L.rngsdk_next_bounded_u64_array.argtypes = [p, u64, ctypes.POINTER(u64), sz]
        L.rngsdk_next_bounded_u32_array.restype = st
        L.rngsdk_next_bounded_u32_array.argtypes = [p, u32, ctypes.POINTER(u32), sz]
        L.rngsdk_next_int_range.restype = st
        L.rngsdk_next_int_range.argtypes = [p, ctypes.c_int64, ctypes.c_int64,
                                            ctypes.POINTER(ctypes.c_int64)]
        L.rngsdk_next_bytes.restype = st
        L.rngsdk_next_bytes.argtypes = [p, ctypes.POINTER(ctypes.c_uint8), sz]

        L.rngsdk_pf_commitment.restype = st
        L.rngsdk_pf_commitment.argtypes = [ctypes.c_char_p, ctypes.c_char_p, sz]
        L.rngsdk_pf_verify_commitment.restype = st
        L.rngsdk_pf_verify_commitment.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                                  ctypes.POINTER(ctypes.c_int)]
        L.rngsdk_pf_generate_server_seed.restype = st
        L.rngsdk_pf_generate_server_seed.argtypes = [ctypes.c_char_p, sz]
        L.rngsdk_pf_next_floats.restype = st
        L.rngsdk_pf_next_floats.argtypes = [ctypes.c_char_p, ctypes.c_char_p, u64, sz,
                                            ctypes.POINTER(ctypes.c_double)]
        L.rngsdk_pf_generate.restype = st
        L.rngsdk_pf_generate.argtypes = [ctypes.c_char_p, ctypes.c_char_p, u64,
                                         ctypes.POINTER(ctypes.c_double)]
        L.rngsdk_pf_next_ints.restype = st
        L.rngsdk_pf_next_ints.argtypes = [ctypes.c_char_p, ctypes.c_char_p, u64, sz, u64,
                                          ctypes.POINTER(u64)]
        L.rngsdk_pf_next_ints_unbiased.restype = st
        L.rngsdk_pf_next_ints_unbiased.argtypes = [ctypes.c_char_p, ctypes.c_char_p, u64,
                                                   sz, u64, ctypes.POINTER(u64)]

        L.rngsdk_pf_session_create.restype = st
        L.rngsdk_pf_session_create.argtypes = [ctypes.c_char_p, u64, ctypes.POINTER(p)]
        L.rngsdk_pf_session_destroy.restype = None
        L.rngsdk_pf_session_destroy.argtypes = [p]
        L.rngsdk_pf_session_commitment.restype = st
        L.rngsdk_pf_session_commitment.argtypes = [p, ctypes.c_char_p, sz]
        L.rngsdk_pf_session_set_client_seed.restype = st
        L.rngsdk_pf_session_set_client_seed.argtypes = [p, ctypes.c_char_p]
        L.rngsdk_pf_session_play.restype = st
        L.rngsdk_pf_session_play.argtypes = [p, sz, ctypes.POINTER(ctypes.c_double)]
        L.rngsdk_pf_session_next_nonce.restype = st
        L.rngsdk_pf_session_next_nonce.argtypes = [p, ctypes.POINTER(u64)]
        L.rngsdk_pf_session_reveal.restype = st
        L.rngsdk_pf_session_reveal.argtypes = [p, ctypes.c_char_p, sz]

    # -- error handling ---------------------------------------------------
    def _check(self, status, where):
        if status != Status.OK:
            # The returned pointer is static library data. Do NOT free it;
            # ctypes copies the bytes out for us here.
            msg = self._lib.rngsdk_status_message(status).decode("utf-8")
            raise RngSdkError(status, msg, where)

    # -- introspection ----------------------------------------------------
    def build_info(self):
        raw = BuildInfo()
        self._lib.rngsdk_build_info(ctypes.byref(raw))
        return BuildInfoView(raw.version.decode("utf-8"),
                             raw.crypto_backend.decode("utf-8"),
                             bool(raw.has_aes_ctr_drbg))

    # -- Provably Fair, stateless -----------------------------------------
    def commitment(self, server_seed):
        buf = ctypes.create_string_buffer(HEX_BUF)
        self._check(self._lib.rngsdk_pf_commitment(_utf8(server_seed), buf, HEX_BUF),
                    "rngsdk_pf_commitment")
        return buf.value.decode("ascii")

    def verify_commitment(self, server_seed, commitment_hex):
        ok = ctypes.c_int(0)
        self._check(self._lib.rngsdk_pf_verify_commitment(
            _utf8(server_seed), _utf8(commitment_hex), ctypes.byref(ok)),
            "rngsdk_pf_verify_commitment")
        return ok.value == 1

    def generate_server_seed(self):
        buf = ctypes.create_string_buffer(HEX_BUF)
        self._check(self._lib.rngsdk_pf_generate_server_seed(buf, HEX_BUF),
                    "rngsdk_pf_generate_server_seed")
        return buf.value.decode("ascii")

    def pf_next_floats(self, server_seed, client_seed, nonce, n):
        out = (ctypes.c_double * n)()
        self._check(self._lib.rngsdk_pf_next_floats(
            _utf8(server_seed), _utf8(client_seed), nonce, n, out),
            "rngsdk_pf_next_floats")
        return list(out)

    def pf_generate(self, server_seed, client_seed, nonce):
        out = ctypes.c_double()
        self._check(self._lib.rngsdk_pf_generate(
            _utf8(server_seed), _utf8(client_seed), nonce, ctypes.byref(out)),
            "rngsdk_pf_generate")
        return out.value

    def pf_next_ints(self, server_seed, client_seed, nonce, n, bound):
        out = (ctypes.c_uint64 * n)()
        self._check(self._lib.rngsdk_pf_next_ints(
            _utf8(server_seed), _utf8(client_seed), nonce, n, bound, out),
            "rngsdk_pf_next_ints")
        return list(out)

    def pf_next_ints_unbiased(self, server_seed, client_seed, nonce, n, bound):
        out = (ctypes.c_uint64 * n)()
        self._check(self._lib.rngsdk_pf_next_ints_unbiased(
            _utf8(server_seed), _utf8(client_seed), nonce, n, bound, out),
            "rngsdk_pf_next_ints_unbiased")
        return list(out)

    # -- handle factories -------------------------------------------------
    def Random(self, engine, seed=None, seed_bytes=None):
        return Random(self, engine, seed=seed, seed_bytes=seed_bytes)

    def PfSession(self, server_seed, start_nonce):
        return PfSession(self, server_seed, start_nonce)


def _utf8(s):
    """Seeds cross the boundary as their own UTF-8/ASCII BYTES.

    THE TRAP: the scheme uses the server seed's CHARACTERS as the HMAC key —
    the bytes of the 64 hex characters, not the 32 bytes they encode. If you
    hold raw bytes, hex-encode them into a string and pass that. Decoding the
    hex first produces a different key and an entirely different result
    stream, with nothing to tell you it happened.
    """
    return s.encode("utf-8") if isinstance(s, str) else s


class Random:
    """A generator handle. Not thread-safe. Prefer the *_array methods."""

    def __init__(self, lib, engine, seed=None, seed_bytes=None):
        self._lib = lib
        self._h = ctypes.c_void_p()
        L = lib._lib
        if seed is not None and seed_bytes is not None:
            raise ValueError("pass seed or seed_bytes, not both")
        if seed is not None:
            st = L.rngsdk_random_create_seeded(int(engine), seed, ctypes.byref(self._h))
            where = "rngsdk_random_create_seeded"
        elif seed_bytes is not None:
            buf = (ctypes.c_uint8 * len(seed_bytes))(*seed_bytes)
            st = L.rngsdk_random_create_seeded_bytes(int(engine), buf, len(seed_bytes),
                                                     ctypes.byref(self._h))
            where = "rngsdk_random_create_seeded_bytes"
        else:
            # OS-seeded. On the fast tier this is unpredictable at
            # instantiation but still NOT cryptographic — never use the fast
            # tier for paid outcomes.
            st = L.rngsdk_random_create_secure(int(engine), ctypes.byref(self._h))
            where = "rngsdk_random_create_secure"
        lib._check(st, where)

    def close(self):
        if self._h:
            self._lib._lib.rngsdk_random_destroy(self._h)
            self._h = ctypes.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def seed(self, value):
        self._lib._check(self._lib._lib.rngsdk_random_seed(self._h, value),
                         "rngsdk_random_seed")

    def next_u64_array(self, n):
        out = (ctypes.c_uint64 * n)()
        self._lib._check(self._lib._lib.rngsdk_next_u64_array(self._h, out, n),
                         "rngsdk_next_u64_array")
        return list(out)

    def next_u32_array(self, n):
        out = (ctypes.c_uint32 * n)()
        self._lib._check(self._lib._lib.rngsdk_next_u32_array(self._h, out, n),
                         "rngsdk_next_u32_array")
        return list(out)

    def next_double_array(self, n):
        out = (ctypes.c_double * n)()
        self._lib._check(self._lib._lib.rngsdk_next_double_array(self._h, out, n),
                         "rngsdk_next_double_array")
        return list(out)

    def next_float_array(self, n):
        out = (ctypes.c_float * n)()
        self._lib._check(self._lib._lib.rngsdk_next_float_array(self._h, out, n),
                         "rngsdk_next_float_array")
        return list(out)

    def next_bounded_u64_array(self, bound, n):
        out = (ctypes.c_uint64 * n)()
        self._lib._check(
            self._lib._lib.rngsdk_next_bounded_u64_array(self._h, bound, out, n),
            "rngsdk_next_bounded_u64_array")
        return list(out)

    def next_bounded_u32_array(self, bound, n):
        out = (ctypes.c_uint32 * n)()
        self._lib._check(
            self._lib._lib.rngsdk_next_bounded_u32_array(self._h, bound, out, n),
            "rngsdk_next_bounded_u32_array")
        return list(out)

    def next_int_range(self, lo, hi):
        out = ctypes.c_int64(0)
        self._lib._check(
            self._lib._lib.rngsdk_next_int_range(self._h, lo, hi, ctypes.byref(out)),
            "rngsdk_next_int_range")
        return out.value

    def next_bytes(self, n):
        out = (ctypes.c_uint8 * n)()
        self._lib._check(self._lib._lib.rngsdk_next_bytes(self._h, out, n),
                         "rngsdk_next_bytes")
        return bytes(out)


class PfSession:
    """A Provably Fair server session. Not thread-safe.

    start_nonce is required. Persist it with the server seed: a server that
    restarts and resumes at 0 replays outcomes the player has already seen.
    """

    def __init__(self, lib, server_seed, start_nonce):
        self._lib = lib
        self._h = ctypes.c_void_p()
        # Size reveal()'s buffer from the seed we were actually given, not from
        # HEX_BUF. rngsdk_pf_session_create accepts any seed of 32 characters or
        # more; a longer one would make reveal() fail with BUFFER_TOO_SMALL
        # *after* the latch has fired, leaving a session that can neither play
        # nor produce the seed the player needs to verify the bets already made.
        self._reveal_cap = len(_utf8(server_seed)) + 1
        lib._check(lib._lib.rngsdk_pf_session_create(
            _utf8(server_seed), start_nonce, ctypes.byref(self._h)),
            "rngsdk_pf_session_create")

    def close(self):
        if self._h:
            self._lib._lib.rngsdk_pf_session_destroy(self._h)
            self._h = ctypes.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def commitment(self):
        buf = ctypes.create_string_buffer(HEX_BUF)
        self._lib._check(
            self._lib._lib.rngsdk_pf_session_commitment(self._h, buf, HEX_BUF),
            "rngsdk_pf_session_commitment")
        return buf.value.decode("ascii")

    def set_client_seed(self, client_seed):
        self._lib._check(
            self._lib._lib.rngsdk_pf_session_set_client_seed(self._h, _utf8(client_seed)),
            "rngsdk_pf_session_set_client_seed")

    def play(self, n_floats):
        out = (ctypes.c_double * n_floats)()
        self._lib._check(self._lib._lib.rngsdk_pf_session_play(self._h, n_floats, out),
                         "rngsdk_pf_session_play")
        return list(out)

    def next_nonce(self):
        out = ctypes.c_uint64(0)
        self._lib._check(
            self._lib._lib.rngsdk_pf_session_next_nonce(self._h, ctypes.byref(out)),
            "rngsdk_pf_session_next_nonce")
        return out.value

    def reveal(self):
        buf = ctypes.create_string_buffer(self._reveal_cap)
        self._lib._check(
            self._lib._lib.rngsdk_pf_session_reveal(
                self._h, buf, self._reveal_cap),
            "rngsdk_pf_session_reveal")
        return buf.value.decode("ascii")
