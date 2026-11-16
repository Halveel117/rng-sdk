/* c_parse_test.c — compiled by the C compiler, on purpose.
 *
 * Its job is not behavioural coverage (tests/test_main.cpp does that) but to
 * prove rngsdk_c.h is genuinely C. Without this file the header is only ever
 * parsed by a C++ compiler, and a stray `bool`, a `namespace`, a default
 * argument or an accidental C++ keyword ships undetected and fails first on
 * the licensee's machine. It also links against the SHARED library, so it
 * proves the exported symbols are actually visible from outside the DLL/.so.
 */
#include <stdio.h>
#include <string.h>

#include "rngsdk_c.h"

static int failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            ++failures;                                                   \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);        \
        }                                                                 \
    } while (0)

/* Compile-time, not runtime: these are ABI constants a licensee's
   binary bakes in, so a violation must fail the build, not a test run.
   RNGSDK_OK == 0 is load-bearing — callers write `if (rngsdk_...())`. */
typedef char rngsdk_c_assert_ok_is_zero[(RNGSDK_OK == 0) ? 1 : -1];
typedef char rngsdk_c_assert_hex_buf[(RNGSDK_HEX_BUF == 65) ? 1 : -1];

int main(void)
{
    rngsdk_build_info_t info;
    memset(&info, 0, sizeof info);

    rngsdk_build_info(&info);
    CHECK(info.version != NULL);
    CHECK(info.crypto_backend != NULL);
    CHECK(info.has_aes_ctr_drbg == 0 || info.has_aes_ctr_drbg == 1);

    CHECK(rngsdk_status_message(RNGSDK_OK) != NULL);
    CHECK(rngsdk_status_message(RNGSDK_ERR_INTERNAL) != NULL);

    rngsdk_build_info(NULL);   /* must not crash */

    {
        rngsdk_random* h = NULL;
        uint64_t buf[8];
        int i;
        CHECK(rngsdk_random_create_seeded(RNGSDK_ENGINE_XOSHIRO256PP, 1u, &h) == RNGSDK_OK);
        CHECK(h != NULL);
        CHECK(rngsdk_next_u64_array(h, buf, 8) == RNGSDK_OK);
        for (i = 1; i < 8; ++i) CHECK(buf[i] != buf[0]);   /* not a constant stream */
        CHECK(rngsdk_random_seed(h, 2u) == RNGSDK_OK);
        rngsdk_random_destroy(h);
        rngsdk_random_destroy(NULL);
    }
    {
        rngsdk_random* h = NULL;
        CHECK(rngsdk_random_create_secure(RNGSDK_ENGINE_HMAC_DRBG, &h) == RNGSDK_OK);
        rngsdk_random_destroy(h);
    }
    {
        static const char kSeed[] =
            "a3f9c1e07b8d2456901fbe34ac57d8e21093b6f4c8a70d5e2f6b19c48307ad52";
        char hex[RNGSDK_HEX_BUF];
        double f[4];
        double one = -1.0;
        uint64_t v[4];
        int ok = 0;
        CHECK(rngsdk_pf_commitment(kSeed, hex, sizeof hex) == RNGSDK_OK);
        CHECK(strlen(hex) == 64);
        CHECK(rngsdk_pf_verify_commitment(kSeed, hex, &ok) == RNGSDK_OK);
        CHECK(ok == 1);
        CHECK(rngsdk_pf_next_floats(kSeed, "player-seed", 0u, 4, f) == RNGSDK_OK);
        CHECK(f[0] >= 0.0 && f[0] < 1.0);
        CHECK(rngsdk_pf_generate(kSeed, "player-seed", 0u, &one) == RNGSDK_OK);
        CHECK(one == f[0]);
        CHECK(rngsdk_pf_next_ints_unbiased(kSeed, "player-seed", 0u, 4, 37u, v) == RNGSDK_OK);
        CHECK(v[0] < 37u);
        CHECK(rngsdk_pf_next_ints_unbiased(kSeed, "player-seed", 0u, 4, 0u, v)
              == RNGSDK_ERR_INVALID_BOUND);
    }

    {
        static const char kSeed[] =
            "a3f9c1e07b8d2456901fbe34ac57d8e21093b6f4c8a70d5e2f6b19c48307ad52";
        rngsdk_pf_session* s = NULL;
        char hex[RNGSDK_HEX_BUF];
        double bet[4];
        uint64_t nonce = 0;
        CHECK(rngsdk_pf_session_create(kSeed, 0u, &s) == RNGSDK_OK);
        CHECK(rngsdk_pf_session_commitment(s, hex, sizeof hex) == RNGSDK_OK);
        CHECK(rngsdk_pf_session_play(s, 4, bet) == RNGSDK_ERR_NO_CLIENT_SEED);
        CHECK(rngsdk_pf_session_set_client_seed(s, "player-seed") == RNGSDK_OK);
        CHECK(rngsdk_pf_session_play(s, 4, bet) == RNGSDK_OK);
        CHECK(rngsdk_pf_session_next_nonce(s, &nonce) == RNGSDK_OK);
        CHECK(nonce == 1u);
        CHECK(rngsdk_pf_session_reveal(s, hex, sizeof hex) == RNGSDK_OK);
        CHECK(rngsdk_pf_session_play(s, 4, bet) == RNGSDK_ERR_REVEALED);
        rngsdk_pf_session_destroy(s);
        rngsdk_pf_session_destroy(NULL);
    }

    printf("c_parse_test: %s (version=%s backend=%s aes_ctr=%d)\n",
           failures ? "FAILED" : "PASSED",
           info.version, info.crypto_backend, info.has_aes_ctr_drbg);
    return failures ? 1 : 0;
}
