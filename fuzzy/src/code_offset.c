// SPDX-License-Identifier: MIT

#include "../fuzzy_extractor.h"
#include "oqs_pqclean_decls.h"

#include <oqs/sha3.h>

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#if defined(FUZZY_DEBUG)
#define FUZZY_DPRINTF(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)
#else
#define FUZZY_DPRINTF(...) do { } while (0)
#endif

/* --- Code-Offset implementation using low-level McEliece encrypt/decrypt --- */
/* SYS_N and byte size for error vectors (from params.h: 3488) */
#define SYS_N_BITS 3488
#define SYS_N_BYTES (SYS_N_BITS / 8)

/* Constants matching pqclean params.h */
#define SYS_T 64
#define GFBITS 12
#define PK_NROWS (SYS_T * GFBITS)
#define PK_NCOLS (SYS_N_BITS - PK_NROWS)
#define PK_ROW_BYTES ((PK_NCOLS + 7) / 8)
#define SYND_BYTES ((PK_NROWS + 7) / 8)

/* Compute Niederreiter ciphertext (syndrome) for a caller-provided error vector `e`.
 * This reproduces PQClean's internal syndrome routine (encrypt.c) but takes `e` from caller.
 */
static void compute_syndrome(unsigned char *s, const unsigned char *pk, const unsigned char *e) {
    unsigned char b;
    unsigned char row[SYS_N_BYTES];
    const unsigned char *pk_ptr = pk;

    for (int i = 0; i < SYND_BYTES; i++) {
        s[i] = 0;
    }

    for (int i = 0; i < PK_NROWS; i++) {
        for (int j = 0; j < SYS_N_BYTES; j++) {
            row[j] = 0;
        }

        for (int j = 0; j < PK_ROW_BYTES; j++) {
            row[SYS_N_BYTES - PK_ROW_BYTES + j] = pk_ptr[j];
        }

        row[i / 8] |= (unsigned char)(1u << (i % 8));

        b = 0;
        for (int j = 0; j < SYS_N_BYTES; j++) {
            b ^= (unsigned char)(row[j] & e[j]);
        }

        b ^= (unsigned char)(b >> 4);
        b ^= (unsigned char)(b >> 2);
        b ^= (unsigned char)(b >> 1);
        b &= 1;

        s[i / 8] |= (unsigned char)(b << (i % 8));

        pk_ptr += PK_ROW_BYTES;
    }
}

int code_offset_encode(const uint8_t *w, size_t wlen,
                       uint8_t *helper_out,
                       uint8_t *public_key_out, uint8_t *secret_key_out,
                       uint8_t *key_out, size_t key_len) {
    if (helper_out == NULL || public_key_out == NULL || secret_key_out == NULL || key_out == NULL) return -1;
    if (key_len == 0 || key_len > MCELIECE_348864F_SHARED_SECRET_LEN) return -1;

    FUZZY_DPRINTF("code_offset_encode: start (key_len=%zu, wlen=%zu)\n", key_len, wlen);

    int rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(public_key_out, secret_key_out);
    if (rc != 0) return rc;

    /* Map w into the error vector with zero-padding to preserve Hamming distance. */
    unsigned char e_vec[SYS_N_BYTES];
    memset(e_vec, 0, SYS_N_BYTES);
    if (w != NULL) {
        if (wlen >= SYS_N_BYTES) {
            memcpy(e_vec, w, SYS_N_BYTES);
        } else if (wlen > 0) {
            memcpy(e_vec, w, wlen);
        }
    }

    compute_syndrome(helper_out, public_key_out, e_vec);

    /* Derive stable key from e via SHAKE256. */
    uint8_t shared[MCELIECE_348864F_SHARED_SECRET_LEN];
    OQS_SHA3_shake256(shared, MCELIECE_348864F_SHARED_SECRET_LEN, e_vec, SYS_N_BYTES);
    memcpy(key_out, shared, key_len);

    secure_memzero(shared, sizeof(shared));
    secure_memzero(e_vec, SYS_N_BYTES);
    return 0;
}

int code_offset_decode(const uint8_t *wprime, size_t wlen,
                       const uint8_t *helper, const uint8_t *public_key, const uint8_t *secret_key,
                       uint8_t *key_out, size_t key_len) {
    if (helper == NULL || public_key == NULL || secret_key == NULL || key_out == NULL) return -1;
    if (key_len == 0 || key_len > MCELIECE_348864F_SHARED_SECRET_LEN) return -1;

    /* Step 1: map w' to an error vector e' (zero-pad) */
    unsigned char e_prime[SYS_N_BYTES];
    memset(e_prime, 0, SYS_N_BYTES);
    if (wprime != NULL) {
        if (wlen >= SYS_N_BYTES) {
            memcpy(e_prime, wprime, SYS_N_BYTES);
        } else if (wlen > 0) {
            memcpy(e_prime, wprime, wlen);
        }
    }

    /* Step 2: s' = H e' */
    unsigned char s_prime[SYND_BYTES];
    compute_syndrome(s_prime, public_key, e_prime);

    /* Step 3: s_delta = helper XOR s' */
    unsigned char s_delta[SYND_BYTES];
    for (int i = 0; i < SYND_BYTES; i++) {
        s_delta[i] = helper[i] ^ s_prime[i];
    }

    /* Step 4: decode s_delta -> error_diff */
    unsigned char error_diff[SYS_N_BYTES];

    /* PQClean KEM secret key contains Niederreiter secret key starting at +40. */
    const unsigned char *sk_niederreiter = (const unsigned char *)secret_key + 40;
    int rc = PQCLEAN_MCELIECE348864F_CLEAN_decrypt(error_diff, sk_niederreiter, s_delta);
    if (rc != 0) {
        secure_memzero(error_diff, sizeof(error_diff));
        secure_memzero(e_prime, SYS_N_BYTES);
        return rc;
    }

    /* Step 5: recover e = e' XOR error_diff */
    unsigned char e_recovered[SYS_N_BYTES];
    for (int i = 0; i < SYS_N_BYTES; i++) {
        e_recovered[i] = e_prime[i] ^ error_diff[i];
    }

    /* Step 6: derive key from recovered e */
    uint8_t shared[MCELIECE_348864F_SHARED_SECRET_LEN];
    OQS_SHA3_shake256(shared, MCELIECE_348864F_SHARED_SECRET_LEN, e_recovered, SYS_N_BYTES);
    memcpy(key_out, shared, key_len);

    secure_memzero(shared, sizeof(shared));
    secure_memzero(e_recovered, SYS_N_BYTES);
    secure_memzero(error_diff, SYS_N_BYTES);
    secure_memzero(e_prime, SYS_N_BYTES);

    return 0;
}
