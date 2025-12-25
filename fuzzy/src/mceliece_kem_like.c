// SPDX-License-Identifier: MIT

#include "../fuzzy_extractor.h"
#include "oqs_pqclean_decls.h"

#include <string.h>

int mceliece_kem_encode_like(const uint8_t *w, size_t wlen,
                            uint8_t *helper_out,
                            uint8_t *public_key_out, uint8_t *secret_key_out,
                            uint8_t *key_out, size_t key_len) {
    if (helper_out == NULL || public_key_out == NULL || secret_key_out == NULL || key_out == NULL) {
        return -1;
    }
    if (key_len == 0 || key_len > MCELIECE_348864F_SHARED_SECRET_LEN) return -1;

    int rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(public_key_out, secret_key_out);
    if (rc != 0) return rc;

    uint8_t shared_secret[MCELIECE_348864F_SHARED_SECRET_LEN];
    rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(helper_out, shared_secret, public_key_out);
    if (rc != 0) {
        secure_memzero(shared_secret, sizeof(shared_secret));
        return rc;
    }

    for (size_t i = 0; i < key_len; i++) {
        uint8_t s = shared_secret[i];
        uint8_t wi = (wlen > 0 && w != NULL) ? w[i % wlen] : 0;
        key_out[i] = s ^ wi;
    }

    secure_memzero(shared_secret, sizeof(shared_secret));
    return 0;
}

int mceliece_kem_decode_like(const uint8_t *wprime, size_t wlen,
                            const uint8_t *helper, const uint8_t *secret_key,
                            uint8_t *key_out, size_t key_len) {
    if (helper == NULL || secret_key == NULL || key_out == NULL) return -1;
    if (key_len == 0 || key_len > MCELIECE_348864F_SHARED_SECRET_LEN) return -1;

    uint8_t shared_secret[MCELIECE_348864F_SHARED_SECRET_LEN];
    int rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(shared_secret, helper, secret_key);
    if (rc != 0) {
        secure_memzero(shared_secret, sizeof(shared_secret));
        return rc;
    }

    for (size_t i = 0; i < key_len; i++) {
        uint8_t s = shared_secret[i];
        uint8_t wi = (wlen > 0 && wprime != NULL) ? wprime[i % wlen] : 0;
        key_out[i] = s ^ wi;
    }

    secure_memzero(shared_secret, sizeof(shared_secret));
    return 0;
}
