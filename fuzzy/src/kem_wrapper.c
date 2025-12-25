// SPDX-License-Identifier: MIT

#include "../fuzzy_extractor.h"
#include "oqs_pqclean_decls.h"

#include <string.h>

int fuzzy_generate_key(uint8_t *key_out, size_t key_len,
                       uint8_t *ciphertext_out,
                       uint8_t *public_key_out, uint8_t *secret_key_out) {
    if (key_out == NULL || ciphertext_out == NULL || public_key_out == NULL || secret_key_out == NULL) {
        return -1;
    }
    if (key_len == 0 || key_len > MCELIECE_348864F_SHARED_SECRET_LEN) {
        return -1;
    }

    int rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(public_key_out, secret_key_out);
    if (rc != 0) {
        return rc;
    }

    uint8_t shared_secret[MCELIECE_348864F_SHARED_SECRET_LEN];
    rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ciphertext_out, shared_secret, public_key_out);
    if (rc != 0) {
        secure_memzero(shared_secret, sizeof(shared_secret));
        secure_memzero(secret_key_out, MCELIECE_348864F_SECRET_KEY_LEN);
        return rc;
    }

    memcpy(key_out, shared_secret, key_len);
    secure_memzero(shared_secret, sizeof(shared_secret));
    return 0;
}

int fuzzy_reconstruct_key(uint8_t *key_out, size_t key_len,
                          const uint8_t *ciphertext, const uint8_t *secret_key) {
    if (key_out == NULL || ciphertext == NULL || secret_key == NULL) {
        return -1;
    }
    if (key_len == 0 || key_len > MCELIECE_348864F_SHARED_SECRET_LEN) {
        return -1;
    }

    uint8_t shared_secret[MCELIECE_348864F_SHARED_SECRET_LEN];
    int rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(shared_secret, ciphertext, secret_key);
    if (rc != 0) {
        secure_memzero(shared_secret, sizeof(shared_secret));
        return rc;
    }

    memcpy(key_out, shared_secret, key_len);
    secure_memzero(shared_secret, sizeof(shared_secret));
    return 0;
}
