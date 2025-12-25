// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define FUZZY_USE_MOCK
#include "../fuzzy_extractor.h"

int main(void) {
    uint8_t key[MCELIECE_348864F_SHARED_SECRET_LEN];
    uint8_t key2[MCELIECE_348864F_SHARED_SECRET_LEN];
    uint8_t ciphertext[MCELIECE_348864F_CIPHERTEXT_LEN];
    uint8_t public_key[MCELIECE_348864F_PUBLIC_KEY_LEN];
    uint8_t secret_key[MCELIECE_348864F_SECRET_KEY_LEN];

    memset(key, 0, sizeof(key));

    int rc = fuzzy_generate_key(key, sizeof(key), ciphertext, public_key, secret_key);
    if (rc != 0) {
        fprintf(stderr, "fuzzy_generate_key failed: %d\n", rc);
        return 2;
    }

    /* key should not be all zeros */
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(key); i++) nonzero |= key[i];
    assert(nonzero != 0);

    /* reconstruct and compare */
    rc = fuzzy_reconstruct_key(key2, sizeof(key2), ciphertext, secret_key);
    if (rc != 0) {
        fprintf(stderr, "fuzzy_reconstruct_key failed: %d\n", rc);
        return 3;
    }

    assert(constant_time_compare(key, key2, sizeof(key)) == 1);

    /* test secure erase of key and secret */
    secure_memzero(key, sizeof(key));
    for (size_t i = 0; i < sizeof(key); i++) assert(key[i] == 0);

    secure_memzero(secret_key, sizeof(secret_key));
    for (size_t i = 0; i < sizeof(secret_key); i++) assert(secret_key[i] == 0);

    /* Additional test: use BCH-like encode/decode wrappers with a sample input */
    uint8_t w[16];
    for (size_t i = 0; i < sizeof(w); i++) w[i] = (uint8_t)(i * 3 + 7);

    uint8_t key3[MCELIECE_348864F_SHARED_SECRET_LEN];
    uint8_t key4[MCELIECE_348864F_SHARED_SECRET_LEN];
    /* regenerate public/secret to test encode/decode */
    rc = mceliece_kem_encode_like(w, sizeof(w), ciphertext, public_key, secret_key, key3, sizeof(key3));
    if (rc != 0) { fprintf(stderr, "mceliece_kem_encode_like failed: %d\n", rc); return 4; }

    rc = mceliece_kem_decode_like(w, sizeof(w), ciphertext, secret_key, key4, sizeof(key4));
    if (rc != 0) { fprintf(stderr, "mceliece_kem_decode_like failed: %d\n", rc); return 5; }

    assert(constant_time_compare(key3, key4, sizeof(key3)) == 1);

    printf("All fuzzy extractor tests passed.\n");
    return 0;
}
