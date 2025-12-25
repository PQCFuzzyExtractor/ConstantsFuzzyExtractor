// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../fuzzy_extractor.h"

int main(void) {
    srand((unsigned)time(NULL));

    const size_t KEY_LEN = 16;
    uint8_t key1[KEY_LEN];
    uint8_t key2[KEY_LEN];

    uint8_t pk[MCELIECE_348864F_PUBLIC_KEY_LEN];
    uint8_t sk[MCELIECE_348864F_SECRET_KEY_LEN];
    uint8_t helper[MCELIECE_348864F_CIPHERTEXT_LEN];

    /* create a random template w */
    uint8_t w[KEY_LEN];
    for (size_t i = 0; i < KEY_LEN; i++) w[i] = (uint8_t)(rand() & 0xFF);

    printf("test_code_offset: calling code_offset_encode\n"); fflush(stdout);
    int rc = code_offset_encode(w, KEY_LEN, helper, pk, sk, key1, KEY_LEN);
    if (rc != 0) {
        fprintf(stderr, "encode failed: %d\n", rc);
        return 2;
    }

    printf("test_code_offset: calling code_offset_decode\n"); fflush(stdout);
    rc = code_offset_decode(w, KEY_LEN, helper, sk, key2, KEY_LEN);
    if (rc != 0) {
        fprintf(stderr, "decode failed: %d\n", rc);
        return 3;
    }

    if (memcmp(key1, key2, KEY_LEN) != 0) {
        fprintf(stderr, "mismatch: keys differ\n");
        return 4;
    }

    printf("Code-offset encode/decode success. key_len=%zu\n", KEY_LEN);
    return 0;
}
