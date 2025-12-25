// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../fuzzy_extractor.h"

#define TEST_KEY_LEN 32
#define TEST_WLEN 32
#define MAX_ERRORS 70
/* Classic McEliece 348864f corrects up to SYS_T=64 errors */
#define EXPECTED_MAX_OK 64

int main() {
    uint8_t w[TEST_WLEN];
    uint8_t w_prime[TEST_WLEN];
    uint8_t helper[MCELIECE_348864F_CIPHERTEXT_LEN];
    uint8_t pk[MCELIECE_348864F_PUBLIC_KEY_LEN];
    uint8_t sk[MCELIECE_348864F_SECRET_KEY_LEN];
    uint8_t key_orig[TEST_KEY_LEN];
    uint8_t key_recov[TEST_KEY_LEN];
    int i, errors, rc;
    int success = 0, fail = 0;

    // 1. 랜덤 원본 w 생성
    for (i = 0; i < TEST_WLEN; i++) w[i] = (uint8_t)rand();

    // 2. Encode
    rc = code_offset_encode(w, TEST_WLEN, helper, pk, sk, key_orig, TEST_KEY_LEN);
    if (rc != 0) {
        printf("[FAIL] Encode failed (rc=%d)\n", rc); return 1;
    }

    // 3. 다양한 에러 패턴 테스트
    for (errors = 0; errors <= MAX_ERRORS; errors++) {
        memcpy(w_prime, w, TEST_WLEN);
        // errors개 비트 반전
        for (i = 0; i < errors; i++) {
            /* Flip distinct bits in w_prime (no wrap/cancellation) */
            int pos = i;
            int byte = pos / 8;
            int bit = pos % 8;
            w_prime[byte] ^= (1 << bit);
        }
        rc = code_offset_decode(w_prime, TEST_WLEN, helper, pk, sk, key_recov, TEST_KEY_LEN);
        int match = (rc == 0 && memcmp(key_orig, key_recov, TEST_KEY_LEN) == 0);
        if (errors <= EXPECTED_MAX_OK) {
            if (match) {
                printf("[OK] errors=%2d: key match\n", errors); success++;
            } else {
                printf("[FAIL] errors=%2d: expected success (rc=%d)\n", errors, rc); fail++;
            }
        } else {
            if (!match) {
                printf("[OK] errors=%2d: expected failure (rc=%d)\n", errors, rc); success++;
            } else {
                printf("[FAIL] errors=%2d: unexpected success beyond capability\n", errors);
                fail++;
            }
        }
    }
    printf("\nSummary: %d success, %d fail\n", success, fail);
    return (fail == 0) ? 0 : 1;
}
