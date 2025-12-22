// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../fuzzy_extractor.h"

/* Direct PQClean symbols (exported from liboqs in this workspace build) */
extern int PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern void PQCLEAN_MCELIECE348864F_CLEAN_encrypt(unsigned char *s, const unsigned char *pk, unsigned char *e);
extern int PQCLEAN_MCELIECE348864F_CLEAN_decrypt(unsigned char *e, const unsigned char *sk, const unsigned char *c);

#define SYS_N_BYTES (3488 / 8)

int main(void) {
    uint8_t pk[MCELIECE_348864F_PUBLIC_KEY_LEN];
    uint8_t sk[MCELIECE_348864F_SECRET_KEY_LEN];
    uint8_t c[MCELIECE_348864F_CIPHERTEXT_LEN];
    uint8_t e1[SYS_N_BYTES];
    uint8_t e2[SYS_N_BYTES];

    int rc = PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pk, sk);
    if (rc != 0) {
        printf("keypair rc=%d\n", rc);
        return 1;
    }

    PQCLEAN_MCELIECE348864F_CLEAN_encrypt(c, pk, e1);

    const unsigned char *sk_n = (const unsigned char *)sk + 40;
    rc = PQCLEAN_MCELIECE348864F_CLEAN_decrypt(e2, sk_n, c);

    int same = (memcmp(e1, e2, SYS_N_BYTES) == 0);

    printf("decrypt rc=%d, e_match=%d, c0=%02x, e1_0=%02x, e2_0=%02x\n",
           rc, same, (unsigned)c[0], (unsigned)e1[0], (unsigned)e2[0]);

    /* Also test decrypt on an all-zero syndrome (should decode to e=0 if
     * the decoder supports <= SYS_T errors, including 0). */
    memset(c, 0, sizeof(c));
    memset(e2, 0xA5, sizeof(e2));
    int rc_zero = PQCLEAN_MCELIECE348864F_CLEAN_decrypt(e2, sk_n, c);
    int e2_is_zero = 1;
    for (size_t i = 0; i < sizeof(e2); i++) {
        if (e2[i] != 0) { e2_is_zero = 0; break; }
    }
    printf("decrypt(c=0) rc=%d, e_is_zero=%d\n", rc_zero, e2_is_zero);

    return (rc == 0 && same && rc_zero == 0 && e2_is_zero) ? 0 : 2;
}
