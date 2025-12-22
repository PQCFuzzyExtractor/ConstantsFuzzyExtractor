// SPDX-License-Identifier: MIT
#ifndef FUZZY_OQS_PQCLEAN_DECLS_H
#define FUZZY_OQS_PQCLEAN_DECLS_H

#include <stdint.h>

/* Provided by liboqs (PQClean Classic McEliece 348864f clean). */
extern int PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* Low-level Niederreiter decoder (from PQClean). */
extern int PQCLEAN_MCELIECE348864F_CLEAN_decrypt(unsigned char *e, const unsigned char *sk, const unsigned char *c);

#endif
