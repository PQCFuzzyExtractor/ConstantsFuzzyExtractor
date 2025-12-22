// SPDX-License-Identifier: MIT
#ifndef FUZZY_EXTRACTOR_H
#define FUZZY_EXTRACTOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MCELIECE_348864F_PUBLIC_KEY_LEN 261120
#define MCELIECE_348864F_SECRET_KEY_LEN 6492
#define MCELIECE_348864F_CIPHERTEXT_LEN 96
#define MCELIECE_348864F_SHARED_SECRET_LEN 32

int fuzzy_generate_key(uint8_t *key_out, size_t key_len,
                       uint8_t *ciphertext_out,
                       uint8_t *public_key_out, uint8_t *secret_key_out);

int fuzzy_reconstruct_key(uint8_t *key_out, size_t key_len,
                          const uint8_t *ciphertext, const uint8_t *secret_key);

void secure_memzero(void *v, size_t n);

int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t n);

/* McEliece KEM adapter (ECC-like encode/decode facade).
 *
 * This is NOT BCH. The API shape is similar to BCH-style fuzzy extractors
 * (helper data + key) but it is backed by Classic McEliece KEM.
 */
int mceliece_kem_encode_like(const uint8_t *w, size_t wlen,
                            uint8_t *helper_out, /* helper_out length should be MCELIECE_348864F_CIPHERTEXT_LEN */
                            uint8_t *public_key_out, uint8_t *secret_key_out,
                            uint8_t *key_out, size_t key_len);

int mceliece_kem_decode_like(const uint8_t *wprime, size_t wlen,
                            const uint8_t *helper, const uint8_t *secret_key,
                            uint8_t *key_out, size_t key_len);

/* Code-Offset API: uses McEliece low-level Niederreiter encrypt/decrypt
 * and the internal Goppa decoder to implement a code-offset style
 * helper-data method. Helper data length is MCELIECE_348864F_CIPHERTEXT_LEN.
 */
int code_offset_encode(const uint8_t *w, size_t wlen,
                       uint8_t *helper_out,
                       uint8_t *public_key_out, uint8_t *secret_key_out,
                       uint8_t *key_out, size_t key_len);

int code_offset_decode(const uint8_t *wprime, size_t wlen,
                       const uint8_t *helper, const uint8_t *public_key, const uint8_t *secret_key,
                       uint8_t *key_out, size_t key_len);
#ifdef __cplusplus
}
#endif

#endif
