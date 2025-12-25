// SPDX-License-Identifier: MIT

#include "../fuzzy_extractor.h"

#include <stddef.h>
#include <stdint.h>

void secure_memzero(void *v, size_t n) {
    if (v == NULL || n == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) {
        *p++ = 0;
    }
}

int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    if (a == NULL || b == NULL) return 0;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}
