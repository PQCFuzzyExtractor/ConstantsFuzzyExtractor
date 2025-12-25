// SPDX-License-Identifier: MIT
/*
 * Fuzzy Extractor (McEliece 348864f) - umbrella compilation unit
 *
 * Goal: keep build commands simple (compile this one .c) while keeping
 * the implementation structured by responsibility.
 *
 * Public API: fuzzy/fuzzy_extractor.h
 * Modules:    fuzzy/src/*.c and fuzzy/src/*.h
 */

#include "fuzzy_extractor.h"

/* Utilities (constant-time compare, memzero). */
#include "src/ct_util.c"

/* KEM wrapper functions (keypair/enc/dec). */
#include "src/kem_wrapper.c"

/* McEliece KEM adapter API (legacy-compatible facade). */
#include "src/mceliece_kem_like.c"

/* Code-offset fuzzy extractor using Niederreiter decrypt + SHAKE256. */
#include "src/code_offset.c"

/* All implementations live in the included modules. */
