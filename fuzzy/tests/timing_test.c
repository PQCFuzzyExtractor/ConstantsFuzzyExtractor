// SPDX-License-Identifier: MIT
// Timing test for Code-Offset fuzzy extractor decode across bit flips 0..63

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
static LARGE_INTEGER g_qpc_freq;
static void init_timer(void) {
    QueryPerformanceFrequency(&g_qpc_freq);
}
static double now_usec(void) {
    LARGE_INTEGER cnt;
    QueryPerformanceCounter(&cnt);
    return (double)cnt.QuadPart * 1e6 / (double)g_qpc_freq.QuadPart;
}
#else
#include <sys/time.h>
static void init_timer(void) { }
static double now_usec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1e6 + (double)tv.tv_usec;
}
#endif

#include "../fuzzy_extractor.h"

/* Parameters for Classic McEliece 348864f */
#define SYS_N_BITS 3488
#define SYS_N_BYTES (SYS_N_BITS / 8)

static void flip_distinct_bits(uint8_t *out, const uint8_t *in, int nbits, int flips) {
    memcpy(out, in, (size_t)(nbits / 8));
    if (flips <= 0) return;

    int *inds = (int *)malloc(sizeof(int) * (size_t)flips);
    if (!inds) {
        /* Fall back: deterministic first `flips` bits (best effort). */
        for (int i = 0; i < flips; i++) {
            int pos = i % nbits;
            out[pos / 8] ^= (uint8_t)(1u << (pos % 8));
        }
        return;
    }

    for (int i = 0; i < flips; i++) {
        int pos;
        int ok;
        do {
            pos = rand() % nbits;
            ok = 1;
            for (int j = 0; j < i; j++) {
                if (inds[j] == pos) { ok = 0; break; }
            }
        } while (!ok);
        inds[i] = pos;
        out[pos / 8] ^= (uint8_t)(1u << (pos % 8));
    }

    free(inds);
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

typedef struct {
    int errors;
    int attempts;
    double success_rate;
    double mean_us;
    double median_us;
    double p05_us;
    double p95_us;
    double stddev_us;
} timing_row_t;

static int cmp_row_errors(const void *a, const void *b) {
    const timing_row_t *ra = (const timing_row_t *)a;
    const timing_row_t *rb = (const timing_row_t *)b;
    return (ra->errors > rb->errors) - (ra->errors < rb->errors);
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    init_timer();

#ifdef _WIN32
    /* Reduce OS scheduling noise for timing experiments. */
    (void)SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    (void)SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    (void)SetThreadAffinityMask(GetCurrentThread(), 1);
#endif

    uint8_t *pk = (uint8_t *)malloc(MCELIECE_348864F_PUBLIC_KEY_LEN);
    uint8_t *sk = (uint8_t *)malloc(MCELIECE_348864F_SECRET_KEY_LEN);
    uint8_t *helper = (uint8_t *)malloc(MCELIECE_348864F_CIPHERTEXT_LEN);
    uint8_t *w = (uint8_t *)malloc(SYS_N_BYTES);
    uint8_t *wprime = (uint8_t *)malloc(SYS_N_BYTES);

    uint8_t key_ref[MCELIECE_348864F_SHARED_SECRET_LEN];
    uint8_t key_out[MCELIECE_348864F_SHARED_SECRET_LEN];

    if (!pk || !sk || !helper || !w || !wprime) { fprintf(stderr, "alloc fail\n"); return 2; }

    /* Fix a single enrollment sample `w` and corresponding helper/key. */
    for (int i = 0; i < SYS_N_BYTES; i++) w[i] = (uint8_t)(rand() & 0xFF);

    if (code_offset_encode(w, SYS_N_BYTES, helper, pk, sk, key_ref, MCELIECE_348864F_SHARED_SECRET_LEN) != 0) {
        fprintf(stderr, "code_offset_encode fail\n");
        return 3;
    }

    FILE *csv = fopen("timing_results.csv", "wb");
    FILE *out = csv ? csv : stdout;
    fprintf(out, "errors,attempts,success_rate,mean_us,median_us,p05_us,p95_us,stddev_us\n");
    fflush(out);

    int attempts = 100;
    if (argc >= 2) {
        int a = atoi(argv[1]);
        if (a > 0 && a <= 1000) attempts = a;
    }

    /* Global warm-up to stabilize caches/CPU state before measuring. */
    for (int t = 0; t < 50; t++) {
        int errors = rand() % 64;
        flip_distinct_bits(wprime, w, SYS_N_BITS, errors);
        (void)code_offset_decode(wprime, SYS_N_BYTES, helper, pk, sk, key_out, MCELIECE_348864F_SHARED_SECRET_LEN);
    }

    /* Measure in randomized order to reduce monotonic time-drift artifacts,
     * but sort output by errors for readability. */
    int order[64];
    for (int i = 0; i < 64; i++) order[i] = i;
    for (int i = 63; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }

    timing_row_t rows[64];
    for (int idx = 0; idx < 64; idx++) {
        int errors = order[idx];
        fprintf(stderr, "[progress] %d/64: measuring errors=%d (attempts=%d)\n", idx + 1, errors, attempts);
        fflush(stderr);
        int success = 0;
        double *times = malloc(sizeof(double) * (size_t)attempts);
        if (!times) { fprintf(stderr, "alloc fail\n"); return 2; }

        /* warm-up */
        for (int t = 0; t < 5; t++) {
            flip_distinct_bits(wprime, w, SYS_N_BITS, errors);
            (void)code_offset_decode(wprime, SYS_N_BYTES, helper, pk, sk, key_out, MCELIECE_348864F_SHARED_SECRET_LEN);
        }

        for (int t = 0; t < attempts; t++) {
            flip_distinct_bits(wprime, w, SYS_N_BITS, errors);
            double t0 = now_usec();
            int rc = code_offset_decode(wprime, SYS_N_BYTES, helper, pk, sk, key_out, MCELIECE_348864F_SHARED_SECRET_LEN);
            double t1 = now_usec();
            times[t] = t1 - t0;

            if (rc == 0 && constant_time_compare(key_ref, key_out, MCELIECE_348864F_SHARED_SECRET_LEN)) success++;
        }
        /* compute mean and stddev */
        double sum = 0.0;
        for (int i = 0; i < attempts; i++) sum += times[i];
        double mean = sum / attempts;
        double var = 0.0;
        for (int i = 0; i < attempts; i++) {
            double d = times[i] - mean; var += d*d;
        }
        double stddev = sqrt(var / attempts);

        qsort(times, (size_t)attempts, sizeof(double), cmp_double);
        double median = times[attempts / 2];
        int i05 = (int)floor(0.05 * (attempts - 1));
        int i95 = (int)ceil(0.95 * (attempts - 1));
        if (i05 < 0) i05 = 0;
        if (i95 < 0) i95 = 0;
        if (i05 >= attempts) i05 = attempts - 1;
        if (i95 >= attempts) i95 = attempts - 1;
        double p05 = times[i05];
        double p95 = times[i95];

        rows[idx].errors = errors;
        rows[idx].attempts = attempts;
        rows[idx].success_rate = (double)success / attempts;
        rows[idx].mean_us = mean;
        rows[idx].median_us = median;
        rows[idx].p05_us = p05;
        rows[idx].p95_us = p95;
        rows[idx].stddev_us = stddev;

        fprintf(stderr, "[progress] done errors=%d: success_rate=%.3f mean_us=%.3f stddev_us=%.3f\n",
            errors, rows[idx].success_rate, rows[idx].mean_us, rows[idx].stddev_us);
        fflush(stderr);

        free(times);
    }

    qsort(rows, 64, sizeof(rows[0]), cmp_row_errors);
    for (int i = 0; i < 64; i++) {
        fprintf(out, "%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
                rows[i].errors,
                rows[i].attempts,
                rows[i].success_rate,
                rows[i].mean_us,
                rows[i].median_us,
                rows[i].p05_us,
                rows[i].p95_us,
                rows[i].stddev_us);
    }
    fflush(out);

    if (csv) fclose(csv);
    free(pk); free(sk); free(helper); free(w); free(wprime);
    return 0;
}
