// Qwencoin's work function. This file is exec/qwork.c of https://github.com/staccDOTsol/qwencoin at
// commit 444dfff2548cd722807db4c1ee0a5b2c04750033, unchanged below this note (Apache-2.0, see that
// repository's LICENSE). hashfun uses it to check the proof of work of the Qwencoin headers a
// launch is told about (src/launchyield.h); it must stay bit for bit what Qwencoin's own node runs.

/* See qwork.h. Plain C that is also valid C++ (the node compiles it as crypto/qwork.cpp); the dot
 * products are written so that the compiler turns them into 16-bit multiply-add instructions
 * (pmaddwd and its wider forms). That needs the vectorizer, which -O2 does not always run. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize("O3")
#endif
#include "qwork.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define QWORK_HEADER 24

static uint64_t le64(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}
static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

uint64_t qwork_fnv64(const unsigned char *p, size_t bytes) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i + 8 <= bytes; i += 8) h = (h ^ le64(p + i)) * 0x100000001b3ULL;
    return h;
}

int qwork_open(const char *path, qwork_table *t) {
    memset(t, 0, sizeof *t);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < QWORK_HEADER) { close(fd); return -2; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return -3;
    const unsigned char *p = (const unsigned char *)m;
    t->map = m;
    t->bytes = (size_t)st.st_size;
    t->layers = (int)le32(p + 8);
    t->n = (int)le32(p + 12);
    t->m = (int)le32(p + 16);
    size_t want = QWORK_HEADER + (size_t)t->layers * 3 * (size_t)t->n * (size_t)t->m * 2;
    if (memcmp(p, "QWRK1\0\0\0", 8) != 0 || t->layers <= 0 || t->n <= 0 || t->m <= 0 || t->n % 64 != 0 ||
        want != t->bytes || t->bytes % 8 != 0) {
        qwork_close(t);
        return -4;
    }
    t->data = (const int16_t *)(p + QWORK_HEADER);
    t->fnv = qwork_fnv64(p, t->bytes);
    return 0;
}

void qwork_close(qwork_table *t) {
    if (t->map) munmap(t->map, t->bytes);
    memset(t, 0, sizeof *t);
}

static uint64_t rotl(uint64_t x, int k) { return x << k | x >> (64 - k); }
static uint64_t mix64(uint64_t z) {
    z ^= z >> 30; z *= 0xBF58476D1CE4E5B9ULL;
    z ^= z >> 27; z *= 0x94D049BB133111EBULL;
    return z ^ z >> 31;
}

void qwork_expand(const unsigned char h0[32], uint32_t nonce, int16_t *x, int n) {
    uint64_t a = le64(h0) ^ ((uint64_t)nonce << 32 | nonce);
    uint64_t s[4] = {mix64(a), mix64(le64(h0 + 8) + a), mix64(le64(h0 + 16) ^ rotl(a, 21)), mix64(le64(h0 + 24) + rotl(a, 42))};
    if (!(s[0] | s[1] | s[2] | s[3])) s[0] = 1;
    for (int w = 0; w < n / 64; w++) { /* xoshiro256** */
        uint64_t r = rotl(s[1] * 5, 7) * 9, tt = s[1] << 17;
        s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= tt; s[3] = rotl(s[3], 45);
        for (int b = 0; b < 64; b++) x[64 * w + b] = (r >> b & 1) ? 1 : -1;
    }
}

#if defined(__x86_64__) && defined(__GNUC__) && !defined(__clang__) && defined(__linux__)
#define QWORK_CLONES __attribute__((target_clones("arch=x86-64-v4", "avx2", "default")))
#else
#define QWORK_CLONES
#endif
#if defined(__GNUC__) || defined(__clang__)
#define QW_RESTRICT __restrict__
#else
#define QW_RESTRICT
#endif

/* y[r] = sum_c w[r][c] * x[c] over `rows` rows of `cols` 16-bit weights; x is +-1. */
QWORK_CLONES
static void matvec(const int16_t *QW_RESTRICT w, const int16_t *QW_RESTRICT x, int32_t *QW_RESTRICT y, int rows, int cols) {
    for (int r = 0; r < rows; r++) {
        const int16_t *QW_RESTRICT row = w + (size_t)r * cols;
        int32_t s = 0;
        for (int c = 0; c < cols; c++) s += (int32_t)row[c] * (int32_t)x[c];
        y[r] = s;
    }
}

void qwork_eval(const qwork_table *t, const unsigned char h0[32], uint32_t nonce, unsigned char out[32]) {
    const int n = t->n, m = t->m;
    int16_t *x = (int16_t *)malloc(sizeof(int16_t) * (size_t)(n + m));
    int32_t *g = (int32_t *)malloc(sizeof(int32_t) * (size_t)(2 * m + n));
    int16_t *a = x + n;
    int32_t *u = g + m, *d = g + 2 * m;
    qwork_expand(h0, nonce, x, n);
    const size_t mat = (size_t)n * m;
    for (int l = 0; l < t->layers; l++) {
        const int16_t *G = t->data + (size_t)l * 3 * mat, *U = G + mat, *D = U + mat;
        matvec(G, x, g, m, n);
        matvec(U, x, u, m, n);
        for (int k = 0; k < m; k++) a[k] = ((g[k] > 0) == (u[k] > 0)) ? 1 : -1;
        matvec(D, a, d, n, m);
        for (int j = 0; j < n; j++) x[j] = d[j] > 0 ? 1 : -1;
    }
    memset(out, 0, 32);
    for (int j = 0; j < n; j++)
        if (x[j] > 0) out[(j / 8) % 32] ^= (unsigned char)(1u << (j % 8));
    free(x);
    free(g);
}
