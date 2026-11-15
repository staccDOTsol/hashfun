// Qwencoin's work function. This file is exec/qwork.h of https://github.com/staccDOTsol/qwencoin at
// commit 444dfff2548cd722807db4c1ee0a5b2c04750033, unchanged below this note (Apache-2.0, see that
// repository's LICENSE). hashfun uses it to check the proof of work of the Qwencoin headers a
// launch is told about (src/launchyield.h); it must stay bit for bit what Qwencoin's own node runs.

/* The work function of the chain: a pass through the MLP matrices of Qwen3.5-0.8B.
 *
 * Table (qwork.bin, built by `python -m hashformer.work build`): for each of the model's 24
 * layers its gate_proj and up_proj (3584 x 1024) and down_proj (1024 x 3584), every weight w
 * as the 16-bit integer rint(4096 w). 528 MB.
 *
 *   seed   h0 = SHA256d(block header with nNonce = 0)            (the caller's SHA-256)
 *   x      1024 values of +-1 expanded from (h0, nonce)          (qwork_expand)
 *   layer  a = sgn(G x) * sgn(U x)   3584 values;   x = sgn(D a)        sgn(v) = +1 if v > 0 else -1
 *   out    the 1024 signs after the last layer, packed, folded to 32 bytes by XOR
 *
 * The proof-of-work value of a header is SHA256(out XOR h0). All arithmetic is on integers:
 * every implementation agrees bit for bit, in any order of summation.
 */
#ifndef QWORK_H
#define QWORK_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int layers, n, m;        /* 24, 1024, 3584 */
    const int16_t *data;     /* per layer: G (m x n), U (m x n), D (n x m), row-major */
    size_t bytes;            /* size of the mapped file */
    uint64_t fnv;            /* checksum of the whole file (qwork_fnv64) */
    void *map;
} qwork_table;

/* Maps the table read-only and checks its header. Returns 0, or a negative error. */
int qwork_open(const char *path, qwork_table *t);
void qwork_close(qwork_table *t);
/* FNV-1a over the file's little-endian 64-bit words. */
uint64_t qwork_fnv64(const unsigned char *p, size_t bytes);
/* The start state: n values of +1 / -1 from the seed and the nonce. */
void qwork_expand(const unsigned char h0[32], uint32_t nonce, int16_t *x, int n);
/* The whole pass. out: 32 bytes. Uses up to `layers` layers (0: all). */
void qwork_eval(const qwork_table *t, const unsigned char h0[32], uint32_t nonce, unsigned char out[32]);

#ifdef __cplusplus
}
#endif
#endif
