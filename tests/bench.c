#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "slimiron.h"

#define DATA_SIZE (1024 * 1024 * 16)
#define WARMUP 3
#define ITER   50

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(void) {
    uint8_t *msg    = malloc(DATA_SIZE);
    uint8_t *cipher = malloc(DATA_SIZE);
    uint8_t *out    = malloc(DATA_SIZE);
    uint8_t  snonce[12], tag[16], key[32], nonce[12];
    if (!msg || !cipher || !out) { fprintf(stderr,"malloc failed\n"); return 1; }
    for (int i=0;i<DATA_SIZE;i++) msg[i]=rand();
    for (int i=0;i<32;i++) key[i]=rand();
    for (int i=0;i<12;i++) nonce[i]=rand();

    printf("Slimiron v0.3.0 benchmark\n");
    printf("Data size : %d MB | Warmup: %d | Measured: %d\n",
           DATA_SIZE/(1024*1024), WARMUP, ITER);
    printf("Stream rounds       : %d  (raised from 10 in v0.3.0)\n", SLIMIRON_ROUNDS);
    printf("SIMAC rounds        : %d\n", SIMAC_ROUNDS);
    printf("SIMAC rate/capacity : %d/%d bytes\n", SIMAC_RATE_BYTES, 64-SIMAC_RATE_BYTES);
    printf("SIV mode            : enabled (+1 SIMAC pass over plaintext)\n");
    printf("Wire overhead       : %u bytes\n", SLIMIRON_OVERHEAD);
#if SLIM_HAS_AVX2
    printf("XOR path            : AVX2\n\n");
#else
    printf("XOR path            : scalar (unrolled 8x8)\n\n");
#endif

    /* Warmup encrypt */
    for (int i=0;i<WARMUP;i++)
        slimiron_aead_encrypt(snonce, cipher, tag, msg, DATA_SIZE, NULL, 0, key, nonce);

    double t0 = now();
    for (int i=0;i<ITER;i++)
        slimiron_aead_encrypt(snonce, cipher, tag, msg, DATA_SIZE, NULL, 0, key, nonce);
    double enc_time = now() - t0;

    /* Final encrypt to get valid tag for decrypt bench */
    slimiron_aead_encrypt(snonce, cipher, tag, msg, DATA_SIZE, NULL, 0, key, nonce);

    /* Warmup decrypt */
    for (int i=0;i<WARMUP;i++)
        slimiron_aead_decrypt(out, snonce, cipher, DATA_SIZE, tag, NULL, 0, key,
                              SLIMIRON_WIRE_VERSION);

    double t1 = now();
    for (int i=0;i<ITER;i++)
        slimiron_aead_decrypt(out, snonce, cipher, DATA_SIZE, tag, NULL, 0, key,
                              SLIMIRON_WIRE_VERSION);
    double dec_time = now() - t1;

    double enc_mb = (double)DATA_SIZE*ITER/enc_time/(1024.0*1024.0);
    double dec_mb = (double)DATA_SIZE*ITER/dec_time/(1024.0*1024.0);

    printf("Encrypt : %7.2f MB/s  (%.3f s total, %.2f ms/call)\n",
           enc_mb, enc_time, enc_time/ITER*1000.0);
    printf("Decrypt : %7.2f MB/s  (%.3f s total, %.2f ms/call)\n",
           dec_mb, dec_time, dec_time/ITER*1000.0);
    printf("\nIntegrity: %s\n", memcmp(msg,out,DATA_SIZE)==0?"OK":"FAIL");

    free(msg); free(cipher); free(out);
    return 0;
}
