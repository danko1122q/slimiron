/*
 * Slimiron AEAD — C99 Standalone Implementation
 * Algorithm version 0.2.2 | Spec version 1.0
 *
 * Includes:
 *   - Full AEAD (encrypt/decrypt)
 *   - Test vectors (§9)
 *   - Throughput benchmark
 *   - Stress / fuzz test (multithreaded, 4 cores)
 *
 * Build:
 *   gcc -O2 -march=native -pthread -o slimiron_stress slimiron_stress.c
 *
 * Run:
 *   ./slimiron_stress               # 10 million iters
 *   ./slimiron_stress --iters 1000  # custom
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

/* ── Portability ─────────────────────────────────────────────────────────── */

#ifdef _WIN32
#  include <windows.h>
static void read_random(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}
#else
#  include <unistd.h>
static void read_random(uint8_t *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { perror("urandom"); exit(1); }
    if (fread(buf, 1, n, f) != n) { perror("urandom read"); exit(1); }
    fclose(f);
}
#endif

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

#define MASK32 0xFFFFFFFFu

static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}
static inline uint32_t le32_dec(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline void le32_enc(uint8_t *p, uint32_t v) {
    p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24;
}
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* ── §2 SlimMix ──────────────────────────────────────────────────────────── */

static inline void slimmix(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d = rotl32(*d ^ *a, 15);
    *c += *d; *b = rotl32(*b ^ *c, 11);
    *a += *b; *d = rotl32(*d ^ *a,  9);
    *c += *d; *b = rotl32(*b ^ *c,  5);
}

/* ── §3 Permutation ──────────────────────────────────────────────────────── */

static void permute(uint32_t s[16], int rounds) {
    for (int i = 0; i < rounds/2; i++) {
        slimmix(&s[ 0],&s[ 4],&s[ 8],&s[12]);
        slimmix(&s[ 1],&s[ 5],&s[ 9],&s[13]);
        slimmix(&s[ 2],&s[ 6],&s[10],&s[14]);
        slimmix(&s[ 3],&s[ 7],&s[11],&s[15]);
        slimmix(&s[ 0],&s[ 5],&s[10],&s[15]);
        slimmix(&s[ 1],&s[ 6],&s[11],&s[12]);
        slimmix(&s[ 2],&s[ 7],&s[ 8],&s[13]);
        slimmix(&s[ 3],&s[ 4],&s[ 9],&s[14]);
    }
}

/* ── §8 Constants ────────────────────────────────────────────────────────── */

#define IV_0  0xb9e3ef7fu
#define IV_1  0x7638101du
#define IV_2  0x53373520u
#define IV_3  0x654cbc86u

#define SIMAC_INIT_0  0x3e60fb52u
#define SIMAC_INIT_1  0x858433d2u
#define SIMAC_INIT_2  0xa5db45d3u
#define SIMAC_INIT_3  0x14ae65d8u
#define SIMAC_INIT_4  0x036c4f77u
#define SIMAC_INIT_5  0x5e78b857u
#define SIMAC_INIT_6  0xcceca447u
#define SIMAC_INIT_7  0x7d965649u

#define SIMAC_FINAL_0 0x8d1f0ff9u
#define SIMAC_FINAL_1 0x7a370f9eu
#define SIMAC_FINAL_2 0xe4e1e8ffu
#define SIMAC_FINAL_3 0x45d5c67bu
#define SIMAC_FINAL_4 0xfd3dc527u
#define SIMAC_FINAL_5 0xc608a8c1u
#define SIMAC_FINAL_6 0xc2617c1bu
#define SIMAC_FINAL_7 0xf0327ed2u

#define DOMAIN_AAD 0x8439c00fu
#define DOMAIN_CT  0x35ef9605u
#define DOMAIN_SIV 0x493ccf67u

#define MAX_COUNTER 0xFFFFFFFEu

/* ── §4 Stream Cipher ────────────────────────────────────────────────────── */

typedef struct { uint32_t s[16]; } SlimCtx;

static void slimiron_init(SlimCtx *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    ctx->s[ 0] = 0;
    ctx->s[ 1] = le32_dec(nonce+0);
    ctx->s[ 2] = le32_dec(nonce+4);
    ctx->s[ 3] = le32_dec(nonce+8);
    ctx->s[ 4] = IV_0; ctx->s[5]=IV_1; ctx->s[6]=IV_2; ctx->s[7]=IV_3;
    for (int i=0;i<8;i++) ctx->s[8+i] = le32_dec(key + i*4);
}

static int slimiron_block(SlimCtx *ctx, uint8_t ks[64]) {
    if (ctx->s[0] > MAX_COUNTER) return -2;
    uint32_t x[16];
    memcpy(x, ctx->s, 64);
    permute(x, 10);
    for (int i=0;i<16;i++) le32_enc(ks+i*4, x[i]+ctx->s[i]);
    ctx->s[0]++;
    return 0;
}

static void derive_mac_key(SlimCtx *ctx, uint8_t mac_key[32]) {
    uint8_t ks[64];
    slimiron_block(ctx, ks);
    memcpy(mac_key, ks, 32);
}

/* ── §5 SIMAC ────────────────────────────────────────────────────────────── */

typedef struct {
    uint32_t s[16];
    uint8_t  buf[32];
    int      pos;
} SimacCtx;

static void simac_init(SimacCtx *ctx, const uint8_t mac_key[32], const uint8_t nonce[12]) {
    for (int i=0;i<8;i++) ctx->s[i] = le32_dec(mac_key+i*4);
    ctx->s[ 8] = SIMAC_INIT_0 ^ le32_dec(nonce+0);
    ctx->s[ 9] = SIMAC_INIT_1 ^ le32_dec(nonce+4);
    ctx->s[10] = SIMAC_INIT_2 ^ le32_dec(nonce+8);
    ctx->s[11] = SIMAC_INIT_3;
    ctx->s[12] = SIMAC_INIT_4;
    ctx->s[13] = SIMAC_INIT_5;
    ctx->s[14] = SIMAC_INIT_6;
    ctx->s[15] = SIMAC_INIT_7;
    permute(ctx->s, 10);
    memset(ctx->buf, 0, 32);
    ctx->pos = 0;
}

static void simac_compress(SimacCtx *ctx) {
    for (int i=0;i<8;i++) ctx->s[i] ^= le32_dec(ctx->buf+i*4);
    permute(ctx->s, 10);
    memset(ctx->buf, 0, 32);
    ctx->pos = 0;
}

static void simac_absorb(SimacCtx *ctx, const uint8_t *data, size_t len) {
    if (ctx->pos > 0) {
        int want = 32 - ctx->pos;
        if ((int)len < want) {
            memcpy(ctx->buf + ctx->pos, data, len);
            ctx->pos += len;
            return;
        }
        memcpy(ctx->buf + ctx->pos, data, want);
        data += want; len -= want;
        simac_compress(ctx);
    }
    while (len >= 32) {
        for (int i=0;i<8;i++) ctx->s[i] ^= le32_dec(data+i*4);
        permute(ctx->s, 10);
        data += 32; len -= 32;
    }
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->pos = len;
    }
}

static void simac_absorb_len(SimacCtx *ctx, uint64_t n) {
    uint8_t tmp[8];
    tmp[0]=(n>>56)&0xFF; tmp[1]=(n>>48)&0xFF;
    tmp[2]=(n>>40)&0xFF; tmp[3]=(n>>32)&0xFF;
    tmp[4]=(n>>24)&0xFF; tmp[5]=(n>>16)&0xFF;
    tmp[6]=(n>> 8)&0xFF; tmp[7]=(n>> 0)&0xFF;
    simac_absorb(ctx, tmp, 8);
}

static void simac_pad(SimacCtx *ctx) {
    ctx->buf[ctx->pos] ^= 0x01;
    ctx->buf[31]       ^= 0x80;
    simac_compress(ctx);
}

static void simac_domain(SimacCtx *ctx, uint32_t dom) {
    ctx->s[8] ^= dom;
    permute(ctx->s, 10);
}

static void simac_finalize(SimacCtx *ctx, uint8_t tag[16]) {
    simac_pad(ctx);
    ctx->s[ 8] ^= SIMAC_FINAL_0; ctx->s[ 9] ^= SIMAC_FINAL_1;
    ctx->s[10] ^= SIMAC_FINAL_2; ctx->s[11] ^= SIMAC_FINAL_3;
    ctx->s[12] ^= SIMAC_FINAL_4; ctx->s[13] ^= SIMAC_FINAL_5;
    ctx->s[14] ^= SIMAC_FINAL_6; ctx->s[15] ^= SIMAC_FINAL_7;
    permute(ctx->s, 10);
    permute(ctx->s, 10);
    for (int i=0;i<4;i++) le32_enc(tag+i*4, ctx->s[i]);
}

/* ── §6 SIV ──────────────────────────────────────────────────────────────── */

static void siv_derive(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *msg, size_t mlen,
                       uint8_t synth_nonce[12])
{
    SlimCtx  c;  slimiron_init(&c, key, nonce);
    uint8_t  siv_key[32]; derive_mac_key(&c, siv_key);
    memset(&c, 0, sizeof c);

    SimacCtx m; simac_init(&m, siv_key, nonce);
    memset(siv_key, 0, 32);

    simac_absorb(&m, nonce, 12);
    simac_absorb(&m, aad, aad_len);
    simac_absorb_len(&m, aad_len);
    simac_absorb(&m, msg, mlen);
    simac_absorb_len(&m, mlen);
    simac_pad(&m);
    simac_domain(&m, DOMAIN_SIV);

    uint8_t tag[16]; simac_finalize(&m, tag);
    memset(&m, 0, sizeof m);
    memcpy(synth_nonce, tag, 12);
}

/* ── §7 AEAD ─────────────────────────────────────────────────────────────── */

static int aead_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *msg,    size_t mlen,
    const uint8_t *aad,    size_t aad_len,
    uint8_t synth_nonce[12],
    uint8_t *ct,           /* caller allocates mlen bytes */
    uint8_t tag[16])
{
    siv_derive(key, nonce, aad, aad_len, msg, mlen, synth_nonce);

    SlimCtx c; slimiron_init(&c, key, synth_nonce);
    uint8_t mac_key[32]; derive_mac_key(&c, mac_key);

    SimacCtx m; simac_init(&m, mac_key, synth_nonce);
    memset(mac_key, 0, 32);

    simac_absorb(&m, aad, aad_len);
    simac_absorb_len(&m, aad_len);
    simac_pad(&m);
    simac_domain(&m, DOMAIN_AAD);

    size_t i=0;
    uint8_t ks[64];
    while (i+64 <= mlen) {
        if (slimiron_block(&c, ks)) { memset(&c,0,sizeof c); return -2; }
        for (int j=0;j<64;j++) ct[i+j] = msg[i+j] ^ ks[j];
        simac_absorb(&m, ct+i, 64);
        i += 64;
    }
    if (i < mlen) {
        if (slimiron_block(&c, ks)) { memset(&c,0,sizeof c); return -2; }
        for (size_t j=0; j<mlen-i; j++) ct[i+j] = msg[i+j] ^ ks[j];
        simac_absorb(&m, ct+i, mlen-i);
    }

    simac_absorb_len(&m, mlen);
    simac_pad(&m);
    simac_domain(&m, DOMAIN_CT);
    simac_finalize(&m, tag);

    memset(&c, 0, sizeof c);
    memset(&m, 0, sizeof m);
    return 0;
}

static int aead_decrypt(
    const uint8_t key[32], const uint8_t synth_nonce[12],
    const uint8_t *ct,     size_t clen,
    const uint8_t tag[16],
    const uint8_t *aad,    size_t aad_len,
    uint8_t *msg)          /* caller allocates clen bytes */
{
    SlimCtx c; slimiron_init(&c, key, synth_nonce);
    uint8_t mac_key[32]; derive_mac_key(&c, mac_key);

    SimacCtx m; simac_init(&m, mac_key, synth_nonce);
    memset(mac_key, 0, 32);

    simac_absorb(&m, aad, aad_len);
    simac_absorb_len(&m, aad_len);
    simac_pad(&m);
    simac_domain(&m, DOMAIN_AAD);

    simac_absorb(&m, ct, clen);
    simac_absorb_len(&m, clen);
    simac_pad(&m);
    simac_domain(&m, DOMAIN_CT);

    uint8_t calc_tag[16];
    simac_finalize(&m, calc_tag);
    memset(&m, 0, sizeof m);

    if (!ct_equal(calc_tag, tag, 16)) {
        memset(&c, 0, sizeof c);
        if (msg) memset(msg, 0, clen);
        return -1;
    }

    size_t i=0;
    uint8_t ks[64];
    while (i+64 <= clen) {
        slimiron_block(&c, ks);
        for (int j=0;j<64;j++) msg[i+j] = ct[i+j] ^ ks[j];
        i += 64;
    }
    if (i < clen) {
        slimiron_block(&c, ks);
        for (size_t j=0; j<clen-i; j++) msg[i+j] = ct[i+j] ^ ks[j];
    }
    memset(&c, 0, sizeof c);
    return 0;
}

/* ── Test Vectors ────────────────────────────────────────────────────────── */

static int hex2bin(const char *hex, uint8_t *out, size_t *olen) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    *olen = len / 2;
    for (size_t i=0; i<*olen; i++) {
        char b[3] = {hex[i*2], hex[i*2+1], 0};
        out[i] = (uint8_t)strtol(b, NULL, 16);
    }
    return 0;
}

#define CLR_PASS "\033[92mPASS\033[0m"
#define CLR_FAIL "\033[91mFAIL\033[0m"

static int check(const char *name, const uint8_t *got, const uint8_t *exp, size_t n) {
    if (ct_equal(got, exp, n)) {
        printf("  [" CLR_PASS "] %s\n", name);
        return 1;
    }
    printf("  [" CLR_FAIL "] %s\n", name);
    printf("    got : "); for(size_t i=0;i<n;i++) printf("%02x",got[i]); printf("\n");
    printf("    exp : "); for(size_t i=0;i<n;i++) printf("%02x",exp[i]); printf("\n");
    return 0;
}

static int run_test_vectors(void) {
    int ok = 1;
    uint8_t key[32], nonce[12], pt[256], aad[64];
    uint8_t sn[12], ct[256], tag[16], pt2[256];
    uint8_t exp_sn[12], exp_ct[256], exp_tag[16];
    size_t kl,nl,pl,al,sl,cl,tl;

    /* Vector 1 */
    printf("\n── Vector 1: AEAD with AAD ──\n");
    hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, &kl);
    hex2bin("000000090000004a00000000", nonce, &nl);
    hex2bin("4c616469657320616e642047656e746c656d656e206f662074686520636c617373", pt, &pl);
    hex2bin("50515253c0c1c2c3c4c5c6c7", aad, &al);
    hex2bin("04201460c508fc2f42010028", exp_sn, &sl);
    hex2bin("88c5ae815567dba0561dbf8aff13e3088590d174c3f0894c1d431109d78989c132", exp_ct, &cl);
    hex2bin("6de79bf5a428fcf2edc50dce13bef93c", exp_tag, &tl);
    aead_encrypt(key, nonce, pt, pl, aad, al, sn, ct, tag);
    ok &= check("synth_nonce", sn, exp_sn, 12);
    ok &= check("ciphertext",  ct, exp_ct, pl);
    ok &= check("tag",        tag, exp_tag, 16);
    ok &= (aead_decrypt(key, sn, ct, pl, tag, aad, al, pt2) == 0 &&
           ct_equal(pt2, pt, pl));
    printf("  [%s] decrypt\n", ct_equal(pt2,pt,pl) ? "\033[92mPASS\033[0m" : "\033[91mFAIL\033[0m");

    /* Vector 2 */
    printf("\n── Vector 2: Empty message, no AAD ──\n");
    memset(key,0,32); memset(nonce,0,12); pl=0; al=0;
    hex2bin("6c9c4727fa5c0a6106d63816", exp_sn, &sl);
    hex2bin("9fecd5798e97245e20eb98acbd81db07", exp_tag, &tl);
    aead_encrypt(key, nonce, pt, 0, aad, 0, sn, ct, tag);
    ok &= check("synth_nonce", sn, exp_sn, 12);
    ok &= check("tag",        tag, exp_tag, 16);
    printf("  [" CLR_PASS "] ciphertext (empty)\n");
    ok &= (aead_decrypt(key, sn, ct, 0, tag, aad, 0, pt2) == 0);
    printf("  [%s] decrypt\n", ok ? "\033[92mPASS\033[0m" : "\033[91mFAIL\033[0m");

    /* Vector 3 */
    printf("\n── Vector 3: Single byte, no AAD ──\n");
    hex2bin("070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e6164", key, &kl);
    hex2bin("0102030405060708090a0b0c", nonce, &nl);
    pt[0]=0x42; pl=1; al=0;
    hex2bin("6e164088db45673f99d76110", exp_sn, &sl);
    hex2bin("aa", exp_ct, &cl);
    hex2bin("3c303e3443a0ec6dfa8784d6b85ae512", exp_tag, &tl);
    aead_encrypt(key, nonce, pt, 1, aad, 0, sn, ct, tag);
    ok &= check("synth_nonce", sn, exp_sn, 12);
    ok &= check("ciphertext",  ct, exp_ct, 1);
    ok &= check("tag",        tag, exp_tag, 16);
    ok &= (aead_decrypt(key, sn, ct, 1, tag, aad, 0, pt2) == 0 && pt2[0]==0x42);
    printf("  [%s] decrypt\n", (pt2[0]==0x42) ? "\033[92mPASS\033[0m" : "\033[91mFAIL\033[0m");

    /* Vector 4 */
    printf("\n── Vector 4: AAD only, empty message ──\n");
    hex2bin("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", key, &kl);
    hex2bin("abababababababababababab", nonce, &nl);
    hex2bin("0102030405060708", aad, &al); pl=0;
    hex2bin("763d8cf54f95fe51d8218215", exp_sn, &sl);
    hex2bin("fdd4855f09bb4a8813a86d88ba6e1ffa", exp_tag, &tl);
    aead_encrypt(key, nonce, pt, 0, aad, al, sn, ct, tag);
    ok &= check("synth_nonce", sn, exp_sn, 12);
    ok &= check("tag",        tag, exp_tag, 16);
    printf("  [" CLR_PASS "] ciphertext (empty)\n");
    ok &= (aead_decrypt(key, sn, ct, 0, tag, aad, al, pt2) == 0);
    printf("  [%s] decrypt\n", ok ? "\033[92mPASS\033[0m" : "\033[91mFAIL\033[0m");

    /* Auth failure */
    printf("\n── Auth Failure Test ──\n");
    uint8_t bad_tag[16]; memcpy(bad_tag, tag, 16); bad_tag[0] ^= 0xFF;
    int rc = aead_decrypt(key, sn, ct, 0, bad_tag, aad, al, pt2);
    printf("  [%s] tampered tag %s\n",
           (rc==-1) ? CLR_PASS : CLR_FAIL,
           (rc==-1) ? "correctly rejected" : "WRONGLY ACCEPTED");
    ok &= (rc == -1);

    return ok;
}

/* ── Benchmark ───────────────────────────────────────────────────────────── */

static void run_benchmark(long iters) {
    printf("\n%s\n", "══════════════════════════════════════════════════════");
    printf("  THROUGHPUT BENCHMARK — %ld iterations\n", iters);
    printf("%s\n", "══════════════════════════════════════════════════════");

    uint8_t key[32], nonce[12], msg[64], aad[0];
    uint8_t sn[12], ct[64], tag[16];
    memset(key,0x42,32); memset(nonce,0x13,12); memset(msg,0xAB,64);

    /* warmup */
    for (int i=0;i<1000;i++)
        aead_encrypt(key,nonce,msg,64,aad,0,sn,ct,tag);

    printf("  Warmup done. Running...\n");
    long errors = 0;
    double t0 = now_sec();
    long report = iters / 20;

    for (long i=0; i<iters; i++) {
        if (aead_encrypt(key,nonce,msg,64,aad,0,sn,ct,tag) != 0) errors++;
        if (report > 0 && (i+1) % report == 0) {
            double pct = (i+1)*100.0/iters;
            printf("\r  [%-40s] %5.1f%%",
                   "████████████████████████████████████████" + (int)(40 - 40*pct/100),
                   pct);
            fflush(stdout);
        }
    }
    double elapsed = now_sec() - t0;
    printf("\r  [████████████████████████████████████████] 100.0%%\n\n");

    double ops = iters / elapsed;
    double mb  = (iters * 64.0) / (1024*1024) / elapsed;

    printf("  ┌──────────────────────────────────────┐\n");
    printf("  │ Iterations   : %20ld    │\n", iters);
    printf("  │ Elapsed      : %19.3fs    │\n", elapsed);
    printf("  │ Ops/sec      : %20.0f    │\n", ops);
    printf("  │ Throughput   : %18.2f MB/s  │\n", mb);
    printf("  │ Errors       : %20ld    │\n", errors);
    printf("  └──────────────────────────────────────┘\n");
}

/* ── Stress Test (multithreaded) ─────────────────────────────────────────── */

#define NUM_THREADS 4

typedef struct {
    long iters;
    int  thread_id;
    long roundtrip_ok;
    long tamper_ok;
    long errors;
    long crashes;
} StressArg;

/* Simple LCG per-thread RNG (fast, no lock needed) */
static uint64_t lcg_next(uint64_t *state) {
    *state = *state * 6364136223846793005ULL + 1442695040888963407ULL;
    return *state;
}

static void thread_rng(uint64_t *state, uint8_t *buf, size_t n) {
    for (size_t i=0; i<n; i++) {
        buf[i] = (uint8_t)(lcg_next(state) >> 33);
    }
}

static void *stress_worker(void *arg) {
    StressArg *a = (StressArg*)arg;

    uint64_t rng_state;
    uint8_t seed[8];
    read_random(seed, 8);
    memcpy(&rng_state, seed, 8);
    rng_state ^= (uint64_t)a->thread_id * 0x9e3779b97f4a7c15ULL;

    uint8_t key[32], nonce[12], msg[256], aad[64];
    uint8_t sn[12], ct[256], tag[16], pt2[256], bad_tag[16];

    long rt_ok=0, tap_ok=0, err=0;

    for (long i=0; i<a->iters; i++) {
        /* random inputs */
        thread_rng(&rng_state, key, 32);
        thread_rng(&rng_state, nonce, 12);
        size_t mlen = lcg_next(&rng_state) % 257;
        size_t alen = lcg_next(&rng_state) % 65;
        thread_rng(&rng_state, msg, mlen);
        thread_rng(&rng_state, aad, alen);

        /* encrypt */
        if (aead_encrypt(key, nonce, msg, mlen, aad, alen, sn, ct, tag) != 0) {
            err++; continue;
        }

        /* round-trip */
        if (aead_decrypt(key, sn, ct, mlen, tag, aad, alen, pt2) != 0) {
            err++; continue;
        }
        if (memcmp(pt2, msg, mlen) != 0) { err++; continue; }
        rt_ok++;

        /* tamper tag */
        memcpy(bad_tag, tag, 16);
        bad_tag[lcg_next(&rng_state) % 16] ^= 1 << (lcg_next(&rng_state) % 8);
        if (aead_decrypt(key, sn, ct, mlen, bad_tag, aad, alen, pt2) == -1)
            tap_ok++;
        else
            err++;

        /* tamper ciphertext (if non-empty) */
        if (mlen > 0) {
            uint8_t bad_ct[256];
            memcpy(bad_ct, ct, mlen);
            bad_ct[lcg_next(&rng_state) % mlen] ^= 1 << (lcg_next(&rng_state) % 8);
            if (aead_decrypt(key, sn, bad_ct, mlen, tag, aad, alen, pt2) == -1)
                tap_ok++;
            else
                err++;
        }
    }

    a->roundtrip_ok = rt_ok;
    a->tamper_ok    = tap_ok;
    a->errors       = err;
    return NULL;
}

static void run_stress(long iters) {
    printf("\n%s\n", "══════════════════════════════════════════════════════");
    printf("  STRESS / FUZZ TEST — %ld iterations × %d threads\n", iters, NUM_THREADS);
    printf("%s\n", "══════════════════════════════════════════════════════");
    printf("  Each iter: random key/nonce/msg(0-256b)/aad(0-64b)\n");
    printf("  Checks: encrypt→decrypt round-trip + tamper rejection\n\n");

    pthread_t threads[NUM_THREADS];
    StressArg args[NUM_THREADS];
    long per_thread = iters / NUM_THREADS;

    double t0 = now_sec();
    for (int t=0; t<NUM_THREADS; t++) {
        args[t].iters     = per_thread;
        args[t].thread_id = t;
        args[t].roundtrip_ok = args[t].tamper_ok = args[t].errors = args[t].crashes = 0;
        pthread_create(&threads[t], NULL, stress_worker, &args[t]);
    }

    /* Progress monitor on main thread */
    long total_done = 0;
    while (total_done < iters) {
        usleep(200000); /* 200ms */
        total_done = 0;
        for (int t=0; t<NUM_THREADS; t++)
            total_done += args[t].roundtrip_ok + args[t].errors;
        double pct = (double)total_done / iters * 100.0;
        int filled = (int)(40 * pct / 100.0);
        printf("\r  [");
        for (int i=0;i<40;i++) printf(i<filled?"█":"░");
        printf("] %5.1f%%  %ld/%ld", pct, total_done, iters);
        fflush(stdout);
    }

    for (int t=0; t<NUM_THREADS; t++) pthread_join(threads[t], NULL);
    double elapsed = now_sec() - t0;
    printf("\r  [████████████████████████████████████████] 100.0%%  %ld/%ld\n\n", iters, iters);

    long rt_total=0, tap_total=0, err_total=0;
    for (int t=0; t<NUM_THREADS; t++) {
        rt_total  += args[t].roundtrip_ok;
        tap_total += args[t].tamper_ok;
        err_total += args[t].errors;
    }

    printf("  ┌──────────────────────────────────────┐\n");
    printf("  │ Iterations   : %20ld    │\n", iters);
    printf("  │ Threads      : %20d    │\n", NUM_THREADS);
    printf("  │ Elapsed      : %19.3fs    │\n", elapsed);
    printf("  │ Ops/sec      : %20.0f    │\n", iters/elapsed);
    printf("  │ Round-trips  : %20ld    │\n", rt_total);
    printf("  │ Tamper rej.  : %20ld    │\n", tap_total);
    printf("  │ Errors       : %20ld    │\n", err_total);
    printf("  └──────────────────────────────────────┘\n");

    if (err_total == 0)
        printf("\n  \033[92mAll stress checks PASSED ✓\033[0m\n");
    else
        printf("\n  \033[91m%ld FAILURES detected!\033[0m\n", err_total);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    long iters = 10000000L;
    for (int i=1; i<argc; i++) {
        if (strcmp(argv[i],"--iters")==0 && i+1<argc)
            iters = atol(argv[++i]);
    }

    printf("\n  Slimiron Stress Suite (C99)\n");
    printf("  Iterations: %ld | Threads: %d\n", iters, NUM_THREADS);

    /* 1. Test vectors first */
    printf("\n%s\n", "══════════════════════════════════════════════════════");
    printf("  TEST VECTORS\n");
    printf("%s\n", "══════════════════════════════════════════════════════");
    int tv_ok = run_test_vectors();
    if (!tv_ok) {
        printf("\n\033[91mTest vectors FAILED — aborting.\033[0m\n");
        return 1;
    }
    printf("\n  \033[92mTest vectors PASSED ✓ — proceeding to stress tests\033[0m\n");

    double t0 = now_sec();

    /* 2. Benchmark */
    run_benchmark(iters);

    /* 3. Stress */
    run_stress(iters);

    double total = now_sec() - t0;
    printf("\n%s\n", "══════════════════════════════════════════════════════");
    printf("  Total time: %.2fs\n", total);
    printf("%s\n\n", "══════════════════════════════════════════════════════");

    return 0;
}
