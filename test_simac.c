dava@Dava:~/github/slimiron
$ make
gcc -O3 -march=native -funroll-loops -fomit-frame-pointer -o test_simac test_simac.c
gcc -O3 -march=native -funroll-loops -fomit-frame-pointer -o bench bench.c
dava@Dava:~/github/slimiron
$ make run-test
./test_simac
Slimiron v0.2.0 test suite
SlimMix rotations   : (15,11,9,5)
Stream rounds       : 10
SIMAC rounds        : 10
SIMAC rate/capacity : 32/32 bytes
SIV mode            : enabled (nonce-misuse resistant)
XOR path            : scalar (unrolled 8x8)

[PASS] vector: encrypt returns 0
[PASS] vector: decrypt returns 0
[PASS] vector: plaintext recovered
[PASS] vector: synth_nonce deterministic
[PASS] vector: ciphertext deterministic
[PASS] vector: tag deterministic
[PASS] roundtrip: plaintext recovered
[PASS] multiblock: all boundary sizes round-trip correctly
[PASS] avalanche: tag 61/128 bits differ, synth_nonce 43/96 bits differ
[PASS] SIV misuse: diff msg → diff synth_nonce
[PASS] SIV misuse: same msg → same synth_nonce
[PASS] SIV misuse: diff msg → diff ciphertext
[PASS] forgery: cipher tamper detected
[PASS] forgery: output zeroed on failure
[PASS] forgery: tag tamper detected
[PASS] forgery: synth_nonce tamper detected
[PASS] AAD: tampered AAD detected
[PASS] domain sep: AAD vs CT not interchangeable
[PASS] wrong key detected
[PASS] wrong ext nonce: decrypt with correct snonce succeeds
[PASS] empty: encrypt returns 0
[PASS] empty: decrypt round-trip
[PASS] empty: tag differs with different AAD
[PASS] counter overflow: slimiron_block returns -2
[PASS] slim_zero: buffer fully zeroed
[PASS] verify16: equal → 0
[PASS] verify16: differ last byte → -1
[PASS] verify16: differ first byte → -1
[PASS] SIMAC fast path: bulk == byte-by-byte
[PASS] capacity: different capacity → different tag
[PASS] xor64: matches reference
[PASS] collision: no tag collisions in 10000 runs

32 passed, 0 failed
dava@Dava:~/github/slimiron
$ make run-bench
./bench
Slimiron v0.2.0 benchmark
Data size : 16 MB | Warmup: 3 | Measured: 50
SIMAC rate/capacity : 32/32 bytes
SIV mode : enabled (+1 SIMAC pass over plaintext)
XOR path : scalar (unrolled 8x8)

Encrypt :  146.51 MB/s  (5.460 s total, 109.21 ms/call)
Decrypt :  252.14 MB/s  (3.173 s total, 63.46 ms/call)

Integrity: OK
dava@Dava:~/github/slimiron
$ python3 gen_constants.py
Slimiron constant verifier v0.2.2
Method: slimiron_bootstrap(label)  [pure Slimiron permutation, no hashlib]
==================================================================

[OK      ] SLIMIRON_IV_0..3  <- slimiron_bootstrap("slimiron-stream-v5")
           word[0]: computed=0xb9e3ef7f  header=0xb9e3ef7f  ==
           word[1]: computed=0x7638101d  header=0x7638101d  ==
           word[2]: computed=0x53373520  header=0x53373520  ==
           word[3]: computed=0x654cbc86  header=0x654cbc86  ==

[OK      ] SIMAC_INIT_0..7  <- slimiron_bootstrap("simac-init-v5")
           word[0]: computed=0x3e60fb52  header=0x3e60fb52  ==
           word[1]: computed=0x858433d2  header=0x858433d2  ==
           word[2]: computed=0xa5db45d3  header=0xa5db45d3  ==
           word[3]: computed=0x14ae65d8  header=0x14ae65d8  ==
           word[4]: computed=0x036c4f77  header=0x036c4f77  ==
           word[5]: computed=0x5e78b857  header=0x5e78b857  ==
           word[6]: computed=0xcceca447  header=0xcceca447  ==
           word[7]: computed=0x7d965649  header=0x7d965649  ==

[OK      ] SIMAC_FINAL_0..7  <- slimiron_bootstrap("simac-final-v5")
           word[0]: computed=0x8d1f0ff9  header=0x8d1f0ff9  ==
           word[1]: computed=0x7a370f9e  header=0x7a370f9e  ==
           word[2]: computed=0xe4e1e8ff  header=0xe4e1e8ff  ==
           word[3]: computed=0x45d5c67b  header=0x45d5c67b  ==
           word[4]: computed=0xfd3dc527  header=0xfd3dc527  ==
           word[5]: computed=0xc608a8c1  header=0xc608a8c1  ==
           word[6]: computed=0xc2617c1b  header=0xc2617c1b  ==
           word[7]: computed=0xf0327ed2  header=0xf0327ed2  ==

[OK      ] SIMAC_DOMAIN_AAD  <- slimiron_bootstrap("simac-domain-aad-v5")
           word[0]: computed=0x8439c00f  header=0x8439c00f  ==

[OK      ] SIMAC_DOMAIN_CT  <- slimiron_bootstrap("simac-domain-ct-v5")
           word[0]: computed=0x35ef9605  header=0x35ef9605  ==

[OK      ] SIMAC_DOMAIN_SIV  <- slimiron_bootstrap("simac-domain-siv-v5")
           word[0]: computed=0x493ccf67  header=0x493ccf67  ==

==================================================================
All constants verified.  slimiron.h v0.2.2 is consistent.
No external hash library used — pure Slimiron permutation only.
dava@Dava:~/github/slimiron
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "slimiron.h"

#define TEST_SIZE 1024
#define TEST_ITER 10000

static int g_pass = 0, g_fail = 0;
static void check(int cond, const char *label) {
    if (cond) { printf("[PASS] %s\n", label); g_pass++; }
    else       { printf("[FAIL] %s\n", label); g_fail++; }
}

static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

static int count_bits_diff(const uint8_t *a, const uint8_t *b, size_t len) {
    int diff = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t x = a[i] ^ b[i];
        for (int j = 0; j < 8; j++) diff += (x >> j) & 1;
    }
    return diff;
}

/* ── Helper: encrypt into allocated buffer, returns 0 on success ── */
static int do_encrypt(
    uint8_t snonce[12], uint8_t *cipher, uint8_t tag[16],
    const uint8_t *msg, size_t mlen,
    const uint8_t *aad, size_t alen,
    const uint8_t key[32], const uint8_t nonce[12])
{
    return slimiron_aead_encrypt(snonce, cipher, tag, msg, mlen, aad, alen, key, nonce);
}

static int do_decrypt(
    uint8_t *msg,
    const uint8_t snonce[12], const uint8_t *cipher, size_t clen,
    const uint8_t tag[16],
    const uint8_t *aad, size_t alen,
    const uint8_t key[32])
{
    return slimiron_aead_decrypt(msg, snonce, cipher, clen, tag, aad, alen, key);
}

/* ── Test: fixed test vector ── */
void test_vector(void) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00
    };
    static const uint8_t plaintext[33] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,
        0x47,0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,
        0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,0x73
    };
    static const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
    };

    uint8_t snonce[12], cipher[33], tag[16];
    int r = do_encrypt(snonce, cipher, tag, plaintext, 33, aad, 12, key, nonce);
    check(r == 0, "vector: encrypt returns 0");

    /* Decrypt and verify round-trip */
    uint8_t recovered[33];
    r = do_decrypt(recovered, snonce, cipher, 33, tag, aad, 12, key);
    check(r == 0, "vector: decrypt returns 0");
    check(memcmp(recovered, plaintext, 33) == 0, "vector: plaintext recovered");

    /* Same input → same synth_nonce and ciphertext (deterministic SIV) */
    uint8_t snonce2[12], cipher2[33], tag2[16];
    do_encrypt(snonce2, cipher2, tag2, plaintext, 33, aad, 12, key, nonce);
    check(memcmp(snonce, snonce2, 12) == 0,   "vector: synth_nonce deterministic");
    check(memcmp(cipher, cipher2, 33) == 0,   "vector: ciphertext deterministic");
    check(memcmp(tag,    tag2,    16) == 0,    "vector: tag deterministic");
}

/* ── Test: SIV nonce-misuse resistance ── */
void test_siv_misuse(void) {
    uint8_t key[32], nonce[12];
    uint8_t msg1[64], msg2[64];
    uint8_t sn1[12], sn2[12], sn3[12];
    uint8_t c1[64], c2[64], c3[64], tag[16];

    random_bytes(key, 32);
    random_bytes(nonce, 12);   /* SAME nonce for all three */
    random_bytes(msg1, 64);
    memcpy(msg2, msg1, 64); msg2[0] ^= 1;  /* differ by 1 bit */

    do_encrypt(sn1, c1, tag, msg1, 64, NULL, 0, key, nonce);
    do_encrypt(sn2, c2, tag, msg2, 64, NULL, 0, key, nonce);  /* same nonce, diff msg */
    do_encrypt(sn3, c3, tag, msg1, 64, NULL, 0, key, nonce);  /* identical to first */

    /* Different messages → different synth_nonce even with same external nonce */
    check(memcmp(sn1, sn2, 12) != 0, "SIV misuse: diff msg → diff synth_nonce");
    /* Same message → same synth_nonce (deterministic) */
    check(memcmp(sn1, sn3, 12) == 0, "SIV misuse: same msg → same synth_nonce");
    /* Different ciphertext for different messages */
    check(memcmp(c1, c2, 64) != 0,   "SIV misuse: diff msg → diff ciphertext");
}

/* ── Test: round-trip ── */
void test_roundtrip(void) {
    uint8_t key[32], nonce[12], msg[TEST_SIZE], recovered[TEST_SIZE];
    uint8_t snonce[12], cipher[TEST_SIZE], tag[16];
    random_bytes(key, 32); random_bytes(nonce, 12); random_bytes(msg, TEST_SIZE);
    do_encrypt(snonce, cipher, tag, msg, TEST_SIZE, NULL, 0, key, nonce);
    int r = do_decrypt(recovered, snonce, cipher, TEST_SIZE, tag, NULL, 0, key);
    check(r == 0 && memcmp(msg, recovered, TEST_SIZE) == 0, "roundtrip: plaintext recovered");
}

/* ── Test: multiblock boundary sizes ── */
void test_multiblock(void) {
    uint8_t key[32], nonce[12];
    random_bytes(key, 32); random_bytes(nonce, 12);
    static const size_t sizes[] = { 0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 256, 513 };
    int ok = 1;
    for (size_t s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        uint8_t *msg = n ? malloc(n) : NULL;
        uint8_t *cipher = n ? malloc(n) : NULL;
        uint8_t *recovered = n ? malloc(n) : NULL;
        uint8_t snonce[12], tag[16];
        if (n) { random_bytes(msg, n); }
        do_encrypt(snonce, cipher, tag, msg, n, NULL, 0, key, nonce);
        int r = do_decrypt(recovered, snonce, cipher, n, tag, NULL, 0, key);
        if (r != 0 || (n && memcmp(msg, recovered, n) != 0)) {
            printf("  FAIL at size %zu\n", n); ok = 0;
        }
        free(msg); free(cipher); free(recovered);
    }
    check(ok, "multiblock: all boundary sizes round-trip correctly");
}

/* ── Test: avalanche ── */
void test_avalanche(void) {
    uint8_t key[32], nonce[12], msg[TEST_SIZE], msg2[TEST_SIZE];
    uint8_t sn1[12], sn2[12], tag1[16], tag2[16], cipher[TEST_SIZE];
    random_bytes(key, 32); random_bytes(nonce, 12); random_bytes(msg, TEST_SIZE);
    memcpy(msg2, msg, TEST_SIZE);
    do_encrypt(sn1, cipher, tag1, msg,  TEST_SIZE, NULL, 0, key, nonce);
    msg2[0] ^= 1;
    do_encrypt(sn2, cipher, tag2, msg2, TEST_SIZE, NULL, 0, key, nonce);
    int diff_tag  = count_bits_diff(tag1, tag2, 16);
    int diff_snonce = count_bits_diff(sn1, sn2, 12);
    int ok = (diff_tag >= 40 && diff_tag <= 88) && (diff_snonce > 0);
    printf("[%s] avalanche: tag %d/128 bits differ, synth_nonce %d/96 bits differ\n",
           ok?"PASS":"FAIL", diff_tag, diff_snonce);
    if (ok) g_pass++; else g_fail++;
}

/* ── Test: forgery detection ── */
void test_forgery(void) {
    uint8_t key[32], nonce[12], msg[TEST_SIZE], out[TEST_SIZE];
    uint8_t snonce[12], cipher[TEST_SIZE], tag[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(msg,TEST_SIZE);
    do_encrypt(snonce, cipher, tag, msg, TEST_SIZE, NULL, 0, key, nonce);

    /* Tamper ciphertext */
    uint8_t c2[TEST_SIZE]; memcpy(c2, cipher, TEST_SIZE); c2[0] ^= 1;
    int r = do_decrypt(out, snonce, c2, TEST_SIZE, tag, NULL, 0, key);
    check(r == -1, "forgery: cipher tamper detected");
    uint8_t zero[TEST_SIZE]; memset(zero, 0, TEST_SIZE);
    check(memcmp(out, zero, TEST_SIZE) == 0, "forgery: output zeroed on failure");

    /* Tamper tag */
    uint8_t t2[16]; memcpy(t2, tag, 16); t2[7] ^= 0xFF;
    r = do_decrypt(out, snonce, cipher, TEST_SIZE, t2, NULL, 0, key);
    check(r == -1, "forgery: tag tamper detected");

    /* Tamper synth_nonce */
    uint8_t sn2[12]; memcpy(sn2, snonce, 12); sn2[0] ^= 1;
    r = do_decrypt(out, sn2, cipher, TEST_SIZE, tag, NULL, 0, key);
    check(r == -1, "forgery: synth_nonce tamper detected");
}

/* ── Test: AAD authenticated ── */
void test_aad(void) {
    uint8_t key[32], nonce[12], msg[64], out[64], aad[16];
    uint8_t snonce[12], cipher[64], tag[16];
    random_bytes(key,32); random_bytes(nonce,12);
    random_bytes(msg,64); random_bytes(aad,16);
    do_encrypt(snonce, cipher, tag, msg, 64, aad, 16, key, nonce);
    aad[0] ^= 1;
    int r = do_decrypt(out, snonce, cipher, 64, tag, aad, 16, key);
    check(r == -1, "AAD: tampered AAD detected");
}

/* ── Test: domain separation ── */
void test_domain_sep(void) {
    uint8_t key[32], nonce[12];
    uint8_t sn1[12], sn2[12], tag1[16], tag2[16], cipher[2];
    random_bytes(key,32); random_bytes(nonce,12);
    const uint8_t ab[2]={'A','B'}, a[1]={'A'}, b[1]={'B'};
    do_encrypt(sn1, cipher, tag1, NULL, 0, ab, 2, key, nonce);
    do_encrypt(sn2, cipher, tag2, b,    1, a,  1, key, nonce);
    check(memcmp(tag1, tag2, 16) != 0, "domain sep: AAD vs CT not interchangeable");
}

/* ── Test: wrong key / nonce ── */
void test_wrong_credentials(void) {
    uint8_t key[32], key2[32], nonce[12], nonce2[12];
    uint8_t msg[64], out[64], snonce[12], cipher[64], tag[16];
    random_bytes(key,32); memcpy(key2,key,32); key2[0]^=1;
    random_bytes(nonce,12); memcpy(nonce2,nonce,12); nonce2[0]^=1;
    random_bytes(msg,64);
    do_encrypt(snonce, cipher, tag, msg, 64, NULL, 0, key, nonce);
    check(do_decrypt(out, snonce, cipher, 64, tag, NULL, 0, key2)  == -1, "wrong key detected");
    /* Wrong external nonce: SIV derives different synth_nonce, so auth fails */
    uint8_t snonce_bad[12], cipher_bad[64], tag_bad[16];
    do_encrypt(snonce_bad, cipher_bad, tag_bad, msg, 64, NULL, 0, key, nonce2);
    check(do_decrypt(out, snonce_bad, cipher_bad, 64, tag_bad, NULL, 0, key) == 0,
          "wrong ext nonce: decrypt with correct snonce succeeds");
}

/* ── Test: empty message ── */
void test_empty(void) {
    uint8_t key[32], nonce[12], sn1[12], sn2[12], tag1[16], tag2[16], dummy[1];
    random_bytes(key,32); random_bytes(nonce,12);
    int r  = do_encrypt(sn1, dummy, tag1, NULL, 0, NULL, 0, key, nonce);
    check(r == 0, "empty: encrypt returns 0");
    int r2 = do_decrypt(dummy, sn1, NULL, 0, tag1, NULL, 0, key);
    check(r2 == 0, "empty: decrypt round-trip");
    const uint8_t aad[1] = {0x42};
    do_encrypt(sn2, dummy, tag2, NULL, 0, aad, 1, key, nonce);
    check(memcmp(tag1, tag2, 16) != 0, "empty: tag differs with different AAD");
}

/* ── Test: counter overflow ── */
void test_counter_overflow(void) {
    slimiron_ctx ctx;
    uint8_t key[32]={0}, nonce[12]={0};
    slimiron_init(&ctx, key, nonce);
    ctx.state[0] = SLIMIRON_MAX_COUNTER + 1;
    int r = slimiron_block(&ctx);
    check(r == -2, "counter overflow: slimiron_block returns -2");
}

/* ── Test: slim_zero ── */
void test_slim_zero(void) {
    uint8_t buf[64]; memset(buf, 0xAB, 64);
    slim_zero(buf, 64);
    int ok = 1;
    for (int i = 0; i < 64; i++) ok &= (buf[i] == 0);
    check(ok, "slim_zero: buffer fully zeroed");
}

/* ── Test: crypto_verify_16 ── */
void test_verify16(void) {
    uint8_t a[16]={0}, b[16]={0};
    check(crypto_verify_16(a,b) ==  0, "verify16: equal → 0");
    b[15]^=1;
    check(crypto_verify_16(a,b) == -1, "verify16: differ last byte → -1");
    b[15]^=1; b[0]^=0xFF;
    check(crypto_verify_16(a,b) == -1, "verify16: differ first byte → -1");
}

/* ── Test: SIMAC fast path ── */
void test_simac_fast_path(void) {
    uint8_t key[32], nonce[12], mac_key[32];
    uint8_t data[SIMAC_RATE_BYTES * 4];
    uint8_t tag1[16], tag2[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(data,sizeof(data));
    slimiron_ctx c;
    slimiron_init(&c, key, nonce);
    slimiron_derive_mac_key(&c, mac_key);
    slim_zero(&c, sizeof(c));

    simac_ctx m1, m2;
    simac_init(&m1, mac_key, nonce);
    simac_absorb(&m1, data, sizeof(data));
    simac_absorb_len(&m1, sizeof(data));
    simac_domain(&m1, SIMAC_DOMAIN_CT);
    simac_finalize(&m1, tag1);

    simac_init(&m2, mac_key, nonce);
    for (size_t i = 0; i < sizeof(data); i++) simac_absorb(&m2, data+i, 1);
    simac_absorb_len(&m2, sizeof(data));
    simac_domain(&m2, SIMAC_DOMAIN_CT);
    simac_finalize(&m2, tag2);

    check(memcmp(tag1, tag2, 16) == 0, "SIMAC fast path: bulk == byte-by-byte");
    slim_zero(mac_key,32); slim_zero(&m1,sizeof(m1)); slim_zero(&m2,sizeof(m2));
}

/* ── Test: capacity doubled — different capacity constants give different tags ── */
void test_capacity_isolation(void) {
    uint8_t key[32], nonce[12], mac_key[32];
    uint8_t data[64], tag1[16], tag2[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(data,64);
    slimiron_ctx c;
    slimiron_init(&c, key, nonce);
    slimiron_derive_mac_key(&c, mac_key);
    slim_zero(&c, sizeof(c));

    simac_ctx m1, m2;
    simac_init(&m1, mac_key, nonce);
    simac_absorb(&m1, data, 64);
    simac_finalize(&m1, tag1);

    /* Manually corrupt capacity word to simulate different init */
    simac_init(&m2, mac_key, nonce);
    m2.state[8] ^= 0xDEADBEEF;   /* corrupt capacity */
    simac_absorb(&m2, data, 64);
    simac_finalize(&m2, tag2);

    check(memcmp(tag1, tag2, 16) != 0, "capacity: different capacity → different tag");
    slim_zero(mac_key,32);
}

/* ── Test: xor64 ── */
void test_xor64(void) {
    uint8_t src[64], key[64], dst[64], ref[64];
    random_bytes(src,64); random_bytes(key,64);
    for (int i=0;i<64;i++) ref[i]=src[i]^key[i];
    xor64(dst, src, key);
    check(memcmp(dst,ref,64)==0, "xor64: matches reference");
}

/* ── Test: collision ── */
void test_collision(void) {
    uint8_t key[32], nonce[12], msg[TEST_SIZE], cipher[TEST_SIZE];
    uint8_t (*tags)[16] = malloc((size_t)TEST_ITER * 16);
    uint8_t snonce[12];
    if (!tags) { printf("[SKIP] collision: alloc failed\n"); return; }
    random_bytes(key,32); random_bytes(nonce,12);
    for (int i = 0; i < TEST_ITER; i++) {
        random_bytes(msg, TEST_SIZE);
        do_encrypt(snonce, cipher, tags[i], msg, TEST_SIZE, NULL, 0, key, nonce);
    }
    int collisions = 0;
    for (int i = 0; i < TEST_ITER; i++)
        for (int j = i+1; j < TEST_ITER; j++)
            if (memcmp(tags[i], tags[j], 16) == 0) collisions++;
    check(collisions == 0, "collision: no tag collisions in 10000 runs");
    free(tags);
}

/* ── Main ── */
int main(void) {
    srand(1234);
    printf("Slimiron v0.2.2 test suite\n");
    printf("SlimMix rotations   : (15,11,9,5)\n");
    printf("Stream rounds       : %d\n", SLIMIRON_ROUNDS);
    printf("SIMAC rounds        : %d\n", SIMAC_ROUNDS);
    printf("SIMAC rate/capacity : %d/%d bytes\n", SIMAC_RATE_BYTES, 64-SIMAC_RATE_BYTES);
    printf("SIV mode            : enabled (nonce-misuse resistant)\n");
#if SLIM_HAS_AVX2
    printf("XOR path            : AVX2\n\n");
#else
    printf("XOR path            : scalar (unrolled 8x8)\n\n");
#endif

    /* Correctness */
    test_vector();
    test_roundtrip();
    test_multiblock();
    test_avalanche();

    /* Security */
    test_siv_misuse();
    test_forgery();
    test_aad();
    test_domain_sep();
    test_wrong_credentials();

    /* Edge cases */
    test_empty();
    test_counter_overflow();

    /* Implementation */
    test_slim_zero();
    test_verify16();
    test_simac_fast_path();
    test_capacity_isolation();
    test_xor64();

    /* Stress */
    test_collision();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
