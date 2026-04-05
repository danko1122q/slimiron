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
    return slimiron_aead_decrypt(msg, snonce, cipher, clen, tag, aad, alen, key,
                                 SLIMIRON_WIRE_VERSION);
}

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
    uint8_t recovered[33];
    r = do_decrypt(recovered, snonce, cipher, 33, tag, aad, 12, key);
    check(r == 0, "vector: decrypt returns 0");
    check(memcmp(recovered, plaintext, 33) == 0, "vector: plaintext recovered");
    uint8_t snonce2[12], cipher2[33], tag2[16];
    do_encrypt(snonce2, cipher2, tag2, plaintext, 33, aad, 12, key, nonce);
    check(memcmp(snonce,  snonce2,  12) == 0, "vector: synth_nonce deterministic");
    check(memcmp(cipher,  cipher2,  33) == 0, "vector: ciphertext deterministic");
    check(memcmp(tag,     tag2,     16) == 0, "vector: tag deterministic");
}

void test_siv_misuse(void) {
    uint8_t key[32], nonce[12], msg1[64], msg2[64];
    uint8_t sn1[12], sn2[12], sn3[12], c1[64], c2[64], c3[64], tag[16];
    random_bytes(key,32); random_bytes(nonce,12);
    random_bytes(msg1,64); memcpy(msg2,msg1,64); msg2[0]^=1;
    do_encrypt(sn1, c1, tag, msg1, 64, NULL, 0, key, nonce);
    do_encrypt(sn2, c2, tag, msg2, 64, NULL, 0, key, nonce);
    do_encrypt(sn3, c3, tag, msg1, 64, NULL, 0, key, nonce);
    check(memcmp(sn1, sn2, 12) != 0, "SIV misuse: diff msg -> diff synth_nonce");
    check(memcmp(sn1, sn3, 12) == 0, "SIV misuse: same msg -> same synth_nonce");
    check(memcmp(c1,  c2,  64) != 0, "SIV misuse: diff msg -> diff ciphertext");
}

void test_roundtrip(void) {
    uint8_t key[32], nonce[12], msg[TEST_SIZE], recovered[TEST_SIZE];
    uint8_t snonce[12], cipher[TEST_SIZE], tag[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(msg,TEST_SIZE);
    do_encrypt(snonce, cipher, tag, msg, TEST_SIZE, NULL, 0, key, nonce);
    int r = do_decrypt(recovered, snonce, cipher, TEST_SIZE, tag, NULL, 0, key);
    check(r == 0 && memcmp(msg, recovered, TEST_SIZE) == 0, "roundtrip: plaintext recovered");
}

void test_multiblock(void) {
    uint8_t key[32], nonce[12];
    random_bytes(key,32); random_bytes(nonce,12);
    static const size_t sizes[] = {0,1,31,32,33,63,64,65,127,128,129,256,513};
    int ok = 1;
    for (size_t s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        uint8_t *msg = n ? malloc(n) : NULL;
        uint8_t *cipher = n ? malloc(n) : NULL;
        uint8_t *recovered = n ? malloc(n) : NULL;
        uint8_t snonce[12], tag[16];
        if (n) random_bytes(msg, n);
        do_encrypt(snonce, cipher, tag, msg, n, NULL, 0, key, nonce);
        int r = do_decrypt(recovered, snonce, cipher, n, tag, NULL, 0, key);
        if (r != 0 || (n && memcmp(msg, recovered, n) != 0)) {
            printf("  FAIL at size %zu\n", n); ok = 0;
        }
        free(msg); free(cipher); free(recovered);
    }
    check(ok, "multiblock: all boundary sizes round-trip correctly");
}

void test_avalanche(void) {
    uint8_t key[32], nonce[12], msg[TEST_SIZE], msg2[TEST_SIZE];
    uint8_t sn1[12], sn2[12], tag1[16], tag2[16], cipher[TEST_SIZE];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(msg,TEST_SIZE);
    memcpy(msg2, msg, TEST_SIZE);
    do_encrypt(sn1, cipher, tag1, msg,  TEST_SIZE, NULL, 0, key, nonce);
    msg2[0] ^= 1;
    do_encrypt(sn2, cipher, tag2, msg2, TEST_SIZE, NULL, 0, key, nonce);
    int diff_tag    = count_bits_diff(tag1, tag2, 16);
    int diff_snonce = count_bits_diff(sn1,  sn2,  12);
    int ok = (diff_tag >= 40 && diff_tag <= 88) && (diff_snonce > 0);
    printf("[%s] avalanche: tag %d/128 bits differ, synth_nonce %d/96 bits differ\n",
           ok ? "PASS" : "FAIL", diff_tag, diff_snonce);
    if (ok) g_pass++; else g_fail++;
}

void test_forgery(void) {
    uint8_t key[32], nonce[12], msg[TEST_SIZE], out[TEST_SIZE];
    uint8_t snonce[12], cipher[TEST_SIZE], tag[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(msg,TEST_SIZE);
    do_encrypt(snonce, cipher, tag, msg, TEST_SIZE, NULL, 0, key, nonce);
    uint8_t c2[TEST_SIZE]; memcpy(c2, cipher, TEST_SIZE); c2[0] ^= 1;
    int r = do_decrypt(out, snonce, c2, TEST_SIZE, tag, NULL, 0, key);
    check(r == -1, "forgery: cipher tamper detected");
    uint8_t zero[TEST_SIZE]; memset(zero, 0, TEST_SIZE);
    check(memcmp(out, zero, TEST_SIZE) == 0, "forgery: output zeroed on failure");
    uint8_t t2[16]; memcpy(t2, tag, 16); t2[7] ^= 0xFF;
    r = do_decrypt(out, snonce, cipher, TEST_SIZE, t2, NULL, 0, key);
    check(r == -1, "forgery: tag tamper detected");
    uint8_t sn2[12]; memcpy(sn2, snonce, 12); sn2[0] ^= 1;
    r = do_decrypt(out, sn2, cipher, TEST_SIZE, tag, NULL, 0, key);
    check(r == -1, "forgery: synth_nonce tamper detected");
}

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

void test_domain_sep(void) {
    uint8_t key[32], nonce[12];
    uint8_t sn1[12], sn2[12], tag1[16], tag2[16], cipher[2];
    random_bytes(key,32); random_bytes(nonce,12);
    const uint8_t ab[2]={'A','B'}, a[1]={'A'}, b[1]={'B'};
    do_encrypt(sn1, cipher, tag1, NULL, 0, ab, 2, key, nonce);
    do_encrypt(sn2, cipher, tag2, b,    1, a,  1, key, nonce);
    check(memcmp(tag1, tag2, 16) != 0, "domain sep: AAD vs CT not interchangeable");
}

void test_wrong_credentials(void) {
    uint8_t key[32], key2[32], nonce[12], nonce2[12];
    uint8_t msg[64], out[64], snonce[12], cipher[64], tag[16];
    random_bytes(key,32); memcpy(key2,key,32); key2[0]^=1;
    random_bytes(nonce,12); memcpy(nonce2,nonce,12); nonce2[0]^=1;
    random_bytes(msg,64);
    do_encrypt(snonce, cipher, tag, msg, 64, NULL, 0, key, nonce);
    check(do_decrypt(out, snonce, cipher, 64, tag, NULL, 0, key2) == -1, "wrong key detected");
    uint8_t snonce_bad[12], cipher_bad[64], tag_bad[16];
    do_encrypt(snonce_bad, cipher_bad, tag_bad, msg, 64, NULL, 0, key, nonce2);
    check(do_decrypt(out, snonce_bad, cipher_bad, 64, tag_bad, NULL, 0, key) == 0,
          "wrong ext nonce: decrypt with correct snonce succeeds");
}

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

void test_counter_overflow(void) {
    slimiron_ctx ctx;
    uint8_t key[32]={0}, nonce[12]={0};
    slimiron_init(&ctx, key, nonce);
    ctx.state[0] = SLIMIRON_MAX_COUNTER + 1;
    int r = slimiron_block(&ctx);
    check(r == -2, "counter overflow: slimiron_block returns -2");
}

void test_slim_zero(void) {
    uint8_t buf[64]; memset(buf, 0xAB, 64);
    slim_zero(buf, 64);
    int ok = 1;
    for (int i = 0; i < 64; i++) ok &= (buf[i] == 0);
    check(ok, "slim_zero: buffer fully zeroed");
}

void test_verify16(void) {
    uint8_t a[16]={0}, b[16]={0};
    check(crypto_verify_16(a,b) ==  0, "verify16: equal -> 0");
    b[15]^=1;
    check(crypto_verify_16(a,b) == -1, "verify16: differ last byte -> -1");
    b[15]^=1; b[0]^=0xFF;
    check(crypto_verify_16(a,b) == -1, "verify16: differ first byte -> -1");
}

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
    simac_init(&m2, mac_key, nonce);
    m2.state[8] ^= 0xDEADBEEF;
    simac_absorb(&m2, data, 64);
    simac_finalize(&m2, tag2);
    check(memcmp(tag1, tag2, 16) != 0, "capacity: different capacity -> different tag");
    slim_zero(mac_key,32);
}

void test_xor64(void) {
    uint8_t src[64], key[64], dst[64], ref[64];
    random_bytes(src,64); random_bytes(key,64);
    for (int i=0;i<64;i++) ref[i]=src[i]^key[i];
    xor64(dst, src, key);
    check(memcmp(dst,ref,64)==0, "xor64: matches reference");
}

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

/* ── v0.3.0 new tests ── */

void test_inplace_alias(void) {
    uint8_t key[32], nonce[12], buf[64], snonce[12], tag[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(buf,64);
    int r = slimiron_aead_encrypt(snonce, buf, tag, buf, 64, NULL, 0, key, nonce);
    check(r == -3, "alias guard: msg==cipher returns -3");
    r = slimiron_aead_encrypt(snonce, buf, tag, buf, 0, NULL, 0, key, nonce);
    check(r == 0,  "alias guard: mlen==0 with same ptr is OK");
}

void test_wire_version(void) {
    uint8_t key[32], nonce[12], msg[32], out[32];
    uint8_t snonce[12], cipher[32], tag[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(msg,32);
    do_encrypt(snonce, cipher, tag, msg, 32, NULL, 0, key, nonce);
    int r = slimiron_aead_decrypt(out, snonce, cipher, 32, tag, NULL, 0, key,
                                   SLIMIRON_WIRE_VERSION);
    check(r == 0,  "wire version: correct version accepted");
    r = slimiron_aead_decrypt(out, snonce, cipher, 32, tag, NULL, 0, key,
                               (uint8_t)(SLIMIRON_WIRE_VERSION ^ 0xFF));
    check(r == -4, "wire version: wrong version returns -4");
}

void test_finalize_contract(void) {
    uint8_t key[32], nonce[12], mac_key[32];
    uint8_t data[48], tag1[16], tag2[16];
    random_bytes(key,32); random_bytes(nonce,12); random_bytes(data,48);
    slimiron_ctx c;
    slimiron_init(&c, key, nonce);
    slimiron_derive_mac_key(&c, mac_key);
    slim_zero(&c, sizeof(c));
    simac_ctx m1, m2;
    simac_init(&m1, mac_key, nonce);
    simac_absorb(&m1, data, 48);
    simac_absorb_len(&m1, 48);
    simac_pad(&m1);
    simac_domain(&m1, SIMAC_DOMAIN_CT);
    simac_finalize(&m1, tag1);
    simac_init(&m2, mac_key, nonce);
    simac_absorb(&m2, data, 48);
    simac_absorb_len(&m2, 48);
    simac_pad(&m2);
    simac_domain(&m2, SIMAC_DOMAIN_CT);
    simac_finalize(&m2, tag2);
    check(memcmp(tag1, tag2, 16) == 0, "finalize contract: identical data -> identical tag");
    slim_zero(mac_key,32);
}

void test_ctx_layout(void) {
    size_t expected = 16 * sizeof(uint32_t) + 64;
    check(sizeof(slimiron_ctx) == expected,
          "ctx layout: slimiron_ctx has no pos field (correct size)");
}

void test_round_count(void) {
    check(SLIMIRON_ROUNDS == 14, "rounds: SLIMIRON_ROUNDS == 14 (Fix #6)");
    check(SIMAC_ROUNDS    == 10, "rounds: SIMAC_ROUNDS == 10 (unchanged)");
}

void test_overhead_constant(void) {
    check(SLIMIRON_OVERHEAD == 29u, "overhead: SLIMIRON_OVERHEAD == 29 (1+12+16)");
}

int main(void) {
    srand(1234);
    printf("Slimiron v0.3.0 test suite\n");
    printf("SlimMix rotations   : (15,11,9,5)\n");
    printf("Stream rounds       : %d  (raised from 10 in v0.3.0)\n", SLIMIRON_ROUNDS);
    printf("SIMAC rounds        : %d\n", SIMAC_ROUNDS);
    printf("SIMAC rate/capacity : %d/%d bytes\n", SIMAC_RATE_BYTES, 64-SIMAC_RATE_BYTES);
    printf("SIV mode            : enabled (nonce-misuse resistant)\n");
    printf("Wire version        : 0x%02x  overhead: %u bytes\n",
           SLIMIRON_WIRE_VERSION, SLIMIRON_OVERHEAD);
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

    /* v0.3.0 new */
    test_inplace_alias();
    test_wire_version();
    test_finalize_contract();
    test_ctx_layout();
    test_round_count();
    test_overhead_constant();

    /* Stress */
    test_collision();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
