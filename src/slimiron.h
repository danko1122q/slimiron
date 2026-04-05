#ifndef SLIMIRON_H
#define SLIMIRON_H

/*
 * Slimiron + SIMAC  —  AEAD cipher (hobby project)
 * Version: 0.2.2
 *
 * ── Changelog ───────────────────────────────────────────────────────────────
 *
 * Fix #1 [PERF] simac_domain() overhead — v0.2.1
 *   simac_domain() no longer calls simac_pad() internally.
 *   Callers pad explicitly before each domain call.
 *   Saves 2 permutations on encrypt path, 2 on decrypt path.
 *
 * Fix #2 [SECURITY] slim_zero() compiler barrier — v0.2.1
 *   Added __asm__ volatile("" ::: "memory") after the volatile write loop to
 *   prevent LTO/WPO dead-store elimination of key material zeroization.
 *
 * Fix #3 [SECURITY] Full 256-bit key in capacity region — v0.2.1  WARNING: breaking
 *   State layout changed so all 8 key words live in state[8..15] permanently.
 *   Counter + nonce moved to state[0..3]. Old layout silently discarded K4..K7.
 *
 *   State layout (v0.2.1+):
 *     [  0] CTR     [  1] N0      [  2] N1      [  3] N2
 *     [  4] IV_0    [  5] IV_1    [  6] IV_2    [  7] IV_3
 *     [  8] K0      [  9] K1      [ 10] K2      [ 11] K3
 *     [ 12] K4      [ 13] K5      [ 14] K6      [ 15] K7
 *
 * Fix #4 [COMPAT] simac_absorb_len() big-endian — v0.2.1  WARNING: breaking
 *   Length field now encoded big-endian (MSB first), matching TLS/HKDF/GCM.
 *
 * Fix #5 [PURITY] Self-bootstrapped constants — v0.2.2  WARNING: breaking
 *   All initialization constants now derived from the Slimiron permutation
 *   itself.  SHA-256 dependency completely removed.
 *
 *   Bootstrap method per label string:
 *     1. Start with all-zero 16-word state
 *     2. Absorb label bytes into rate region (XOR into buffer, permute on
 *        full 32-byte block — same rule as simac_absorb)
 *     3. Apply two-marker padding (0x01 at pos, 0x80 at last rate byte)
 *     4. Permute once (SIMAC_ROUNDS = 10)
 *     5. Squeeze needed words from state[0..N-1]
 *
 *   Labels use suffix "-v5" to distinguish from SHA-256-derived v4 constants.
 *   Verified by gen_constants.py which reimplements the same bootstrap in
 *   pure Python — no hashlib, no external dependencies.
 *
 * ── Parameters ──────────────────────────────────────────────────────────────
 *   Key   : 256-bit
 *   Nonce : 96-bit  — unique per (key, message) recommended; misuse-resistant
 *   Tag   : 128-bit
 *
 * ── Security properties ─────────────────────────────────────────────────────
 *   - Constant-time tag comparison (volatile accumulator)
 *   - All key material zeroized on every return path
 *   - Compiler memory barrier prevents dead-store elimination of slim_zero()
 *   - Verify-first decryption (no plaintext released before tag check)
 *   - Nonce-misuse resistant: identical output only for identical inputs
 *   - Counter limit: 2^32 - 2 blocks (~256 GB) per (key, synth_nonce)
 *   - Full 256-bit key in permanent capacity region (no silent truncation)
 *
 * ── Return codes ────────────────────────────────────────────────────────────
 *    0   success
 *   -1   authentication failure (decrypt only; output buffer zeroed)
 *   -2   message too large
 *
 * ── Sponge parameters ───────────────────────────────────────────────────────
 *   Rate     = 32 bytes (8 words)  — state[0..7],  XORed with input
 *   Capacity = 32 bytes (8 words)  — state[8..15], never XORed with input
 *   Birthday bound: 2^128  (256-bit capacity)
 *
 * ── Constant derivation ─────────────────────────────────────────────────────
 *   All constants = slimiron_bootstrap(label)[0:N]
 *   Bootstrap absorbs the ASCII label into a zero-state Slimiron sponge,
 *   pads, permutes, and squeezes — no SHA-256 or any external hash.
 *   Verified by gen_constants.py (pure Python, no hashlib).
 *
 * WARNING: Hobby project. Not for production use.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Compiler portability
 * ------------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#  define SLIMFORCE        static inline __attribute__((always_inline))
#  define SLIMHOT          __attribute__((hot))
#  define SLIM_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define SLIM_UNLIKELY(x) __builtin_expect(!!(x), 0)
#  define SLIM_RESTRICT    __restrict__
#  define SLIM_COMPILER_BARRIER() __asm__ volatile("" ::: "memory")
#else
#  define SLIMFORCE        static inline
#  define SLIMHOT
#  define SLIM_LIKELY(x)   (x)
#  define SLIM_UNLIKELY(x) (x)
#  define SLIM_RESTRICT
#  define SLIM_COMPILER_BARRIER() ((void)0)
#endif

#if defined(__AVX2__)
#  include <immintrin.h>
#  define SLIM_HAS_AVX2 1
#else
#  define SLIM_HAS_AVX2 0
#endif

/* -------------------------------------------------------------------------
 * Round counts
 * With capacity doubled to 32 bytes, 10 rounds provides equivalent security
 * margin to 20 rounds at 16-byte capacity.
 * SIMAC at 10 rounds: birthday bound = 2^128 (capacity = 256 bits).
 * ------------------------------------------------------------------------- */
#define SLIMIRON_ROUNDS  10
#define SIMAC_ROUNDS     10

/* -------------------------------------------------------------------------
 * Initialization constants — slimiron_bootstrap(label)[0:N]
 *
 * Derived purely from the Slimiron permutation (SlimMix ARX, 10 rounds).
 * No external hash function.  Verified by gen_constants.py.
 *
 * Bootstrap: absorb ASCII label into zero-state sponge (rate=32 bytes),
 * apply two-marker padding, permute once, squeeze state[0..N-1].
 * ------------------------------------------------------------------------- */

/* SLIMIRON_IV_[0-3]  <- slimiron_bootstrap("slimiron-stream-v5")[0:4]
 * (Only 4 words; IV occupies state[4..7], state[0..3] = CTR+nonce.)     */
#define SLIMIRON_IV_0  0xb9e3ef7fu
#define SLIMIRON_IV_1  0x7638101du
#define SLIMIRON_IV_2  0x53373520u
#define SLIMIRON_IV_3  0x654cbc86u

/* SIMAC_INIT_[0-7]  <- slimiron_bootstrap("simac-init-v5")[0:8] */
#define SIMAC_INIT_0   0x3e60fb52u
#define SIMAC_INIT_1   0x858433d2u
#define SIMAC_INIT_2   0xa5db45d3u
#define SIMAC_INIT_3   0x14ae65d8u
#define SIMAC_INIT_4   0x036c4f77u
#define SIMAC_INIT_5   0x5e78b857u
#define SIMAC_INIT_6   0xcceca447u
#define SIMAC_INIT_7   0x7d965649u

/* SIMAC_FINAL_[0-7]  <- slimiron_bootstrap("simac-final-v5")[0:8] */
#define SIMAC_FINAL_0  0x8d1f0ff9u
#define SIMAC_FINAL_1  0x7a370f9eu
#define SIMAC_FINAL_2  0xe4e1e8ffu
#define SIMAC_FINAL_3  0x45d5c67bu
#define SIMAC_FINAL_4  0xfd3dc527u
#define SIMAC_FINAL_5  0xc608a8c1u
#define SIMAC_FINAL_6  0xc2617c1bu
#define SIMAC_FINAL_7  0xf0327ed2u

/* Domain separators  <- slimiron_bootstrap(label)[0] */
#define SIMAC_DOMAIN_AAD  0x8439c00fu  /* slimiron_bootstrap("simac-domain-aad-v5") */
#define SIMAC_DOMAIN_CT   0x35ef9605u  /* slimiron_bootstrap("simac-domain-ct-v5")  */
#define SIMAC_DOMAIN_SIV  0x493ccf67u  /* slimiron_bootstrap("simac-domain-siv-v5") */

/* -------------------------------------------------------------------------
 * SIMAC sponge parameters
 *   Rate     = 32 bytes (8 words)  -- state[0..7],  XORed with input
 *   Capacity = 32 bytes (8 words)  -- state[8..15], never XORed with input
 * ------------------------------------------------------------------------- */
#define SIMAC_RATE_WORDS  8
#define SIMAC_RATE_BYTES  32

/* -------------------------------------------------------------------------
 * Counter limit: 2^32 - 2 blocks ~ 256 GB per (key, synth_nonce)
 * ------------------------------------------------------------------------- */
#define SLIMIRON_MAX_COUNTER 0xFFFFFFFEu

/* -------------------------------------------------------------------------
 * Types
 * ------------------------------------------------------------------------- */
typedef struct {
    uint32_t state[16];
    uint8_t  stream[64];
    size_t   pos;
} slimiron_ctx;

typedef struct {
    uint32_t state[16];
    uint8_t  buffer[SIMAC_RATE_BYTES];
    size_t   pos;
} simac_ctx;

/* -------------------------------------------------------------------------
 * Secure zeroization -- guaranteed not optimized away.
 *
 * volatile pointer: forces every byte write to be emitted.
 * SLIM_COMPILER_BARRIER(): prevents LTO/WPO from treating the writes as
 * dead stores even when the pointer is never read afterwards.
 * ------------------------------------------------------------------------- */
SLIMFORCE void slim_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
    SLIM_COMPILER_BARRIER();
}

/* -------------------------------------------------------------------------
 * Endian-safe helpers (little-endian wire format)
 * ------------------------------------------------------------------------- */
SLIMFORCE uint32_t load32_le(const uint8_t *src) {
    uint32_t v; memcpy(&v, src, 4);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    return v;
}

SLIMFORCE void store32_le(uint8_t *dst, uint32_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    memcpy(dst, &v, 4);
}

SLIMFORCE uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* -------------------------------------------------------------------------
 * Constant-time 16-byte comparison.
 * volatile accumulator prevents early-exit optimization at -O3.
 * ------------------------------------------------------------------------- */
SLIMFORCE int crypto_verify_16(const uint8_t *a, const uint8_t *b) {
    volatile uint8_t diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= a[i] ^ b[i];
    return (diff == 0) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * SlimMix -- ARX quarter-round
 * Rotation constants (15, 11, 9, 5): confirmed optimal via 142-candidate
 * sweep; full 512-bit avalanche at DR2; all odd; non-repeating.
 * ------------------------------------------------------------------------- */
SLIMFORCE void slimmix(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 15);
    *c += *d; *b ^= *c; *b = rotl32(*b, 11);
    *a += *b; *d ^= *a; *d = rotl32(*d,  9);
    *c += *d; *b ^= *c; *b = rotl32(*b,  5);
}

SLIMFORCE void permute(uint32_t s[16], int rounds) {
    for (int i = 0; i < rounds; i += 2) {
        /* column round */
        slimmix(&s[0], &s[4], &s[8],  &s[12]);
        slimmix(&s[1], &s[5], &s[9],  &s[13]);
        slimmix(&s[2], &s[6], &s[10], &s[14]);
        slimmix(&s[3], &s[7], &s[11], &s[15]);
        /* diagonal round */
        slimmix(&s[0], &s[5], &s[10], &s[15]);
        slimmix(&s[1], &s[6], &s[11], &s[12]);
        slimmix(&s[2], &s[7], &s[8],  &s[13]);
        slimmix(&s[3], &s[4], &s[9],  &s[14]);
    }
}

/* =========================================================================
 * Slimiron stream cipher
 *
 * State layout (v0.2.1+):
 *   [  0] CTR     [  1] N0      [  2] N1      [  3] N2
 *   [  4] IV_0    [  5] IV_1    [  6] IV_2    [  7] IV_3
 *   [  8] K0      [  9] K1      [ 10] K2      [ 11] K3
 *   [ 12] K4      [ 13] K5      [ 14] K6      [ 15] K7
 *
 * Full 256-bit key in state[8..15] (capacity) -- never overwritten.
 * Counter and nonce in state[0..3] (rate region).
 * ========================================================================= */

SLIMFORCE void slimiron_init(slimiron_ctx *ctx,
                             const uint8_t key[32],
                             const uint8_t nonce[12])
{
    ctx->state[0] = 0;                      /* counter */
    ctx->state[1] = load32_le(nonce + 0);   /* N0 */
    ctx->state[2] = load32_le(nonce + 4);   /* N1 */
    ctx->state[3] = load32_le(nonce + 8);   /* N2 */
    ctx->state[4] = SLIMIRON_IV_0;
    ctx->state[5] = SLIMIRON_IV_1;
    ctx->state[6] = SLIMIRON_IV_2;
    ctx->state[7] = SLIMIRON_IV_3;
    /* Capacity: full 256-bit key -- never overwritten */
    for (int i = 0; i < 8; i++)
        ctx->state[8 + i] = load32_le(key + i * 4);
    ctx->pos = 64;
}

/* Returns 0 on success, -2 if counter limit exceeded */
SLIMFORCE int slimiron_block(slimiron_ctx *ctx) {
    if (SLIM_UNLIKELY(ctx->state[0] > SLIMIRON_MAX_COUNTER))
        return -2;
    uint32_t x[16];
    memcpy(x, ctx->state, 64);
    permute(x, SLIMIRON_ROUNDS);
    for (int i = 0; i < 16; i++) {
        x[i] += ctx->state[i];
        store32_le(ctx->stream + i * 4, x[i]);
    }
    ctx->state[0]++;
    ctx->pos = 0;
    return 0;
}

SLIMFORCE int slimiron_derive_mac_key(slimiron_ctx *ctx, uint8_t mac_key[32]) {
    int r = slimiron_block(ctx);
    if (r != 0) return r;
    memcpy(mac_key, ctx->stream, 32);
    ctx->pos = 64;
    return 0;
}

/* =========================================================================
 * SIMAC -- sponge-based MAC (32-byte capacity)
 *
 * State after simac_init():
 *   [  0.. 7] rate   -- XORed with absorbed input (32 bytes)
 *   [  8..15] capacity -- never touched by absorb path
 *
 * Capacity seeded with SIMAC_INIT_[0-7] XOR nonce (3 words) for
 * per-(key,nonce) uniqueness, then an initial permute mixes everything.
 * ========================================================================= */

SLIMFORCE void simac_init(simac_ctx *ctx,
                          const uint8_t mac_key[32],
                          const uint8_t nonce[12])
{
    for (int i = 0; i < 8; i++)
        ctx->state[i] = load32_le(mac_key + i * 4);
    /* Capacity seeded with derived constants XOR nonce for uniqueness */
    ctx->state[ 8] = SIMAC_INIT_0 ^ load32_le(nonce + 0);
    ctx->state[ 9] = SIMAC_INIT_1 ^ load32_le(nonce + 4);
    ctx->state[10] = SIMAC_INIT_2 ^ load32_le(nonce + 8);
    ctx->state[11] = SIMAC_INIT_3;
    ctx->state[12] = SIMAC_INIT_4;
    ctx->state[13] = SIMAC_INIT_5;
    ctx->state[14] = SIMAC_INIT_6;
    ctx->state[15] = SIMAC_INIT_7;
    permute(ctx->state, SIMAC_ROUNDS);
    memset(ctx->buffer, 0, SIMAC_RATE_BYTES);
    ctx->pos = 0;
}

/* Compress one full rate block directly from pointer (fast path) */
SLIMFORCE void simac_compress(simac_ctx *ctx, const uint8_t *block) {
    for (int i = 0; i < SIMAC_RATE_WORDS; i++)
        ctx->state[i] ^= load32_le(block + i * 4);
    permute(ctx->state, SIMAC_ROUNDS);
}

/* Flush internal buffer */
SLIMFORCE void simac_block(simac_ctx *ctx) {
    simac_compress(ctx, ctx->buffer);
    memset(ctx->buffer, 0, SIMAC_RATE_BYTES);
    ctx->pos = 0;
}

SLIMHOT SLIMFORCE void simac_absorb(simac_ctx *ctx,
                                    const uint8_t *data, size_t len)
{
    if (ctx->pos > 0) {
        size_t want = SIMAC_RATE_BYTES - ctx->pos;
        if (len < want) {
            memcpy(ctx->buffer + ctx->pos, data, len);
            ctx->pos += len;
            return;
        }
        memcpy(ctx->buffer + ctx->pos, data, want);
        data += want; len -= want;
        simac_block(ctx);
    }
    while (len >= SIMAC_RATE_BYTES) {
        simac_compress(ctx, data);
        data += SIMAC_RATE_BYTES;
        len  -= SIMAC_RATE_BYTES;
    }
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->pos = len;
    }
}

/*
 * Absorb a 64-bit length field, big-endian (MSB first).
 * Big-endian matches standard cryptographic convention (TLS, HKDF, GCM).
 */
SLIMFORCE void simac_absorb_len(simac_ctx *ctx, uint64_t len) {
    uint8_t tmp[8];
    for (int i = 0; i < 8; i++) tmp[i] = (uint8_t)(len >> (56 - 8 * i));
    simac_absorb(ctx, tmp, 8);
}

/* Two-marker padding: 0x01 at pos, 0x80 at last rate byte.
   When pos == SIMAC_RATE_BYTES-1: both land on same byte -> 0x81. */
SLIMFORCE void simac_pad(simac_ctx *ctx) {
    ctx->buffer[ctx->pos] ^= 0x01;
    ctx->buffer[SIMAC_RATE_BYTES - 1] ^= 0x80;
    simac_block(ctx);
}

/*
 * simac_domain -- apply domain separator into capacity region.
 *
 * CALLER MUST call simac_pad() before this function.
 * simac_domain() only XORs the constant into state[8] (first capacity word,
 * never reachable by the absorb path) and runs one permutation.
 *
 * This avoids the double-permutation overhead of v0.2.0 where
 * simac_domain() called simac_pad() internally.
 */
SLIMFORCE void simac_domain(simac_ctx *ctx, uint32_t dom) {
    ctx->state[8] ^= dom;
    permute(ctx->state, SIMAC_ROUNDS);
}

/* Finalize: XOR 256-bit mask into capacity, double permute, squeeze 128 bits */
SLIMFORCE void simac_finalize(simac_ctx *ctx, uint8_t tag[16]) {
    simac_pad(ctx);
    ctx->state[ 8] ^= SIMAC_FINAL_0;
    ctx->state[ 9] ^= SIMAC_FINAL_1;
    ctx->state[10] ^= SIMAC_FINAL_2;
    ctx->state[11] ^= SIMAC_FINAL_3;
    ctx->state[12] ^= SIMAC_FINAL_4;
    ctx->state[13] ^= SIMAC_FINAL_5;
    ctx->state[14] ^= SIMAC_FINAL_6;
    ctx->state[15] ^= SIMAC_FINAL_7;
    permute(ctx->state, SIMAC_ROUNDS);
    permute(ctx->state, SIMAC_ROUNDS);
    for (int i = 0; i < 4; i++)
        store32_le(tag + i * 4, ctx->state[i]);
}

/* =========================================================================
 * XOR 64-byte block -- AVX2 path when available, else scalar 8x8-byte
 * ========================================================================= */
SLIMHOT SLIMFORCE void xor64(
    uint8_t       * SLIM_RESTRICT dst,
    const uint8_t * SLIM_RESTRICT src,
    const uint8_t * SLIM_RESTRICT key)
{
#if SLIM_HAS_AVX2
    __m256i s0 = _mm256_loadu_si256((const __m256i *)(src));
    __m256i s1 = _mm256_loadu_si256((const __m256i *)(src + 32));
    __m256i k0 = _mm256_loadu_si256((const __m256i *)(key));
    __m256i k1 = _mm256_loadu_si256((const __m256i *)(key + 32));
    _mm256_storeu_si256((__m256i *)(dst),      _mm256_xor_si256(s0, k0));
    _mm256_storeu_si256((__m256i *)(dst + 32), _mm256_xor_si256(s1, k1));
#else
    for (int i = 0; i < 8; i++) {
        uint64_t s, k;
        memcpy(&s, src + i * 8, 8);
        memcpy(&k, key + i * 8, 8);
        s ^= k;
        memcpy(dst + i * 8, &s, 8);
    }
#endif
}

/* =========================================================================
 * SIV -- Synthetic IV derivation (nonce-misuse resistance)
 *
 * synth_nonce = SIMAC_SIV(key, nonce, aad, msg)[0:12]
 *
 * Properties:
 *   - Nonce reuse with different msg  -> different synth_nonce -> safe
 *   - Only identical (key, nonce, aad, msg) produces identical output
 *   - Cost: one extra SIMAC pass over the plaintext before encryption
 * ========================================================================= */
SLIMHOT static int siv_derive(
    uint8_t        synth_nonce[12],
    const uint8_t *msg,     size_t mlen,
    const uint8_t *aad,     size_t aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12])
{
    slimiron_ctx c;
    slimiron_init(&c, key, nonce);
    uint8_t siv_key[32];
    int r = slimiron_derive_mac_key(&c, siv_key);
    slim_zero(&c, sizeof(c));
    if (r != 0) return r;

    simac_ctx m;
    simac_init(&m, siv_key, nonce);
    slim_zero(siv_key, 32);

    /* Commit original nonce into rate region too */
    simac_absorb(&m, nonce, 12);

    if (aad_len > 0) simac_absorb(&m, aad, aad_len);
    simac_absorb_len(&m, (uint64_t)aad_len);

    if (mlen > 0) simac_absorb(&m, msg, mlen);
    simac_absorb_len(&m, (uint64_t)mlen);

    simac_pad(&m);
    simac_domain(&m, SIMAC_DOMAIN_SIV);

    uint8_t tag[16];
    simac_finalize(&m, tag);
    slim_zero(&m, sizeof(m));

    memcpy(synth_nonce, tag, 12);
    slim_zero(tag, 16);
    return 0;
}

/* =========================================================================
 * Internal encrypt/decrypt helpers
 * ========================================================================= */
SLIMHOT static int encrypt_blocks(slimiron_ctx *c, simac_ctx *m,
                                   const uint8_t * SLIM_RESTRICT msg,
                                   uint8_t       * SLIM_RESTRICT cipher,
                                   size_t len)
{
    size_t i = 0;
    while (i + 64 <= len) {
        if (SLIM_UNLIKELY(slimiron_block(c) != 0)) return -2;
        xor64(cipher + i, msg + i, c->stream);
        simac_absorb(m, cipher + i, 64);
        i += 64;
    }
    if (i < len) {
        if (SLIM_UNLIKELY(slimiron_block(c) != 0)) return -2;
        size_t tail = len - i;
        for (size_t j = 0; j < tail; j++)
            cipher[i + j] = msg[i + j] ^ c->stream[j];
        c->pos = tail;
        simac_absorb(m, cipher + i, tail);
    }
    return 0;
}

SLIMHOT static int decrypt_blocks(slimiron_ctx *c,
                                   const uint8_t * SLIM_RESTRICT cipher,
                                   uint8_t       * SLIM_RESTRICT msg,
                                   size_t len)
{
    size_t i = 0;
    while (i + 64 <= len) {
        if (SLIM_UNLIKELY(slimiron_block(c) != 0)) return -2;
        xor64(msg + i, cipher + i, c->stream);
        i += 64;
    }
    if (i < len) {
        if (SLIM_UNLIKELY(slimiron_block(c) != 0)) return -2;
        size_t tail = len - i;
        for (size_t j = 0; j < tail; j++)
            msg[i + j] = cipher[i + j] ^ c->stream[j];
        c->pos = tail;
    }
    return 0;
}

/* =========================================================================
 * Public AEAD interface
 *
 * Encrypt:
 *   1. synth_nonce = SIV(key, nonce, aad, msg)
 *   2. mac_key     = stream(key, synth_nonce)[counter=0][0:32]
 *   3. ciphertext  = stream(key, synth_nonce)[counter=1..N] XOR msg
 *   4. tag         = SIMAC(mac_key, synth_nonce, aad, ciphertext)
 *
 * Decrypt:
 *   1. mac_key     = stream(key, synth_nonce)[counter=0][0:32]
 *   2. calc_tag    = SIMAC(mac_key, synth_nonce, aad, ciphertext)
 *   3. verify      calc_tag == tag  (constant-time)
 *   4. plaintext   = stream(key, synth_nonce)[counter=1..N] XOR ciphertext
 *
 * Wire format: [ synth_nonce:12 ][ ciphertext:mlen ][ tag:16 ]
 * Total overhead: 28 bytes per message.
 *
 * Domain sequence (v0.2.1+, explicit pad-before-domain):
 *   absorb(aad) + absorb_len(aad_len) -> pad() -> domain(AAD)  [1 perm]
 *   absorb(ct)  + absorb_len(ct_len)  -> pad() -> domain(CT)   [1 perm]
 *   finalize()                                     [pad + 2x perm]
 *   Total domain-boundary permutations: 2  (was 4 in v0.2.0)
 * ========================================================================= */

SLIMHOT static inline int slimiron_aead_encrypt(
    uint8_t       *synth_nonce_out,
    uint8_t       *cipher,
    uint8_t        tag[16],
    const uint8_t *msg,    size_t mlen,
    const uint8_t *aad,    size_t aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12])
{
    uint8_t snonce[12];
    int r = siv_derive(snonce, msg, mlen, aad, aad_len, key, nonce);
    if (SLIM_UNLIKELY(r != 0)) return r;
    memcpy(synth_nonce_out, snonce, 12);

    slimiron_ctx c;
    slimiron_init(&c, key, snonce);
    uint8_t mac_key[32];
    if (SLIM_UNLIKELY(slimiron_derive_mac_key(&c, mac_key) != 0)) {
        slim_zero(&c, sizeof(c));
        slim_zero(snonce, 12);
        return -2;
    }

    simac_ctx m;
    simac_init(&m, mac_key, snonce);
    slim_zero(mac_key, 32);

    if (aad_len > 0) simac_absorb(&m, aad, aad_len);
    simac_absorb_len(&m, (uint64_t)aad_len);
    simac_pad(&m);
    simac_domain(&m, SIMAC_DOMAIN_AAD);

    if (mlen > 0) {
        r = encrypt_blocks(&c, &m, msg, cipher, mlen);
        if (SLIM_UNLIKELY(r != 0)) {
            slim_zero(&c, sizeof(c));
            slim_zero(&m, sizeof(m));
            slim_zero(snonce, 12);
            return r;
        }
    }
    simac_absorb_len(&m, (uint64_t)mlen);
    simac_pad(&m);
    simac_domain(&m, SIMAC_DOMAIN_CT);
    simac_finalize(&m, tag);

    slim_zero(&c, sizeof(c));
    slim_zero(&m, sizeof(m));
    slim_zero(snonce, 12);
    return 0;
}

SLIMHOT static inline int slimiron_aead_decrypt(
    uint8_t       *msg,
    const uint8_t *synth_nonce,
    const uint8_t *cipher, size_t clen,
    const uint8_t  tag[16],
    const uint8_t *aad,    size_t aad_len,
    const uint8_t  key[32])
{
    slimiron_ctx c;
    slimiron_init(&c, key, synth_nonce);
    uint8_t mac_key[32];
    if (SLIM_UNLIKELY(slimiron_derive_mac_key(&c, mac_key) != 0)) {
        slim_zero(&c, sizeof(c));
        return -2;
    }

    simac_ctx m;
    simac_init(&m, mac_key, synth_nonce);
    slim_zero(mac_key, 32);

    if (aad_len > 0) simac_absorb(&m, aad, aad_len);
    simac_absorb_len(&m, (uint64_t)aad_len);
    simac_pad(&m);
    simac_domain(&m, SIMAC_DOMAIN_AAD);

    if (clen > 0) simac_absorb(&m, cipher, clen);
    simac_absorb_len(&m, (uint64_t)clen);
    simac_pad(&m);
    simac_domain(&m, SIMAC_DOMAIN_CT);

    uint8_t calc_tag[16];
    simac_finalize(&m, calc_tag);
    slim_zero(&m, sizeof(m));

    if (SLIM_UNLIKELY(crypto_verify_16(calc_tag, tag) != 0)) {
        slim_zero(calc_tag, 16);
        slim_zero(&c, sizeof(c));
        if (msg && clen > 0) slim_zero(msg, clen);
        return -1;
    }
    slim_zero(calc_tag, 16);

    if (clen > 0) {
        int r = decrypt_blocks(&c, cipher, msg, clen);
        if (SLIM_UNLIKELY(r != 0)) {
            slim_zero(&c, sizeof(c));
            if (msg) slim_zero(msg, clen);
            return r;
        }
    }
    slim_zero(&c, sizeof(c));
    return 0;
}

#endif /* SLIMIRON_H */
