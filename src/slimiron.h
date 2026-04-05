#ifndef SLIMIRON_H
#define SLIMIRON_H

/*
 * Slimiron + SIMAC  —  AEAD cipher (hobby project)
 * Version: 0.3.0
 *
 * WARNING: Hobby project. Not for production use. Not cryptanalyzed.
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
 * Fix #3 [SECURITY] Full 256-bit key in capacity region — v0.2.1  BREAKING
 *   State layout changed so all 8 key words live in state[8..15] permanently.
 *   Counter + nonce moved to state[0..3]. Old layout silently discarded K4..K7.
 *
 *   State layout (v0.2.1+):
 *     [  0] CTR     [  1] N0      [  2] N1      [  3] N2
 *     [  4] IV_0    [  5] IV_1    [  6] IV_2    [  7] IV_3
 *     [  8] K0      [  9] K1      [ 10] K2      [ 11] K3
 *     [ 12] K4      [ 13] K5      [ 14] K6      [ 15] K7
 *
 * Fix #4 [COMPAT] simac_absorb_len() big-endian — v0.2.1  BREAKING
 *   Length field now encoded big-endian (MSB first), matching TLS/HKDF/GCM.
 *
 * Fix #5 [PURITY] Self-bootstrapped constants — v0.2.2  BREAKING
 *   All initialization constants now derived from the Slimiron permutation
 *   itself.  SHA-256 dependency completely removed.
 *   Labels use suffix "-v5".  Verified by gen_constants.py.
 *
 * Fix #6 [SECURITY] Increase stream cipher rounds to 14 — v0.3.0  BREAKING
 *   SLIMIRON_ROUNDS raised from 10 to 14.  The 256-bit capacity argument
 *   applies to the SIMAC sponge, not to the counter-mode stream cipher where
 *   round count directly governs resistance to differential/linear attacks.
 *   14 rounds provides a more conservative margin.  SIMAC_ROUNDS unchanged.
 *
 * Fix #7 [CLARITY] simac_finalize() contract — v0.3.0
 *   Documented explicitly: simac_finalize() performs its OWN internal
 *   simac_pad() as the first step.  Callers must NOT call simac_pad() before
 *   simac_finalize(); only call simac_pad() before simac_domain().
 *
 * Fix #8 [CORRECTNESS] Removed unused pos field from slimiron_ctx — v0.3.0
 *   slimiron_ctx.pos was set inconsistently and never used by the streaming
 *   API (encrypt_blocks/decrypt_blocks use slimiron_block() directly and
 *   access ctx->stream[] without a pos offset).  Removed to prevent confusion.
 *
 * Fix #9 [SECURITY] Hardened crypto_verify_16() — v0.3.0
 *   Added SLIM_COMPILER_BARRIER() after the accumulation loop to prevent
 *   aggressive LTO/WPO from vectorizing the loop with predicated loads that
 *   could be non-constant-time on some microarchitectures.
 *
 * Fix #10 [CORRECTNESS] Removed inconsistent aad_len>0 guards — v0.3.0
 *   The `if (aad_len > 0)` guards before simac_absorb() were inconsistent
 *   between siv_derive() and the main encrypt/decrypt paths.
 *   simac_absorb(ctx, ptr, 0) is a documented no-op; the guards were removed
 *   for consistency.  An explicit `if (len == 0) return;` is now inside
 *   simac_absorb() itself as a single canonical guard.
 *
 * Fix #11 [CORRECTNESS] In-place aliasing guard — v0.3.0
 *   slimiron_aead_encrypt() now returns -3 if msg == cipher.
 *   SLIM_RESTRICT on encrypt_blocks() parameters forbids aliasing by C99
 *   contract; this runtime check makes the violation explicit rather than UB.
 *
 * Fix #12 [COMPAT] Version byte in wire format — v0.3.0  BREAKING
 *   Wire format now prefixed with SLIMIRON_WIRE_VERSION (1 byte = 0x03).
 *   slimiron_aead_decrypt() accepts the version byte as a parameter and
 *   returns -4 on mismatch before performing any cryptographic work.
 *   Total overhead: SLIMIRON_OVERHEAD = 29 bytes (1 + 12 + 16).
 *
 * ── Parameters ──────────────────────────────────────────────────────────────
 *   Key   : 256-bit
 *   Nonce : 96-bit  — unique per (key, message) recommended; misuse-resistant
 *   Tag   : 128-bit
 *
 * ── Return codes ────────────────────────────────────────────────────────────
 *    0   success
 *   -1   authentication failure (decrypt only; output buffer zeroed)
 *   -2   message too large (counter overflow)
 *   -3   aliasing error: msg == cipher (encrypt only)
 *   -4   version mismatch (decrypt only)
 *
 * ── Security properties ─────────────────────────────────────────────────────
 *   - Constant-time tag comparison (volatile accumulator + compiler barrier)
 *   - All key material zeroized on every return path
 *   - Compiler barrier prevents dead-store elimination of slim_zero()
 *   - Verify-first decryption (no plaintext released before tag check)
 *   - Nonce-misuse resistant: identical output only for identical inputs
 *   - Counter limit: 2^32 - 2 blocks (~256 GB) per (key, synth_nonce)
 *   - Full 256-bit key in permanent capacity region (no silent truncation)
 *   - In-place encrypt rejected (-3)
 *   - Wire version byte prevents cross-version ciphertext confusion (-4)
 *
 * ── Sponge parameters ───────────────────────────────────────────────────────
 *   Rate     = 32 bytes (8 words)  — state[0..7],  XORed with input
 *   Capacity = 32 bytes (8 words)  — state[8..15], never XORed with input
 *   Birthday bound: 2^128 (256-bit capacity)
 *
 * ── Wire format (v0.3.x) ────────────────────────────────────────────────────
 *   [ version:1 ][ synth_nonce:12 ][ ciphertext:mlen ][ tag:16 ]
 *   Total overhead: SLIMIRON_OVERHEAD = 29 bytes.
 *
 * ── Constant derivation ─────────────────────────────────────────────────────
 *   All constants = slimiron_bootstrap(label)[0:N] using SIMAC_ROUNDS (10).
 *   The bootstrap sponge always uses 10 rounds regardless of SLIMIRON_ROUNDS.
 *   Verified by gen_constants.py (pure Python, no hashlib).
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
 *
 * SLIMIRON_ROUNDS = 14 (stream cipher) — raised from 10 in v0.3.0.
 *   The 256-bit capacity margin argument is valid for the SIMAC sponge only.
 *   For the counter-mode stream cipher, round count directly governs
 *   resistance to differential and linear cryptanalysis.  14 rounds provides
 *   a more conservative margin without the full cost of ChaCha20's 20 rounds.
 *   NOTE: SlimMix rotations were selected by avalanche sweep, not by
 *   differential/linear analysis.  No formal security proof exists.
 *
 * SIMAC_ROUNDS = 10 (sponge MAC) — unchanged.
 *   256-bit capacity -> birthday bound 2^128.  10 rounds adequate.
 *
 * IMPORTANT: The bootstrap sponge that derives constants always uses
 * SIMAC_ROUNDS (10), not SLIMIRON_ROUNDS.  Changing SLIMIRON_ROUNDS does
 * NOT invalidate the constants — only changing SIMAC_ROUNDS would.
 * ------------------------------------------------------------------------- */
#define SLIMIRON_ROUNDS  14
#define SIMAC_ROUNDS     10

/* -------------------------------------------------------------------------
 * Wire format constants
 * ------------------------------------------------------------------------- */
#define SLIMIRON_WIRE_VERSION  0x03u   /* version tag — 1 byte at wire start */
#define SLIMIRON_OVERHEAD      29u     /* 1 version + 12 synth_nonce + 16 tag */

/* -------------------------------------------------------------------------
 * Initialization constants — slimiron_bootstrap(label)[0:N]
 *   Derived purely from the Slimiron permutation (SlimMix ARX, SIMAC_ROUNDS).
 *   No external hash function.  Verified by gen_constants.py.
 * ------------------------------------------------------------------------- */

/* SLIMIRON_IV_[0-3]  <- slimiron_bootstrap("slimiron-stream-v5")[0:4] */
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
#define SIMAC_DOMAIN_AAD  0x8439c00fu
#define SIMAC_DOMAIN_CT   0x35ef9605u
#define SIMAC_DOMAIN_SIV  0x493ccf67u

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
 *
 * slimiron_ctx:
 *   state[16] — persistent cipher state; state[0] = current counter.
 *   stream[64] — keystream block filled by the most recent slimiron_block().
 *
 *   NOTE: There is intentionally no pos field.  The encrypt/decrypt helpers
 *   always call slimiron_block() for each block and index stream[] directly.
 *   A pos field was present in v0.2.x but was set inconsistently and never
 *   consumed by the streaming API; it has been removed (Fix #8).
 * ------------------------------------------------------------------------- */
typedef struct {
    uint32_t state[16];
    uint8_t  stream[64];
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
 *
 * volatile accumulator: prevents early-exit short-circuit at -O3.
 * SLIM_COMPILER_BARRIER(): prevents LTO/WPO from vectorizing with predicated
 *   loads that may be non-constant-time on some microarchitectures.
 * ------------------------------------------------------------------------- */
SLIMFORCE int crypto_verify_16(const uint8_t *a, const uint8_t *b) {
    volatile uint8_t diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= a[i] ^ b[i];
    SLIM_COMPILER_BARRIER();
    return (diff == 0) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * SlimMix -- ARX quarter-round
 *
 * Rotation constants (15, 11, 9, 5): selected via 142-candidate exhaustive
 * sweep for full 512-bit avalanche quality at double-round 2.  All odd
 * (gcd(rot,32)=1 for all odd values → invertible); non-repeating.
 *
 * LIMITATION: Constants were selected by avalanche sweep only.  No
 * differential or linear cryptanalysis has been performed on SlimMix.
 * Avalanche quality is necessary but not sufficient for cryptographic security.
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
    ctx->state[0] = 0;                    /* counter starts at 0 */
    ctx->state[1] = load32_le(nonce + 0); /* N0 */
    ctx->state[2] = load32_le(nonce + 4); /* N1 */
    ctx->state[3] = load32_le(nonce + 8); /* N2 */
    ctx->state[4] = SLIMIRON_IV_0;
    ctx->state[5] = SLIMIRON_IV_1;
    ctx->state[6] = SLIMIRON_IV_2;
    ctx->state[7] = SLIMIRON_IV_3;
    /* Capacity: full 256-bit key -- never overwritten by absorb or counter */
    for (int i = 0; i < 8; i++)
        ctx->state[8 + i] = load32_le(key + i * 4);
}

/* Generate one 64-byte keystream block into ctx->stream[].
 * Returns 0 on success, -2 if counter limit exceeded. */
SLIMFORCE int slimiron_block(slimiron_ctx *ctx) {
    if (SLIM_UNLIKELY(ctx->state[0] > SLIMIRON_MAX_COUNTER))
        return -2;
    uint32_t x[16];
    memcpy(x, ctx->state, 64);
    permute(x, SLIMIRON_ROUNDS);
    for (int i = 0; i < 16; i++) {
        x[i] += ctx->state[i];        /* add-back prevents state inversion */
        store32_le(ctx->stream + i * 4, x[i]);
    }
    ctx->state[0]++;                   /* advance counter */
    return 0;
}

/* Consume counter slot 0 to derive a 32-byte MAC key.
 * Subsequent slimiron_block() calls (counter >= 1) generate keystream. */
SLIMFORCE int slimiron_derive_mac_key(slimiron_ctx *ctx, uint8_t mac_key[32]) {
    int r = slimiron_block(ctx);       /* fills ctx->stream; counter 0 -> 1 */
    if (r != 0) return r;
    memcpy(mac_key, ctx->stream, 32);  /* first half of block 0 only */
    return 0;
}

/* =========================================================================
 * SIMAC -- sponge-based MAC (32-byte capacity)
 *
 * State after simac_init():
 *   [  0.. 7] rate      -- XORed with absorbed input (32 bytes)
 *   [  8..15] capacity  -- never touched by the absorb path
 *
 * ── Calling contract ─────────────────────────────────────────────────────
 *
 *   Per logical input field:
 *     simac_absorb(data, len)
 *     simac_absorb_len(len)     [64-bit big-endian length commitment]
 *     simac_pad()               [two-marker padding + compress]
 *     simac_domain(DOMAIN_X)   [capacity XOR + permute]
 *
 *   Final squeeze:
 *     simac_finalize(tag)
 *
 *   CRITICAL: simac_finalize() calls simac_pad() internally as its FIRST
 *   step.  Do NOT call simac_pad() before simac_finalize().  Only call
 *   simac_pad() before simac_domain().
 * ========================================================================= */

SLIMFORCE void simac_init(simac_ctx *ctx,
                          const uint8_t mac_key[32],
                          const uint8_t nonce[12])
{
    /* Rate: load 256-bit MAC key */
    for (int i = 0; i < 8; i++)
        ctx->state[i] = load32_le(mac_key + i * 4);
    /* Capacity: derived constants XOR nonce for per-nonce uniqueness */
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

/* Compress one full rate block from a pointer (fast path, no buffer copy) */
SLIMFORCE void simac_compress(simac_ctx *ctx, const uint8_t *block) {
    for (int i = 0; i < SIMAC_RATE_WORDS; i++)
        ctx->state[i] ^= load32_le(block + i * 4);
    permute(ctx->state, SIMAC_ROUNDS);
}

/* Flush internal buffer into state */
SLIMFORCE void simac_block(simac_ctx *ctx) {
    simac_compress(ctx, ctx->buffer);
    memset(ctx->buffer, 0, SIMAC_RATE_BYTES);
    ctx->pos = 0;
}

/* Absorb arbitrary-length data into the sponge.
 * Zero-length absorb is a canonical no-op (single guard inside). */
SLIMHOT SLIMFORCE void simac_absorb(simac_ctx *ctx,
                                    const uint8_t *data, size_t len)
{
    if (len == 0) return;   /* canonical no-op — no guard needed at call sites */
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
    /* Fast path: full blocks bypass the buffer */
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

/* Absorb a 64-bit length commitment, big-endian (MSB first).
 * Matches standard cryptographic convention (TLS, HKDF, GCM). */
SLIMFORCE void simac_absorb_len(simac_ctx *ctx, uint64_t len) {
    uint8_t tmp[8];
    for (int i = 0; i < 8; i++) tmp[i] = (uint8_t)(len >> (56 - 8 * i));
    simac_absorb(ctx, tmp, 8);
}

/* Two-marker padding: 0x01 at current pos, 0x80 at last rate byte.
 * When pos == SIMAC_RATE_BYTES-1: both land on same byte -> 0x81.
 * MUST be called before simac_domain().
 * Do NOT call before simac_finalize() — finalize pads internally. */
SLIMFORCE void simac_pad(simac_ctx *ctx) {
    ctx->buffer[ctx->pos] ^= 0x01;
    ctx->buffer[SIMAC_RATE_BYTES - 1] ^= 0x80;
    simac_block(ctx);
}

/* Apply domain separator into the capacity region.
 * Caller MUST have called simac_pad() immediately before this.
 * XORs constant into state[8] (first capacity word — unreachable by absorb)
 * then runs one full permutation. */
SLIMFORCE void simac_domain(simac_ctx *ctx, uint32_t dom) {
    ctx->state[8] ^= dom;
    permute(ctx->state, SIMAC_ROUNDS);
}

/* Squeeze 128-bit authentication tag.
 *
 * MUST be called after the last simac_domain() call.
 * Do NOT call simac_pad() before this — finalize calls it internally.
 *
 * Internal steps:
 *   1. simac_pad()          — pad remaining buffer + compress
 *   2. XOR SIMAC_FINAL mask — 256-bit mask into full capacity region
 *   3. permute x2           — double permutation before squeeze
 *   4. squeeze state[0..3]  — 128-bit (4-word) tag output
 */
SLIMFORCE void simac_finalize(simac_ctx *ctx, uint8_t tag[16]) {
    simac_pad(ctx);   /* internal pad — caller must NOT pad before this call */
    ctx->state[ 8] ^= SIMAC_FINAL_0;
    ctx->state[ 9] ^= SIMAC_FINAL_1;
    ctx->state[10] ^= SIMAC_FINAL_2;
    ctx->state[11] ^= SIMAC_FINAL_3;
    ctx->state[12] ^= SIMAC_FINAL_4;
    ctx->state[13] ^= SIMAC_FINAL_5;
    ctx->state[14] ^= SIMAC_FINAL_6;
    ctx->state[15] ^= SIMAC_FINAL_7;
    permute(ctx->state, SIMAC_ROUNDS);
    permute(ctx->state, SIMAC_ROUNDS);  /* double permute before squeeze */
    for (int i = 0; i < 4; i++)
        store32_le(tag + i * 4, ctx->state[i]);
}

/* =========================================================================
 * XOR 64-byte block — AVX2 path when available, else scalar 8x8-byte
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
 * SIV — Synthetic IV derivation (nonce-misuse resistance)
 *
 * synth_nonce = SIMAC_SIV(key, nonce, aad, msg)[0:12]
 *
 * Properties:
 *   - Same (key, nonce, aad, msg) -> same synth_nonce (deterministic)
 *   - Different msg with same nonce -> different synth_nonce
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

    /* Absorb: original nonce || aad || aad_len || msg || mlen */
    simac_absorb(&m, nonce, 12);
    simac_absorb(&m, aad, aad_len);         /* no-op if aad_len == 0 */
    simac_absorb_len(&m, (uint64_t)aad_len);
    simac_absorb(&m, msg, mlen);            /* no-op if mlen == 0 */
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
SLIMHOT static int encrypt_blocks(slimiron_ctx *c,
                                   simac_ctx *m,
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
    }
    return 0;
}

/* =========================================================================
 * Public AEAD interface
 *
 * Wire format (v0.3.x):
 *   [ version:1 ][ synth_nonce:12 ][ ciphertext:mlen ][ tag:16 ]
 *   Total overhead: SLIMIRON_OVERHEAD = 29 bytes.
 *
 * Encrypt:
 *   1. synth_nonce = SIV(key, nonce, aad, msg)
 *   2. mac_key     = stream(key, synth_nonce)[counter=0][0:32]
 *   3. ciphertext  = stream(key, synth_nonce)[counter=1..N] XOR msg
 *   4. tag         = SIMAC(mac_key, synth_nonce, aad, ciphertext)
 *
 * Decrypt:
 *   0. Check wire_version == SLIMIRON_WIRE_VERSION  -> -4 on mismatch
 *   1. mac_key     = stream(key, synth_nonce)[counter=0][0:32]
 *   2. calc_tag    = SIMAC(mac_key, synth_nonce, aad, ciphertext)
 *   3. verify      calc_tag == tag  (constant-time)           -> -1 on fail
 *   4. plaintext   = stream(key, synth_nonce)[counter=1..N] XOR ciphertext
 *
 * Return codes:
 *    0   success
 *   -1   authentication failure (output zeroed)
 *   -2   message too large (counter overflow)
 *   -3   aliasing error: msg == cipher (encrypt only)
 *   -4   version mismatch (decrypt only)
 *
 * Domain sequence (explicit pad-before-domain):
 *   absorb(aad) + absorb_len(aad_len) -> pad() -> domain(AAD)  [1 perm]
 *   absorb(ct)  + absorb_len(ct_len)  -> pad() -> domain(CT)   [1 perm]
 *   finalize()    [pad + mask + 2x perm — all internal]
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
    /* Fix #11: reject in-place aliasing.
     * SLIM_RESTRICT on encrypt_blocks() forbids aliasing by C99 contract;
     * this check makes the violation explicit rather than silent UB. */
    if (SLIM_UNLIKELY(mlen > 0 && msg == cipher))
        return -3;

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

    /* AAD — absorb_len always absorbed (zero-length is well-defined) */
    simac_absorb(&m, aad, aad_len);
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
    simac_finalize(&m, tag);   /* finalize does its own internal pad */

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
    const uint8_t  key[32],
    uint8_t        wire_version)
{
    /* Fix #12: reject mismatched version before any cryptographic work */
    if (SLIM_UNLIKELY(wire_version != SLIMIRON_WIRE_VERSION))
        return -4;

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

    /* AAD */
    simac_absorb(&m, aad, aad_len);
    simac_absorb_len(&m, (uint64_t)aad_len);
    simac_pad(&m);
    simac_domain(&m, SIMAC_DOMAIN_AAD);

    /* Ciphertext */
    simac_absorb(&m, cipher, clen);
    simac_absorb_len(&m, (uint64_t)clen);
    simac_pad(&m);
    simac_domain(&m, SIMAC_DOMAIN_CT);

    uint8_t calc_tag[16];
    simac_finalize(&m, calc_tag);   /* finalize does its own internal pad */
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