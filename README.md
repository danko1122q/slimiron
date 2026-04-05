# Slimiron

**Hobby AEAD cipher — not for production use.**

Slimiron is a from-scratch authenticated encryption (AEAD) scheme built as a learning project. It combines two original primitives:

- **SlimMix** — ARX quarter-round (rotations: 15, 11, 9, 5)
- **SIMAC** — duplex-sponge MAC with 256-bit capacity

No external dependencies. Single header file.

## Parameters

| Parameter | Value |
|-----------|-------|
| Key | 256-bit |
| Nonce | 96-bit (misuse-resistant via SIV) |
| Tag | 128-bit |
| Overhead | 29 bytes (1 version + 12 synth\_nonce + 16 tag) |
| Max message | ~256 GB per (key, synth\_nonce) |
| Stream rounds | 14 |
| SIMAC rounds | 10 |
| SIMAC rate/capacity | 32 / 32 bytes |

## API

```c
#include "slimiron.h"

// Encrypt
int slimiron_aead_encrypt(
    uint8_t       *synth_nonce_out,   // 12 bytes out
    uint8_t       *cipher,            // mlen bytes out (must not alias msg)
    uint8_t        tag[16],           // 16 bytes out
    const uint8_t *msg,    size_t mlen,
    const uint8_t *aad,    size_t aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12]);

// Decrypt — verifies tag before releasing plaintext
int slimiron_aead_decrypt(
    uint8_t       *msg,               // mlen bytes out (zeroed on failure)
    const uint8_t *synth_nonce,       // 12 bytes in
    const uint8_t *cipher, size_t clen,
    const uint8_t  tag[16],
    const uint8_t *aad,    size_t aad_len,
    const uint8_t  key[32],
    uint8_t        wire_version);     // pass SLIMIRON_WIRE_VERSION
```

Return codes: `0` success, `-1` auth failure (output zeroed), `-2` message too large,
`-3` aliasing error (msg == cipher), `-4` version mismatch.

## Usage

```c
uint8_t key[32]   = { /* your key */ };
uint8_t nonce[12] = { /* your nonce */ };

// Encrypt
uint8_t snonce[12], tag[16];
uint8_t cipher[mlen];
slimiron_aead_encrypt(snonce, cipher, tag, msg, mlen, aad, aad_len, key, nonce);

// Decrypt
uint8_t plain[clen];
int r = slimiron_aead_decrypt(plain, snonce, cipher, clen, tag, aad, aad_len, key,
                               SLIMIRON_WIRE_VERSION);
if (r != 0) { /* authentication failed */ }
```

Wire format: `[ version:1 ][ synth_nonce:12 ][ ciphertext:mlen ][ tag:16 ]`

## Build & Test

```sh
make           # build test + bench
make run-test  # run test suite (41 tests)
make run-bench # benchmark

python3 gen_constants.py  # verify all constants
```

Requires: C99 compiler. AVX2 detected automatically via `-march=native`.

## Benchmark

Measured on GitHub Codespace (4-core, 16 GB RAM), AVX2 enabled, 14 stream rounds:

```
Encrypt :  162 MB/s  (AVX2)
Decrypt :  261 MB/s  (AVX2)
```

Encrypt is slower because SIV requires an extra SIMAC pass over the plaintext.
Stream rounds raised from 10 to 14 in v0.3.0 — ~25% overhead increase vs v0.2.2.

## Design Notes

- **SIV (Synthetic IV)** — the actual encryption nonce is derived from `SIMAC(key, nonce, aad, msg)`, so nonce reuse with different messages is safe.
- **Verify-first decryption** — plaintext is never released before the tag passes.
- **Self-bootstrapped constants** — all IV/MAC constants derived from the Slimiron permutation itself (no SHA-256). Verified by `gen_constants.py`.
- **Full 256-bit key** in the sponge capacity region (never XORed with data).
- **Wire version byte** — `SLIMIRON_WIRE_VERSION` (0x03) prefixes every ciphertext; decrypt rejects mismatched versions before doing any crypto work.
- **In-place aliasing rejected** — `slimiron_aead_encrypt` returns `-3` if `msg == cipher`.

See `docs/slimiron_design.docx` for full design and math.

## Warning

This has **not** been cryptanalyzed. SlimMix is a novel construction — rotation constants were selected by avalanche sweep only, not by differential or linear analysis. Do not use for anything real.

## Changelog

### v0.3.0 (current)
- **[SECURITY]** Stream rounds raised 10 → 14 (capacity argument applies to sponge, not stream cipher) — **BREAKING**
- **[COMPAT]** Wire format now includes 1-byte version tag `SLIMIRON_WIRE_VERSION`; `slimiron_aead_decrypt` gains `wire_version` parameter — **BREAKING**
- **[CORRECTNESS]** `slimiron_aead_encrypt` returns `-3` if `msg == cipher` (aliasing UB guard)
- **[SECURITY]** `crypto_verify_16` hardened with `SLIM_COMPILER_BARRIER()` after accumulation loop
- **[CORRECTNESS]** Removed `pos` field from `slimiron_ctx` (was set inconsistently, never used)
- **[CORRECTNESS]** Removed inconsistent `if (aad_len > 0)` guards; `simac_absorb(len=0)` is now canonical no-op
- **[CLARITY]** `simac_finalize()` contract documented: performs its own internal `simac_pad()` — callers must not pad before it

### v0.2.2
- Self-bootstrapped constants; SHA-256 dependency removed — BREAKING

### v0.2.1
- Full 256-bit key in capacity region — BREAKING
- `simac_absorb_len()` big-endian — BREAKING
- `simac_domain()` no longer calls `simac_pad()` internally (perf)
- `slim_zero()` compiler barrier
