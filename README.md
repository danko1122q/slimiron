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
| Overhead | 28 bytes (12 synth_nonce + 16 tag) |
| Max message | ~256 GB per (key, synth\_nonce) |
| Stream rounds | 10 |
| SIMAC rounds | 10 |
| SIMAC rate/capacity | 32 / 32 bytes |

## API

```c
#include "slimiron.h"

// Encrypt
int slimiron_aead_encrypt(
    uint8_t       *synth_nonce_out,   // 12 bytes out
    uint8_t       *cipher,            // mlen bytes out
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
    const uint8_t  key[32]);
```

Return codes: `0` success, `-1` auth failure (output zeroed), `-2` message too large.

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
int r = slimiron_aead_decrypt(plain, snonce, cipher, clen, tag, aad, aad_len, key);
if (r != 0) { /* authentication failed */ }
```

Wire format: `[ synth_nonce:12 ][ ciphertext:mlen ][ tag:16 ]`

## Build & Test

```sh
make          # build test + bench
make run-test # run test suite (32 tests)
make run-bench # benchmark

python3 gen_constants.py  # verify all constants
```

Requires: C99 compiler. AVX2 detected automatically via `-march=native`.

## Design Notes

- **SIV (Synthetic IV)** — the actual encryption nonce is derived from `SIMAC(key, nonce, aad, msg)`, so nonce reuse with different messages is safe (different synth\_nonce → different keystream).
- **Verify-first decryption** — plaintext is never released before the tag passes.
- **Self-bootstrapped constants** — all IV/MAC constants derived from the Slimiron permutation itself (no SHA-256). Verified by `gen_constants.py`.
- **Full 256-bit key** in the sponge capacity region (never XORed with data).

See `docs/slimiron_design.docx` for full design and math.

## Benchmark

```
Encrypt :  146 MB/s  (scalar, no AVX2)
Decrypt :  252 MB/s
```

Encrypt is slower because SIV requires an extra SIMAC pass over the plaintext.

## Warning

This has **not** been cryptanalyzed. SlimMix is a novel construction. Do not use for anything real.
