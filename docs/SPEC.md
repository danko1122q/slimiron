# Slimiron Specification

**Version:** 1.1 (algorithm version 0.3.0)  
**Status:** Draft — hobby project, not for production use

This document defines the Slimiron AEAD algorithm precisely enough to implement
independently in any language. The reference implementation is `slimiron.h` (C99).

---

## Table of Contents

1. [Notation](#1-notation)
2. [SlimMix — ARX Quarter-Round](#2-slimmix--arx-quarter-round)
3. [Permutation](#3-permutation)
4. [Slimiron Stream Cipher](#4-slimiron-stream-cipher)
5. [SIMAC — Sponge MAC](#5-simac--sponge-mac)
6. [SIV — Synthetic IV](#6-siv--synthetic-iv)
7. [AEAD Interface](#7-aead-interface)
8. [Constants](#8-constants)
9. [Test Vectors](#9-test-vectors)

---

## 1. Notation

| Symbol | Meaning |
|--------|---------|
| `+` | Addition mod 2³² |
| `⊕` | Bitwise XOR |
| `⋘ n` | Left rotation by n bits (32-bit word) |
| `LE32(b)` | Decode 4 bytes little-endian → uint32 |
| `LE32_enc(w)` | Encode uint32 → 4 bytes little-endian |
| `\|\|` | Concatenation |
| `[0]×n` | n zero bytes |

All integer arithmetic is unsigned 32-bit unless stated otherwise.  
State is an array of sixteen 32-bit words: `s[0..15]`.

---

## 2. SlimMix — ARX Quarter-Round

SlimMix takes four 32-bit words `(a, b, c, d)` and returns four words:

```
a ← a + b
d ← d ⊕ a
d ← d ⋘ 15

c ← c + d
b ← b ⊕ c
b ← b ⋘ 11

a ← a + b
d ← d ⊕ a
d ← d ⋘ 9

c ← c + d
b ← b ⊕ c
b ← b ⋘ 5

return (a, b, c, d)
```

Rotation constants `(15, 11, 9, 5)` — all odd, non-repeating, selected for
full avalanche at double-round 2 via exhaustive 142-candidate sweep.

**Limitation:** Constants selected by avalanche sweep only. No differential or
linear cryptanalysis has been performed on SlimMix.

---

## 3. Permutation

`permute(s[16], rounds)` applies `rounds/2` double-rounds to the state.
`rounds` must be even.

```
for i in 0 .. rounds/2:

  // Column round
  (s[ 0], s[ 4], s[ 8], s[12]) ← SlimMix(s[ 0], s[ 4], s[ 8], s[12])
  (s[ 1], s[ 5], s[ 9], s[13]) ← SlimMix(s[ 1], s[ 5], s[ 9], s[13])
  (s[ 2], s[ 6], s[10], s[14]) ← SlimMix(s[ 2], s[ 6], s[10], s[14])
  (s[ 3], s[ 7], s[11], s[15]) ← SlimMix(s[ 3], s[ 7], s[11], s[15])

  // Diagonal round
  (s[ 0], s[ 5], s[10], s[15]) ← SlimMix(s[ 0], s[ 5], s[10], s[15])
  (s[ 1], s[ 6], s[11], s[12]) ← SlimMix(s[ 1], s[ 6], s[11], s[12])
  (s[ 2], s[ 7], s[ 8], s[13]) ← SlimMix(s[ 2], s[ 7], s[ 8], s[13])
  (s[ 3], s[ 4], s[ 9], s[14]) ← SlimMix(s[ 3], s[ 4], s[ 9], s[14])
```

Default rounds: **14 for stream cipher**, **10 for SIMAC**.

---

## 4. Slimiron Stream Cipher

### 4.1 State Layout

```
s[ 0] = CTR              // counter, starts at 0
s[ 1] = LE32(nonce[0..3])
s[ 2] = LE32(nonce[4..7])
s[ 3] = LE32(nonce[8..11])
s[ 4] = IV_0             // constant — see §8
s[ 5] = IV_1
s[ 6] = IV_2
s[ 7] = IV_3
s[ 8] = LE32(key[0..3])
s[ 9] = LE32(key[4..7])
...
s[15] = LE32(key[28..31])
```

`s[0..7]` = rate region (counter + nonce + IV).  
`s[8..15]` = capacity region (full 256-bit key, never overwritten).

### 4.2 Block Generation

`MAX_COUNTER = 0xFFFFFFFE` (2³² − 2).

```
slimiron_block(ctx) → keystream[64] | error:
  if ctx.s[0] > MAX_COUNTER: return ERROR_TOO_LARGE
  x ← copy(ctx.s)
  x ← permute(x, 14)                   // 14 rounds (v0.3.0+)
  for i in 0..15:
    x[i] ← x[i] + ctx.s[i]            // add-back prevents inversion
    keystream[i*4..(i+1)*4] ← LE32_enc(x[i])
  ctx.s[0] ← ctx.s[0] + 1             // increment counter
  return keystream
```

### 4.3 MAC Key Derivation

```
derive_mac_key(ctx) → mac_key[32]:
  keystream ← slimiron_block(ctx)      // consumes counter 0
  return keystream[0..31]              // first 32 bytes only
  // counter is now 1; subsequent blocks used for encryption
```

---

## 5. SIMAC — Sponge MAC

**Parameters:** rate = 32 bytes (8 words), capacity = 32 bytes (8 words),
rounds = 10, birthday bound = 2¹²⁸.

### 5.1 Initialization

```
simac_init(mac_key[32], nonce[12]) → ctx:
  ctx.s[0..7]  ← LE32(mac_key[0..31])
  ctx.s[ 8]    ← SIMAC_INIT_0 ⊕ LE32(nonce[0..3])
  ctx.s[ 9]    ← SIMAC_INIT_1 ⊕ LE32(nonce[4..7])
  ctx.s[10]    ← SIMAC_INIT_2 ⊕ LE32(nonce[8..11])
  ctx.s[11]    ← SIMAC_INIT_3
  ctx.s[12]    ← SIMAC_INIT_4
  ctx.s[13]    ← SIMAC_INIT_5
  ctx.s[14]    ← SIMAC_INIT_6
  ctx.s[15]    ← SIMAC_INIT_7
  ctx.s        ← permute(ctx.s, 10)
  ctx.buf      ← [0]×32
  ctx.pos      ← 0
```

### 5.2 Compress

```
compress(ctx):
  for i in 0..7: ctx.s[i] ← ctx.s[i] ⊕ LE32(ctx.buf[i*4..])
  ctx.s ← permute(ctx.s, 10)
  ctx.buf ← [0]×32
  ctx.pos ← 0
```

### 5.3 Absorb

Zero-length absorb is a no-op.

```
simac_absorb(ctx, data, len):
  if len == 0: return
  // Fill partial buffer
  if ctx.pos > 0:
    want ← 32 - ctx.pos
    if len < want:
      ctx.buf[ctx.pos..ctx.pos+len] ← data[0..len]
      ctx.pos ← ctx.pos + len
      return
    ctx.buf[ctx.pos..32] ← data[0..want]
    data ← data[want..]; len ← len - want
    compress(ctx)

  // Full blocks (fast path)
  while len >= 32:
    for i in 0..7: ctx.s[i] ← ctx.s[i] ⊕ LE32(data[i*4..])
    ctx.s ← permute(ctx.s, 10)
    data ← data[32..]; len ← len - 32

  // Remaining partial block
  if len > 0:
    ctx.buf[0..len] ← data[0..len]
    ctx.pos ← len
```

### 5.4 Absorb Length

Absorbs a 64-bit length field, **big-endian** (MSB first, 8 bytes):

```
simac_absorb_len(ctx, n: uint64):
  tmp[0] ← (n >> 56) & 0xFF
  ...
  tmp[7] ← (n >>  0) & 0xFF
  simac_absorb(ctx, tmp, 8)
```

### 5.5 Padding

```
simac_pad(ctx):
  ctx.buf[ctx.pos]  ← ctx.buf[ctx.pos] ⊕ 0x01
  ctx.buf[31]       ← ctx.buf[31]      ⊕ 0x80
  compress(ctx)
```

When `pos == 31`: both markers land on same byte → `0x81`.

### 5.6 Domain Separation

Caller must call `simac_pad()` before this. XORs constant into first capacity
word (`s[8]`) only, then permutes.

```
simac_domain(ctx, dom: uint32):
  ctx.s[8] ← ctx.s[8] ⊕ dom
  ctx.s    ← permute(ctx.s, 10)
```

### 5.7 Finalize

**Contract:** Call after the last `simac_domain()`. Do NOT call `simac_pad()`
before this — finalize performs its own internal pad as the first step.

```
simac_finalize(ctx) → tag[16]:
  simac_pad(ctx)                       // internal pad — caller must not pre-pad
  ctx.s[ 8] ← ctx.s[ 8] ⊕ SIMAC_FINAL_0
  ...
  ctx.s[15] ← ctx.s[15] ⊕ SIMAC_FINAL_7
  ctx.s ← permute(ctx.s, 10)
  ctx.s ← permute(ctx.s, 10)          // double permute before squeeze
  tag ← LE32_enc(ctx.s[0]) || LE32_enc(ctx.s[1])
      || LE32_enc(ctx.s[2]) || LE32_enc(ctx.s[3])
  return tag
```

---

## 6. SIV — Synthetic IV

```
siv_derive(key[32], nonce[12], aad, aad_len, msg, mlen) → synth_nonce[12]:
  c       ← slimiron_init(key, nonce)
  siv_key ← derive_mac_key(c)
  zero(c)

  m ← simac_init(siv_key, nonce)
  zero(siv_key)

  simac_absorb(m, nonce, 12)
  simac_absorb(m, aad, aad_len)        // no-op if aad_len == 0
  simac_absorb_len(m, aad_len)
  simac_absorb(m, msg, mlen)           // no-op if mlen == 0
  simac_absorb_len(m, mlen)
  simac_pad(m)
  simac_domain(m, DOMAIN_SIV)
  tag ← simac_finalize(m)
  zero(m)

  return tag[0..11]
```

---

## 7. AEAD Interface

### 7.1 Wire Format

```
[ version:1 ][ synth_nonce:12 ][ ciphertext:mlen ][ tag:16 ]
```

Total overhead: **29 bytes**. `version` = `SLIMIRON_WIRE_VERSION` = `0x03`.

### 7.2 Encrypt

```
encrypt(key[32], nonce[12], msg, mlen, aad, aad_len)
    → (synth_nonce[12], ciphertext[mlen], tag[16]) | error:

  if msg == cipher and mlen > 0: return ERROR_ALIAS

  synth_nonce ← siv_derive(key, nonce, aad, aad_len, msg, mlen)

  c       ← slimiron_init(key, synth_nonce)
  mac_key ← derive_mac_key(c)           // counter 0

  m ← simac_init(mac_key, synth_nonce)
  zero(mac_key)

  simac_absorb(m, aad, aad_len)
  simac_absorb_len(m, aad_len)
  simac_pad(m)
  simac_domain(m, DOMAIN_AAD)

  // Encrypt blocks + absorb ciphertext
  i ← 0
  while i + 64 <= mlen:
    ks          ← slimiron_block(c)
    ct[i..i+64] ← msg[i..i+64] ⊕ ks
    simac_absorb(m, ct[i..i+64], 64)
    i ← i + 64
  if i < mlen:
    ks          ← slimiron_block(c)
    ct[i..mlen] ← msg[i..mlen] ⊕ ks[0..mlen-i]
    simac_absorb(m, ct[i..mlen], mlen-i)

  simac_absorb_len(m, mlen)
  simac_pad(m)
  simac_domain(m, DOMAIN_CT)
  tag ← simac_finalize(m)              // finalize pads internally

  zero(c); zero(m)
  return (synth_nonce, ciphertext, tag)
```

### 7.3 Decrypt

```
decrypt(key[32], wire_version, synth_nonce[12], ciphertext, clen, tag[16], aad, aad_len)
    → plaintext[clen] | FAIL:

  if wire_version != SLIMIRON_WIRE_VERSION: return ERROR_VERSION

  c       ← slimiron_init(key, synth_nonce)
  mac_key ← derive_mac_key(c)

  m ← simac_init(mac_key, synth_nonce)
  zero(mac_key)

  simac_absorb(m, aad, aad_len)
  simac_absorb_len(m, aad_len)
  simac_pad(m)
  simac_domain(m, DOMAIN_AAD)

  simac_absorb(m, ciphertext, clen)
  simac_absorb_len(m, clen)
  simac_pad(m)
  simac_domain(m, DOMAIN_CT)
  calc_tag ← simac_finalize(m)
  zero(m)

  // Verify BEFORE decrypting
  if not constant_time_equal(calc_tag, tag):
    zero(calc_tag); zero(c)
    zero(output, clen)
    return FAIL

  // Decrypt
  i ← 0
  while i + 64 <= clen:
    ks           ← slimiron_block(c)
    msg[i..i+64] ← ciphertext[i..i+64] ⊕ ks
    i ← i + 64
  if i < clen:
    ks           ← slimiron_block(c)
    msg[i..clen] ← ciphertext[i..clen] ⊕ ks[0..clen-i]

  zero(c)
  return msg
```

### 7.4 Return Codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `-1` | Authentication failure — output zeroed |
| `-2` | Message too large (counter overflow) |
| `-3` | Aliasing error: msg == cipher |
| `-4` | Wire version mismatch |

---

## 8. Constants

All constants derived from the Slimiron permutation via `bootstrap(label)`.
The bootstrap sponge always uses **10 rounds** regardless of `SLIMIRON_ROUNDS`.

### 8.1 Bootstrap Procedure

```
bootstrap(label: ASCII string, n: int) → words[n]:
  s   ← [0]×16
  buf ← [0]×32
  pos ← 0

  for byte in label:
    buf[pos] ← buf[pos] ⊕ byte
    pos ← pos + 1
    if pos == 32:
      for i in 0..7: s[i] ← s[i] ⊕ LE32(buf[i*4..])
      s   ← permute(s, 10)
      buf ← [0]×32
      pos ← 0

  buf[pos] ← buf[pos] ⊕ 0x01
  buf[31]  ← buf[31]  ⊕ 0x80
  for i in 0..7: s[i] ← s[i] ⊕ LE32(buf[i*4..])
  s ← permute(s, 10)

  return s[0..n-1]
```

### 8.2 Constant Table

| Constant | Label | Value |
|----------|-------|-------|
| `IV_0` | `slimiron-stream-v5` | `0xb9e3ef7f` |
| `IV_1` | `slimiron-stream-v5` | `0x7638101d` |
| `IV_2` | `slimiron-stream-v5` | `0x53373520` |
| `IV_3` | `slimiron-stream-v5` | `0x654cbc86` |
| `SIMAC_INIT_0..7` | `simac-init-v5` | (8 words — see header) |
| `SIMAC_FINAL_0..7` | `simac-final-v5` | (8 words — see header) |
| `DOMAIN_AAD` | `simac-domain-aad-v5` | `0x8439c00f` |
| `DOMAIN_CT`  | `simac-domain-ct-v5`  | `0x35ef9605` |
| `DOMAIN_SIV` | `simac-domain-siv-v5` | `0x493ccf67` |

---

## 9. Test Vectors

These vectors are for algorithm version **0.3.0** (14 stream rounds).
They differ from v0.2.2 vectors due to the round count change.

---

### Vector 1 — AEAD with AAD

Run `make run-test` to print current vectors from the reference implementation.

> **Note:** Spec v1.1 intentionally omits hardcoded hex vectors for the main
> AEAD interface because they change when `SLIMIRON_ROUNDS` changes.
> The test suite (`test_simac.c`) verifies determinism and round-trip correctness
> for a fixed (key, nonce, plaintext, aad) tuple; run it to obtain current values.
>
> The SIMAC constants (§8) are stable and verified by `gen_constants.py`.

---

## Implementation Notes

- **Zeroize all key material** after use.
- **Verify before decrypt** — never release plaintext before tag passes.
- **Constant-time comparison** for tag verification — no early exit; add a
  compiler barrier after the accumulation loop to prevent vectorization with
  predicated loads.
- The `bootstrap()` constants must be hardcoded; do not recompute at runtime.
- `simac_pad()` must be called before each `simac_domain()` call.
- Do NOT call `simac_pad()` before `simac_finalize()` — finalize pads internally.
- Length fields (`simac_absorb_len`) are **big-endian** 64-bit unsigned integers.
- `simac_absorb(ctx, ptr, 0)` is a no-op; callers do not need to guard it.
- `msg` and `cipher` must not alias in `encrypt`; return `-3` if they do.
- Check `wire_version == SLIMIRON_WIRE_VERSION` before any crypto work in decrypt.
