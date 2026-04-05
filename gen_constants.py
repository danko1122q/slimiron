#!/usr/bin/env python3
"""
gen_constants.py — Slimiron v0.2.2 constant verifier
Verifies all initialization constants in slimiron.h using only the
Slimiron permutation itself.  No hashlib, no external dependencies.

Usage: python3 gen_constants.py

Bootstrap method (mirrors the C bootstrap procedure):
  1. Start with all-zero 16-word state
  2. Absorb the ASCII label string into the rate region (state[0..7])
     using the sponge rule: XOR bytes into a 32-byte buffer, flush
     (XOR buffer into state words + permute) when the buffer fills.
  3. Apply two-marker padding: 0x01 at current position, 0x80 at
     the last byte of the rate buffer (SIMAC_RATE_BYTES - 1).
  4. Flush: XOR padded buffer into state, permute once (10 rounds).
  5. Squeeze: return state[0..N-1] as the derived constants.
"""

__version__ = "0.3.0"

# ---------------------------------------------------------------------------
# SlimMix ARX permutation (pure Python, no imports needed)
# ---------------------------------------------------------------------------

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def slimmix(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 15)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 11)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d,  9)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b,  5)
    return a, b, c, d

def permute(s, rounds=10):
    s = list(s)
    for _ in range(0, rounds, 2):
        # column round
        s[0],s[4],s[8], s[12] = slimmix(s[0],s[4],s[8], s[12])
        s[1],s[5],s[9], s[13] = slimmix(s[1],s[5],s[9], s[13])
        s[2],s[6],s[10],s[14] = slimmix(s[2],s[6],s[10],s[14])
        s[3],s[7],s[11],s[15] = slimmix(s[3],s[7],s[11],s[15])
        # diagonal round
        s[0],s[5],s[10],s[15] = slimmix(s[0],s[5],s[10],s[15])
        s[1],s[6],s[11],s[12] = slimmix(s[1],s[6],s[11],s[12])
        s[2],s[7],s[8], s[13] = slimmix(s[2],s[7],s[8], s[13])
        s[3],s[4],s[9], s[14] = slimmix(s[3],s[4],s[9], s[14])
    return s

RATE_BYTES = 32
RATE_WORDS = 8

def load32_le(data, offset):
    return (data[offset]
            | (data[offset+1] << 8)
            | (data[offset+2] << 16)
            | (data[offset+3] << 24))

def slimiron_bootstrap(label: str, n_words: int) -> list:
    """
    Squeeze n_words 32-bit constants from a Slimiron sponge seeded
    with the ASCII label string.  Mirrors the C bootstrap exactly.
    """
    state = [0] * 16
    buf   = [0] * RATE_BYTES
    pos   = 0

    for byte in label.encode('ascii'):
        buf[pos] ^= byte
        pos += 1
        if pos == RATE_BYTES:
            for i in range(RATE_WORDS):
                state[i] ^= load32_le(buf, i * 4)
            state = permute(state)
            buf   = [0] * RATE_BYTES
            pos   = 0

    # two-marker padding (same as simac_pad in slimiron.h)
    buf[pos]            ^= 0x01
    buf[RATE_BYTES - 1] ^= 0x80
    for i in range(RATE_WORDS):
        state[i] ^= load32_le(buf, i * 4)
    state = permute(state)

    return state[:n_words]

# ---------------------------------------------------------------------------
# Constant groups: (display_name, label_string, n_words)
# ---------------------------------------------------------------------------
CONSTANTS = [
    ("SLIMIRON_IV_0..3",  "slimiron-stream-v5", 4),
    ("SIMAC_INIT_0..7",   "simac-init-v5",       8),
    ("SIMAC_FINAL_0..7",  "simac-final-v5",       8),
    ("SIMAC_DOMAIN_AAD",  "simac-domain-aad-v5",  1),
    ("SIMAC_DOMAIN_CT",   "simac-domain-ct-v5",   1),
    ("SIMAC_DOMAIN_SIV",  "simac-domain-siv-v5",  1),
]

# Expected values as hardcoded in slimiron.h v0.2.2
EXPECTED = {
    "SLIMIRON_IV_0..3":  [0xb9e3ef7f, 0x7638101d, 0x53373520, 0x654cbc86],
    "SIMAC_INIT_0..7":   [0x3e60fb52, 0x858433d2, 0xa5db45d3, 0x14ae65d8,
                          0x036c4f77, 0x5e78b857, 0xcceca447, 0x7d965649],
    "SIMAC_FINAL_0..7":  [0x8d1f0ff9, 0x7a370f9e, 0xe4e1e8ff, 0x45d5c67b,
                          0xfd3dc527, 0xc608a8c1, 0xc2617c1b, 0xf0327ed2],
    "SIMAC_DOMAIN_AAD":  [0x8439c00f],
    "SIMAC_DOMAIN_CT":   [0x35ef9605],
    "SIMAC_DOMAIN_SIV":  [0x493ccf67],
}

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
import sys

print(f"Slimiron constant verifier v{__version__}")
print(f"Method: slimiron_bootstrap(label)  [pure Slimiron permutation, no hashlib]")
print(f"{'=' * 66}")

ok = True
for name, label, n in CONSTANTS:
    computed = slimiron_bootstrap(label, n)
    expected = EXPECTED[name]
    match    = (computed == expected)
    status   = "OK      " if match else "MISMATCH"
    print(f'\n[{status}] {name}  <- slimiron_bootstrap("{label}")')
    for i, (c, e) in enumerate(zip(computed, expected)):
        eq = c == e
        print(f"           word[{i}]: computed=0x{c:08x}  header=0x{e:08x}  "
              f"{'==' if eq else '!= FAIL <---'}")
    if not match:
        ok = False

print(f"\n{'=' * 66}")
if ok:
    print("All constants verified.  slimiron.h v0.3.0 is consistent.")
    print("No external hash library used — pure Slimiron permutation only.")
else:
    print("VERIFICATION FAILED — update slimiron.h!")
sys.exit(0 if ok else 1)
