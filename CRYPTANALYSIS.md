# Formal Cryptanalysis: snowflake-cube

**Subject:** SnowflakeAnonymizer (16-round Feistel cipher) + CubeRandomizer (SplitMix64 scramble generator)
**Date:** 2026-02-18
**Scope:** White-box analysis of all cryptographic components

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Description](#2-system-description)
3. [Threat Model](#3-threat-model)
4. [Analysis of the Feistel Network](#4-analysis-of-the-feistel-network)
   - 4.1 [Structural Analysis](#41-structural-analysis)
   - 4.2 [Key Schedule Analysis](#42-key-schedule-analysis)
   - 4.3 [Round Function Analysis](#43-round-function-analysis)
   - 4.4 [S-Box Analysis](#44-s-box-analysis)
   - 4.5 [Diffusion Analysis](#45-diffusion-analysis)
5. [Classical Attack Vectors](#5-classical-attack-vectors)
   - 5.1 [Linear Cryptanalysis](#51-linear-cryptanalysis)
   - 5.2 [Differential Cryptanalysis](#52-differential-cryptanalysis)
   - 5.3 [Algebraic / GF(2) Linearization Attacks](#53-algebraic--gf2-linearization-attacks)
   - 5.4 [Slide Attacks](#54-slide-attacks)
   - 5.5 [Related-Key Attacks](#55-related-key-attacks)
   - 5.6 [Integral / Square Attacks](#56-integral--square-attacks)
   - 5.7 [Brute-Force and Meet-in-the-Middle](#57-brute-force-and-meet-in-the-middle)
6. [Analysis of CubeRandomizer and SplitMix64 PRNG](#6-analysis-of-cuberandomizer-and-splitmix64-prng)
7. [Passphrase Key Derivation (PBKDF2)](#7-passphrase-key-derivation-pbkdf2)
8. [Identified Residual Weaknesses](#8-identified-residual-weaknesses)
9. [Historical Vulnerabilities (Patched)](#9-historical-vulnerabilities-patched)
10. [Comparison with Established Ciphers](#10-comparison-with-established-ciphers)
11. [Conclusions and Recommendations](#11-conclusions-and-recommendations)

---

## 1. Executive Summary

The snowflake-cube system implements a **custom 16-round balanced Feistel cipher** for bijective number anonymization, paired with a **deterministic Rubik's cube scramble generator**. This analysis evaluates both components against classical cryptanalytic techniques.

**Key findings:**

| ID | Severity | Finding |
|----|----------|---------|
| F1 | Medium | Non-standard cipher construction with no formal security proof |
| F2 | Low | Round function mixes linear and non-linear operations in a non-standard order |
| F3 | Low | Small-domain weakness: bit_width=2 has no S-box protection (half-width=1) |
| F4 | Low | Odd-multiplication diffusion is weaker than MDS matrices used in vetted ciphers |
| F5 | Info | Fold-based diffusion does not achieve full-width avalanche in a single round |
| F6 | Info | SplitMix64 state space (64 bits) is smaller than the Feistel output space |
| F7 | Info | S-box applied byte-by-byte without inter-byte diffusion within the round function |

**Overall assessment:** The cipher is well-engineered for its stated purpose (format-preserving anonymization, not encryption of secrets). It incorporates sound principles — HMAC-based key schedule, AES S-boxes, adequate round count — and has been iteratively hardened against 8 historical vulnerabilities. However, it is a **non-standard construction without a formal security reduction**, and should not be used as a substitute for established ciphers (AES-FF1/FF3-1) in contexts requiring cryptographic confidentiality guarantees.

---

## 2. System Description

### 2.1 SnowflakeAnonymizer

A balanced Feistel network operating on even-width blocks from 2 to 256+ bits.

```
Input: n ∈ [0, 2^B)  where B = bit_width (even)
Split: L = n >> (B/2),  R = n & ((1 << B/2) - 1)

For i = 0 to 15:
    L, R ← R, L ⊕ F(R, rk_xor[i], rk_mul[i], rk_rot[i])

Output: (L << B/2) | R
```

**Round function F (called `_arm`):**
```
F(x, rk_xor, rk_mul, rk_rot):
    x ← x ⊕ rk_xor                       // Key mixing
    x ← ROL(x, rk_rot)                    // Key-dependent rotation
    x ← S-box(x)                          // Non-linear substitution
    x ← (x × (rk_mul | 1)) mod 2^w       // Odd-multiply diffusion
    x ← x ⊕ (x >> max(1, w/2))           // Primary fold
    if w ≥ 4: x ← x ⊕ (x >> w/4)        // Secondary fold
    return x & mask
```

### 2.2 CubeRandomizer

Converts a snowflake integer into a 20-move WCA-compliant Rubik's cube scramble using SHA-256-prehashed SplitMix64 with rejection sampling.

---

## 3. Threat Model

The analysis considers the following adversary capabilities, ordered by increasing strength:

| Attack Model | Description |
|--------------|-------------|
| **Ciphertext-only (COA)** | Adversary observes anonymized outputs only |
| **Known-plaintext (KPA)** | Adversary has access to (input, output) pairs |
| **Chosen-plaintext (CPA)** | Adversary can request anonymization of arbitrary inputs |
| **Chosen-ciphertext (CCA)** | Adversary can request deanonymization of arbitrary values |
| **Related-key (RKA)** | Adversary can observe outputs under keys with known relationships |

The system's intended use (ID anonymization) most realistically faces **KPA** and **CPA** scenarios, where an attacker knows or can guess some original IDs and observes their anonymized forms.

---

## 4. Analysis of the Feistel Network

### 4.1 Structural Analysis

**Balanced Feistel guarantee.** The Luby-Rackoff theorem (1988) establishes that a 3-round Feistel network with pseudorandom round functions is a PRP (pseudorandom permutation) under CPA, and 4 rounds suffice for a strong PRP (CCA security). This cipher uses 16 rounds, providing substantial margin.

**Bijectivity.** The Feistel structure guarantees bijectivity regardless of the round function's properties. This is a structural invariant, not dependent on implementation correctness of `_arm`.

**Block size concern.** For the default 64-bit block, the birthday bound is 2^32 ≈ 4 billion anonymized values before collisions in random associations become likely. For 32-bit blocks, this drops to 2^16 = 65,536. This is a fundamental limitation of the block size, not a cipher flaw.

**Assessment:** Structurally sound. The 16-round count provides generous margin over the Luby-Rackoff minimum.

### 4.2 Key Schedule Analysis

The key schedule derives 16 compound round keys via HMAC-SHA256:

```
For each round i ∈ [0, 15]:
    label = "snowflake-round-XXXX"  (4-digit zero-padded)
    rk_xor = HMAC-SHA256(K, label || 0x01)  truncated to w bits
    rk_mul = HMAC-SHA256(K, label || 0x02)  truncated to w bits
    rk_rot = 1 + HMAC-SHA256(K, label || 0x03)[0] mod max(1, w-1)
```

**Strengths:**
- **HMAC-SHA256 PRF.** Under the assumption that HMAC-SHA256 is a PRF, each round key is computationally independent of all others given only the master key. This is the gold standard for key schedule design.
- **Domain separation.** The three sub-keys use distinct suffix bytes (0x01, 0x02, 0x03), ensuring no key material is shared between XOR, multiplication, and rotation roles.
- **Per-round labels.** The round index is embedded in the HMAC message, preventing any two rounds from sharing derivation input.
- **Full 256-bit master key.** The master key is reduced to 256 bits via `key % 2^256`, preserving the full HMAC-SHA256 key width.

**Weaknesses:**

**(W1) Rotation sub-key entropy is limited.** `rk_rot` is derived from a single byte modulo `max(1, w-1)`. For the default w=32 (64-bit blocks), this yields values in [1, 31] — only ~5 bits of entropy per round. While this is sufficient to prevent fixed-rotation attacks (Finding #5 was exactly this), the rotation contributes minimally to the per-round key diversity compared to the 32-bit `rk_xor` and `rk_mul`.

**(W2) Narrow-width key truncation.** For bit_width=4 (w=2), `rk_xor` and `rk_mul` are each 2 bits. While compound keys expand the effective space from 2^32 to 2^64 (as documented), the per-round key space of 4 × 4 × 1 = 16 values is small enough that exhaustive round-key enumeration is tractable for isolated round analysis.

**Assessment:** The HMAC-based key schedule is the strongest component of the design. No practical attack on the key schedule is apparent for standard bit widths (32-64).

### 4.3 Round Function Analysis

The round function `_arm` chains five operations:

| Step | Operation | Type over GF(2) | Purpose |
|------|-----------|-----------------|---------|
| 1 | `x ⊕ rk_xor` | Linear (affine) | Key introduction |
| 2 | `ROL(x, rk_rot)` | Linear | Bit permutation |
| 3 | `S-box(x)` | **Non-linear** | Confusion |
| 4 | `x × (rk_mul \| 1) mod 2^w` | Linear* | Diffusion |
| 5 | `x ⊕ (x >> k)` | Linear | Intra-word mixing |

*Note: Multiplication by an odd constant is linear over Z/2^w Z but **not** linear over GF(2). However, its non-linearity over GF(2) is weak — it introduces AND-gate interactions only through carry propagation, which provides algebraic degree 2 at best per bit position.

**Concern (F2): Operation ordering.** The S-box (step 3) is sandwiched between two linear operations (rotation, multiplication). In well-studied ciphers like AES, non-linear substitution is followed by strong linear diffusion (MDS matrix) to maximize the branch number. Here, the diffusion layer (odd multiplication + fold) provides weaker mixing than an MDS matrix:

- **Odd multiplication** has branch number 1 in the differential sense: a single non-zero input nibble can produce a difference in only a few output nibbles, depending on the multiplier.
- **Fold operations** (`x ^= x >> k`) are triangular matrices over GF(2), with branch number 2 at best.

In contrast, AES's MixColumns has optimal branch number 5 over 4-byte columns.

**Concern (F5): Per-round diffusion is incomplete.** A single fold `x ^= x >> (w/2)` propagates upper bits downward but not lower bits upward. The double fold improves this but does not achieve full-width avalanche in one round. Full diffusion requires multiple rounds — empirically validated at 16 rounds by the test suite's avalanche checks (≥25% bit changes for every single-bit input flip).

**Assessment:** The round function is adequate for 16 rounds but would be weak at lower round counts. The S-box provides the critical non-linearity. The diffusion layer is the weakest link but is compensated by round count.

### 4.4 S-Box Analysis

Two S-boxes are used depending on half-width:

| S-box | Source | Width | Non-linearity | Used when |
|-------|--------|-------|---------------|-----------|
| `_SBOX_8` | AES (Rijndael) | 8→8 bits | 112 (optimal) | w ≥ 8 (bit_width ≥ 16) |
| `_SBOX_4` | PRESENT | 4→4 bits | 4 (optimal for 4-bit) | 4 ≤ w < 8 (8 ≤ bit_width < 16) |
| None | — | — | — | w < 4 (bit_width < 8) |

**Strengths:**
- The AES S-box is the most thoroughly analyzed non-linear component in symmetric cryptography, providing maximum non-linearity (distance 112 from any affine function over GF(2)^8), differential uniformity of 4, and algebraic degree 7.
- The PRESENT S-box is optimal for 4-bit bijections.

**Concern (F3): No S-box for bit_width < 8.** When bit_width ∈ {2, 4, 6}, the half-width w ∈ {1, 2, 3} falls below the threshold for any S-box. The round function degenerates to:

```
F(x) = ((ROL(x ⊕ rk_xor, rk_rot) × (rk_mul|1)) ⊕ fold) & mask
```

This is **entirely linear/affine over GF(2)** (ignoring carry propagation in the multiplication). For bit_width=2 (w=1, domain of 4 values), the fold guard (`max(1, w//2) = 1`) prevents identity collapse, and the multiplication by an odd 1-bit number is always multiplication by 1 (since `rk_mul | 1` on a 1-bit value is always 1). The round function reduces to:

```
F(x) = ROL(x ⊕ rk_xor, rk_rot) ⊕ fold_of_that
```

For w=1, `ROL(x, 1)` on a 1-bit value is identity. So F(x) = (x ⊕ rk_xor) ⊕ ((x ⊕ rk_xor) >> 1). Since x is 1 bit, `x >> 1 = 0`, giving F(x) = x ⊕ rk_xor. The Feistel cipher then reduces to repeated XOR with round-key bits, which is affine.

However, for a 4-element domain, bijectivity already constrains the permutation to one of 4! = 24 possibilities. The test suite verifies non-triviality (not identity) at bit_width=2. The lack of non-linear confusion at this width is a theoretical concern but practically limited: the domain is too small to hide meaningful data regardless.

**Concern (F7): Byte-granularity S-box without inter-byte mixing.** The S-box is applied independently to each 8-bit (or 4-bit) slice of the half-word:

```python
for i in range(0, w, 8):
    result |= _SBOX_8[(x >> i) & 0xFF] << i
```

There is no cross-byte diffusion within the S-box step itself. In AES, the SubBytes step is followed immediately by ShiftRows (inter-byte permutation) and MixColumns (inter-byte linear mixing). Here, cross-byte diffusion relies entirely on the subsequent multiplication and fold steps, which are weaker than AES's MDS matrix.

This means that for the 64-bit default (w=32, four S-box applications per half-word), a byte-level differential in one S-box input position may not affect all other byte positions within a single round. Full inter-byte diffusion requires accumulation over multiple rounds.

**Assessment:** The S-box choices are well-sourced from established ciphers. The byte-parallel application without intra-step mixing is a design choice that trades per-round diffusion strength for simplicity, compensated by 16 rounds.

### 4.5 Diffusion Analysis

Full diffusion means that every output bit depends on every input bit. For this cipher:

**Per-round diffusion path:**
1. XOR with `rk_xor` — no inter-bit diffusion
2. Rotation — bit permutation (no mixing, just repositioning)
3. S-box — 8-bit local diffusion within each byte lane
4. Odd multiplication — carries propagate left (MSB direction) but not right; a change in bit i affects bits i through w-1
5. Primary fold — `x ^= x >> w/2` mixes upper half into lower half
6. Secondary fold — `x ^= x >> w/4` provides finer-grain mixing

**Estimated rounds to full diffusion:** For w=32 (64-bit blocks), a single round's diffusion chain covers approximately half the word width through the fold operation. Based on the structure, approximately 3-4 rounds are needed for all output bits to depend on all input bits of a single half-word, and ~6-8 rounds for full cross-half diffusion through the Feistel structure. The 16-round count provides roughly 2x this estimate.

**Empirical validation:** The test suite confirms ≥25% (16/64) bit changes for every single-bit input flip at 64 bits, and ≥25% (8/32) at 32 bits. The strict avalanche criterion (SAC) — exactly 50% bit change probability per output bit — is not formally tested but the empirical floor of 25% at 16 rounds suggests reasonable (though not optimal) diffusion.

---

## 5. Classical Attack Vectors

### 5.1 Linear Cryptanalysis

**Attack principle:** Find a linear approximation `α·P ⊕ β·C = γ·K` with bias ε > 0 that holds over all rounds, where α, β, γ are bit masks. The number of known plaintexts needed is O(1/ε²).

**Analysis:**

The AES S-box has maximum linear approximation probability (LAP) of 2^(-6) per 8-bit substitution. For the four parallel S-box applications per half-round (at w=32), assuming independent approximations, the best single-round linear hull has bias at most 2^(-6) per active S-box.

Over 16 rounds, applying the Piling-Up Lemma conservatively (which overestimates bias for non-independent rounds), the cumulative bias would be at most:

```
ε_total ≤ 2^(n-1) × ∏(2 × ε_i)
```

With even a conservative 4 active S-boxes over the 16 rounds, the data complexity exceeds 2^48 known plaintexts — beyond the 2^32 birthday bound for 64-bit blocks.

**Complicating factors for the attacker:**
- The odd-multiplication and fold operations create additional non-trivial linear trail complexity.
- Key-dependent rotations force the attacker to enumerate rotation schedules.

**Assessment:** Linear cryptanalysis appears infeasible for the default 64-bit configuration. For smaller block sizes (32-bit, 16-bit), the margin decreases but 16 rounds with AES S-boxes remains substantial.

### 5.2 Differential Cryptanalysis

**Attack principle:** Find input difference Δ that propagates through the cipher with high probability to a predictable output difference Δ*.

**Analysis:**

The AES S-box has differential uniformity 4, meaning for any non-zero input difference, at most 4/256 input pairs produce any given output difference — a maximum differential probability (MDP) of 2^(-6) per S-box.

For a 16-round Feistel network with 4 parallel S-box lanes, the minimum number of active S-boxes across a differential trail is bounded by the branch number of the diffusion layer. With odd-multiplication having effective branch number ~2 and the fold adding additional diffusion, a conservative lower bound is 2 active S-boxes per 2 rounds, giving ~16 active S-boxes over 16 rounds.

```
P_differential ≤ (2^-6)^16 = 2^(-96)
```

This is well beyond the 2^(-64) threshold for a 64-bit block cipher.

**Assessment:** Classical differential cryptanalysis appears infeasible. The AES S-box's low differential uniformity, combined with 16 rounds, provides strong resistance.

### 5.3 Algebraic / GF(2) Linearization Attacks

**Attack principle:** If the cipher is affine over GF(2), it can be expressed as C = M·P ⊕ b for some binary matrix M and vector b. An attacker recovers M and b with O(n) known plaintext-ciphertext pairs where n = bit_width, then inverts any ciphertext.

**Analysis:**

The AES S-box introduces algebraic degree 7 per 8-bit substitution. Without the S-box, the remaining operations (XOR, rotation, odd-multiplication, fold) are all GF(2)-affine or nearly so (multiplication introduces only low-degree non-linearity through carries). The historical vulnerability record (Finding: affine-over-GF(2)) confirms this was a real attack before S-boxes were added.

With S-boxes present (bit_width ≥ 16), the algebraic degree after r rounds grows rapidly. After 2 rounds, the degree reaches the maximum (limited by block size) for typical parameters. The cipher's test suite confirms ≥90% violation rate of the affine identity `f(a⊕b) = f(a)⊕f(b)⊕f(0)`.

**Residual concern for small domains:** For bit_width < 8 where no S-box is applied, the cipher is GF(2)-affine. For bit_width=2 (4 values), bit_width=4 (16 values), or bit_width=6 (64 values), an attacker with O(bit_width) known pairs can recover the full permutation directly — but these domains are too small to provide meaningful anonymization regardless.

**Assessment:** With S-boxes active (bit_width ≥ 16), algebraic linearization is firmly defeated. Without S-boxes (bit_width < 8), the cipher is theoretically affine but the domain is too small to matter practically.

### 5.4 Slide Attacks

**Attack principle:** If the key schedule has periodicity (identical round keys repeat), the attacker can relate two encryptions offset by the period, reducing the effective number of rounds.

**Analysis:**

The HMAC-based key schedule produces round keys indexed by unique labels (`snowflake-round-0000` through `snowflake-round-0015`). Under the PRF assumption for HMAC-SHA256, no two round keys are related. There is no periodicity in the 16-round schedule.

**Assessment:** Slide attacks are inapplicable. The key schedule has no periodic structure.

### 5.5 Related-Key Attacks

**Attack principle:** The attacker obtains encryptions under keys K and K ⊕ ΔK (or K + ΔK) and exploits predictable relationships in the round keys.

**Analysis:**

Because round keys are derived as `HMAC-SHA256(K_bytes, label)`, and HMAC-SHA256 is assumed to be a PRF, a change in the master key produces computationally unpredictable changes in all round keys. There is no known method to predict the relationship between round keys under related master keys.

The `_key_to_bytes` reduction (`key % 2^256`) means that keys differing by multiples of 2^256 produce identical round keys. This is by design (key space is 2^256) and not exploitable in practice.

**Assessment:** Related-key attacks appear infeasible given the HMAC-SHA256 key schedule.

### 5.6 Integral / Square Attacks

**Attack principle:** Encrypt a set of plaintexts that saturate specific byte positions (all 256 values in one byte, constants elsewhere). Track the sum (XOR) of the corresponding ciphertext bytes through rounds. If the sum is zero after r rounds, the cipher's algebraic structure is exploitable.

**Analysis:**

For the 64-bit block (w=32, four S-box byte lanes), a Λ-set (256 plaintexts saturating one byte lane) would require tracking through:
- S-box: non-linear, preserves the balanced property (since S-box is a permutation, XOR-sum remains zero through 1 round of the saturated byte)
- Multiplication: preserves balance if the multiplier is odd (bijective mod 2^w) — the XOR-sum of a permutation of {0..255} mapped through multiplication by an odd constant remains 0 only if the multiplication restricted to the byte lane is balanced, which it generally is not after inter-byte carry propagation
- Fold: destroys byte-lane independence

The fold operations and odd multiplication break byte-lane alignment, making integral properties difficult to track beyond 2-3 rounds. With 16 rounds, integral attacks are not viable.

**Assessment:** Integral attacks are not applicable at 16 rounds.

### 5.7 Brute-Force and Meet-in-the-Middle

**Key space:** 256 bits (2^256 possible keys). Brute-force search is computationally infeasible.

**Meet-in-the-Middle (MitM):** For a 16-round Feistel cipher, a MitM attack splits the cipher at round 8 and searches from both ends. This requires:
- Time: O(2^256) per side (key schedule does not decompose)
- Memory: O(2^256)

Because the key schedule derives all round keys from a single master key through HMAC, there is no independent key material to split. MitM provides no advantage over brute force.

**Assessment:** Brute-force and MitM are infeasible.

---

## 6. Analysis of CubeRandomizer and SplitMix64 PRNG

### 6.1 SplitMix64

**Design:** Standard splitmix64 constants with SHA-256 pre-hashing of the seed.

```
State initialization: SHA-256(seed_bytes)[:8] → 64-bit initial state
Advancement: state += 0x9E3779B97F4A7C15 (golden ratio × 2^64)
Output mixing: two xorshift-multiply rounds + final xorshift
```

**SHA-256 pre-hash rationale:** Without pre-hashing, splitmix64's mixing function is fully invertible. An observer who can determine the PRNG output stream (e.g., by observing the cube scramble and reverse-engineering the face/suffix selections) could invert the state back to the original snowflake. The SHA-256 pre-hash breaks this inversion.

**Concern (F6): State space limitation.** SplitMix64 has 2^64 possible internal states, but the SnowflakeAnonymizer can produce values up to 2^256. However, the SHA-256 pre-hash maps the full input space down to 64 bits of state, meaning at most 2^64 distinct scramble sequences are possible regardless of the input space. For the default 64-bit anonymizer output, this is a non-issue (64-bit input → 64-bit state). For wider bit widths, this represents information loss in the scramble (though not in the anonymization itself).

**Rejection sampling for modulo-bias elimination:**
```python
limit = 0xFFFFFFFFFFFFFFFF - (0xFFFFFFFFFFFFFFFF % n)
while val > limit: resample
```

This correctly eliminates modulo bias for all values of n. The expected number of rejections per sample is < 1/n, which is negligible for n ≤ 6 (face selection) and n ≤ 3 (suffix selection).

**Assessment:** The PRNG is well-implemented for its purpose. The SHA-256 pre-hash is a sound mitigation for state invertibility. The 64-bit state space is the main limitation but is acceptable for cube scramble generation.

### 6.2 Scramble Validity

The move constraint enforcement implements two rules:

1. **No consecutive same-face moves** — prevents redundancy (U U' = no-op)
2. **No three consecutive same-axis moves** — prevents reducible sequences (U D U = D U U, which has a same-face repeat after rearranging commuting moves)

These rules match the World Cube Association (WCA) scramble generation standards. The `_available_faces` function correctly implements both rules.

**Move space analysis:** At each step, the number of available faces varies:
- First move: 6 faces
- After a non-axis-repeat: 5 faces (previous face excluded)
- After an axis-repeat: 4 faces (entire axis excluded)

Each face has 3 suffixes. The total number of valid 20-move scrambles is approximately 6 × 3 × (5 × 3)^19 ≈ 2^77, far larger than the 2^64 PRNG state space. This means not all valid scrambles are reachable from 64-bit seeds, but the reachable subset is uniform over the 2^64 seeds.

**Assessment:** Scramble generation is correct and bias-free.

---

## 7. Passphrase Key Derivation (PBKDF2)

```python
hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 600_000, dklen=32)
```

| Parameter | Value | Assessment |
|-----------|-------|------------|
| Hash | SHA-256 | Standard, adequate |
| Iterations | 600,000 | Meets NIST SP 800-132 (2023) and OWASP 2024 recommendations |
| Salt | 16 bytes (os.urandom) | Adequate entropy (128 bits) |
| Output | 32 bytes (256 bits) | Full key width utilized |

**Strength against offline brute-force:** At 600,000 iterations, a GPU cluster achieving 10^9 PBKDF2-SHA256 evaluations/second would need:
- 8-character random alphanumeric password (62^8 ≈ 2^47.6): ~2^47.6 / (10^9 / 600000) ≈ 2^47.6 / 2^10.7 ≈ 2^36.9 seconds ≈ impractical
- 4-digit PIN (10^4): ~6 seconds — trivially crackable
- Common dictionary word: trivially crackable

**Assessment:** The PBKDF2 configuration is compliant with current standards. Security depends entirely on passphrase entropy, as expected.

---

## 8. Identified Residual Weaknesses

### F1: Non-Standard Construction (Medium)

**Description:** The cipher is a custom design without a published security proof, peer review, or formal analysis by the cryptographic community. While it follows sound principles (Feistel + HMAC schedule + AES S-box), the specific combination of operations in the round function has not been subjected to dedicated cryptanalytic effort by third parties.

**Impact:** Unknown vulnerabilities may exist that would be identified through formal academic review.

**Recommendation:** For applications requiring cryptographic guarantees, use NIST-standardized format-preserving encryption (FF1/FF3-1) instead. For the stated purpose of deterministic anonymization where the key is not protecting high-value secrets, the current design is reasonable.

### F2: Round Function Operation Ordering (Low)

**Description:** The S-box output feeds directly into odd-multiplication, which provides weaker diffusion than an MDS matrix. This means the non-linear confusion from the S-box is not immediately spread across all byte lanes within a single round.

**Impact:** More rounds are needed to achieve full diffusion compared to AES-like designs. At 16 rounds, this is mitigated empirically but the safety margin is less precisely quantifiable.

### F3: No S-Box for Small Domains (Low)

**Description:** For bit_width < 8, the round function is GF(2)-affine. An attacker with O(bit_width) known pairs can recover the full permutation.

**Impact:** Minimal in practice — domains of 4 to 64 values cannot meaningfully hide data regardless of cipher quality. Documented for completeness.

### F4: Odd-Multiplication Diffusion (Low)

**Description:** Multiplication by an odd constant modulo 2^w has branch number 1 in differential characteristics. A single-bit input difference can remain localized in the least-significant bits through the multiplication step.

**Impact:** Differential trail weights are harder to lower-bound compared to ciphers using MDS matrices. The fold operations partially compensate.

### F5: Incomplete Per-Round Diffusion (Info)

**Description:** The fold operations `x ^= x >> k` are triangular and do not achieve full mixing in a single application. Full avalanche requires multiple rounds.

**Impact:** The 16-round count provides adequate accumulated diffusion, as confirmed empirically.

### F6: PRNG State Space Mismatch (Info)

**Description:** For anonymizer bit_widths > 64, the CubeRandomizer's 64-bit PRNG state cannot distinguish all possible inputs.

**Impact:** Only affects cube scramble uniqueness for very wide bit widths. Does not affect the anonymizer's security.

### F7: Byte-Parallel S-Box Without Cross-Byte Mixing (Info)

**Description:** The S-box substitutes each byte independently without inter-byte permutation (unlike AES's ShiftRows). Cross-byte diffusion depends entirely on the subsequent multiplication and fold steps.

**Impact:** Slightly slower per-round diffusion, compensated by round count.

---

## 9. Historical Vulnerabilities (Patched)

The development history reveals 8 identified and fixed vulnerabilities, demonstrating iterative security improvement:

| # | Vulnerability | Severity | Fix |
|---|--------------|----------|-----|
| 1 | Only 6 Feistel rounds | High | Increased to 16 rounds |
| 2 | XOR-with-constants key schedule | High | HMAC-SHA256 key derivation |
| 3 | 64-bit truncated master key | Medium | Full 256-bit key |
| 4 | SHA-256 truncated passphrase hashing | Medium | PBKDF2 with 600K iterations |
| 5 | Fixed, key-independent rotation `max(1, w//6)` | Medium | HMAC-derived per-round rotation |
| 6 | Same key material for XOR and multiply | Medium | Domain-separated HMAC labels (0x01/0x02) |
| 7 | Implicit type checking | Low | Explicit `isinstance()` guards |
| 8 | Missing `.salt` attribute on direct instances | Low | Initialize `salt=None` in `__init__` |
| 9 | No S-box (cipher was GF(2)-affine) | Critical | AES/PRESENT S-box insertion |
| 10 | Identity permutation at bit_width=2 (fold collapse) | High | `max(1, w//2)` fold guard |
| 11 | SplitMix64 seed invertibility | Medium | SHA-256 pre-hash |

The pre-S-box version (vulnerability #9) was **completely broken**: the entire cipher was affine over GF(2), recoverable with `bit_width` known plaintext-ciphertext pairs via Gaussian elimination. This was the most severe vulnerability in the project's history.

---

## 10. Comparison with Established Ciphers

| Property | snowflake-cube | AES-128 | FF1 (NIST FPE) |
|----------|---------------|---------|-----------------|
| **Structure** | Balanced Feistel | SPN | Balanced Feistel |
| **Rounds** | 16 | 10 | 10 |
| **S-box** | AES (borrowed) | AES (native) | AES (via AES-CBC) |
| **Diffusion** | Odd-mul + fold | MDS matrix | AES round function |
| **Key schedule** | HMAC-SHA256 | XOR + RotWord + S-box | AES-based |
| **Security proof** | None | Extensive peer review | NIST SP 800-38G |
| **Block sizes** | 2-256+ bits | 128 bits | Arbitrary (with tweak) |
| **Format-preserving** | Yes (any even width) | No (128-bit only) | Yes |
| **Standardized** | No | FIPS 197 | NIST SP 800-38G |

The snowflake-cube cipher borrows the AES S-box but does not inherit AES's provable diffusion properties. FF1/FF3-1 achieve format-preserving encryption by using AES as a black box inside a Feistel structure, inheriting AES's full security margin. The snowflake-cube round function is simpler and faster but has weaker per-round diffusion.

---

## 11. Conclusions and Recommendations

### 11.1 Overall Security Assessment

The snowflake-cube cipher is a **competently designed custom construction** that achieves its stated goal of bijective, deterministic number anonymization. Its iterative development history — 11 identified and patched vulnerabilities — demonstrates responsible engineering.

For its intended use case (anonymizing database IDs, user identifiers, and similar non-secret data where bijectivity and format preservation are the primary requirements), the cipher provides:

- **Strong bijectivity** (structural guarantee from Feistel construction)
- **Good empirical avalanche** (≥25% bit change per single-bit input flip)
- **Adequate key schedule** (HMAC-SHA256, industry-standard)
- **Resistance to classical attacks** at 64-bit block size (linear, differential, algebraic)

### 11.2 Limitations

1. **No formal security proof.** Unlike AES or FF1, the cipher has not been analyzed by the broader cryptographic community.
2. **Not suitable for confidentiality of high-value secrets.** Use AES, ChaCha20, or NIST-standardized FPE for that purpose.
3. **64-bit birthday bound.** Anonymizing more than ~2^32 values risks statistical distinguishability from a random permutation.
4. **Small-domain degradation.** For bit_width < 8, the lack of S-box makes the cipher GF(2)-affine.

### 11.3 Recommendations

| Priority | Recommendation |
|----------|---------------|
| **High** | Add a prominent warning in documentation that this is not a replacement for standardized encryption |
| **Medium** | Consider using AES-based round functions (AES-ECB as the Feistel F-function) for stronger per-round security guarantees, following the FF1 approach |
| **Medium** | Add Strict Avalanche Criterion (SAC) testing: for each input bit position, verify that each output bit changes with probability ~50% (not just ≥25%) |
| **Low** | For bit_width < 8, consider warning users that the anonymization is trivially invertible with known plaintexts |
| **Low** | Document the birthday-bound limitation for each supported bit_width |
