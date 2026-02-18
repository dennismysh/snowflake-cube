# Formal Cryptanalysis of `snowflake-cube`

**Target:** `snowflake-cube` v0.2.0
**Components:** `SnowflakeAnonymizer` (Feistel cipher) · `CubeRandomizer` (PRNG)
**Date:** 2026-02-18

---

## 1. Algorithm Specification

### 1.1 SnowflakeAnonymizer

A balanced Feistel network operating on an `n`-bit block (n even, default 64).

**State:** Let `w = n/2` (half-word width). The block is split into `(L, R)`, each `w` bits.

**Encryption (16 rounds):**

```
For i = 0 to 15:
    (L, R) ← (R,  L ⊕ F(R, K_i))
Ciphertext ← (L ‖ R)
```

**Round function `F(x, k)` acting on `w`-bit values:**

```
x ← x ⊕ k
x ← ROL_w(x, rot)      where rot = max(1, ⌊w/6⌋)
x ← x · (k | 1)  mod 2^w
x ← x ⊕ (x >> ⌊w/2⌋)
if w ≥ 4:
    x ← x ⊕ (x >> ⌊w/4⌋)
return x
```

**Key schedule `K_0..K_15`:**

```
master ← K mod 2^256  (as 32 big-endian bytes)
K_i   ← HMAC-SHA256(master, "snowflake-round-{i:04d}")  mod 2^w
```

**Decryption** runs the rounds in reverse:

```
For i = 15 down to 0:
    (R, L) ← (L,  R ⊕ F(L, K_i))
```

### 1.2 CubeRandomizer

Converts a 64-bit integer seed (the anonymized value) into a Rubik's cube
scramble using the SplitMix64 PRNG:

```
state ← seed & 0xFFFFFFFFFFFFFFFF
next():
    state ← (state + 0x9E3779B97F4A7C15) mod 2^64
    z ← state
    z ← (z ⊕ (z >> 30)) · 0xBF58476D1CE4E5B9  mod 2^64
    z ← (z ⊕ (z >> 27)) · 0x94D049BB133111EB  mod 2^64
    return z ⊕ (z >> 31)
```

---

## 2. Findings

---

### Finding 1 — CRITICAL: Identity Cipher for `bit_width=2`

**Theorem.** For `bit_width=2` (`w=1`), `anonymize(n) = n` for every `n` and
every key.

**Proof.**

When `w = 1`:

1. **XOR:** `x ← half ⊕ k`  (1-bit)
2. **Rotation:** `rot = max(1, ⌊1/6⌋) = 1`.
   `ROL_1(x, 1) = ((x << 1) | (x >> 0)) & 1 = x & 1 = x`.
   A rotation by the full word width is the identity on any word width. ∎
3. **Multiply:** `k | 1 = 1` for every 1-bit value k ∈ {0, 1}.
   So `x · 1 mod 2 = x`. Multiply is the identity. ∎
4. **Primary fold:** `x ⊕ (x >> ⌊1/2⌋) = x ⊕ (x >> 0) = x ⊕ x = 0`.
   **The fold unconditionally clears `x` to zero.** ∎
5. **Secondary fold:** `w = 1 < 4`, so it is skipped.

Therefore `F(half, k) = 0` for all inputs and all keys when `w = 1`.

Each Feistel round then degenerates to:

```
(L, R) ← (R, L ⊕ 0) = (R, L)
```

This is a pure swap. Sixteen swaps (an even number) compose to the identity.
Consequently:

```
anonymize(n) = n   for all n ∈ {0, 1, 2, 3}, for all keys.
```

The cipher provides **zero anonymization** at `bit_width=2`.

**Test-suite blind spot.** The test `test_min_bit_width_2` checks only that
the output set equals `{0, 1, 2, 3}` (satisfied trivially by the identity).
`test_exhaustive_bijection_all_values` parameterises over `bit_width` values
starting at 2 but only verifies that outputs are a permutation — the identity
permutation passes. No test checks that `anonymize(n) ≠ n` for `bit_width=2`.

---

### Finding 2 — HIGH: Round Function is Affine over GF(2)^w

**Theorem.** `F(x, k)` is an *affine* map over GF(2)^w for every fixed key k.
Equivalently, the entire 16-round cipher is an affine map C = A·P + b over
GF(2)^n for some matrix A ∈ GF(2)^{n×n} and vector b ∈ GF(2)^n determined
by the key schedule.

**Proof (component-by-component).**

Represent each w-bit word as a vector in GF(2)^w. Each operation in `F`:

| Step | Operation | Type over GF(2)^w |
|------|-----------|-------------------|
| XOR with k | `x ← x ⊕ k` | Affine (translation by constant k) |
| Rotation | `x ← ROL(x, rot)` | Linear (permutation matrix) |
| Multiply by odd c | `x ← x · c mod 2^w` | **Linear** (see below) |
| Right-shift fold | `x ← x ⊕ (x >> s)` | Linear (lower-triangular matrix + identity) |

The multiplication step requires justification. Multiplication by a fixed odd
constant c modulo 2^w defines a GF(2)-linear map M_c : GF(2)^w → GF(2)^w.
The (i, j) entry of M_c is `(c >> (i−j)) & 1` for i ≥ j, 0 otherwise (carry
propagation). Because c is odd, M_c is invertible (its inverse is multiplication
by the modular inverse of c mod 2^w). Despite appearance, this is **not**
non-linear over GF(2).

A composition of linear and affine maps is affine. Therefore `F(·, k)` is
affine for each fixed k. The Feistel network applies F once per round together
with XOR (also affine), so the full cipher is affine. ∎

**Consequence: Known-Plaintext Recovery.**

The ciphertext–plaintext relation over GF(2)^n is:

```
C = A · P + b
```

An adversary who observes n linearly independent plaintext–ciphertext pairs
can solve this system in O(n^3) bit operations via Gaussian elimination,
recovering A and b. With these, they can decrypt *any* ciphertext without
ever learning the key. For the default 64-bit block, exactly **64** known
pairs suffice.

This is a full algebraic break under the known-plaintext model.

**Practical note.** The cipher's stated threat model is number
*anonymization* with a secret key, not semantic security against an adversary
with oracle access. If the key is never reused across different contexts and
no plaintext–ciphertext pairs are observable, this weakness is unexploitable
in practice. However, the security claims made in the documentation
("bank-grade", "AES-256 equivalent") imply a much stronger adversarial model
and are therefore misleading.

---

### Finding 3 — HIGH: Incorrect Comparison to AES-256

The module docstring states:

> "16 Feistel rounds — bank-grade round count, **matching AES-256**"

**Factual errors:**

1. AES-256 uses **14 rounds** (AES-128: 10, AES-192: 12, AES-256: 14).
   16 ≠ 14.

2. Round-count equivalence does not imply security equivalence. AES rounds
   include:
   - **SubBytes:** non-linear S-box over GF(2^8), algebraic degree 7.
   - **MixColumns:** MDS matrix over GF(2^8), guaranteed branch number 5.
   - Combined, AES rounds have provable bounds against both differential and
     linear cryptanalysis (wide-trail strategy).

   The SnowflakeAnonymizer round function is entirely GF(2)-linear (Finding 2)
   and has no S-box. It provides no provable resistance against linear
   cryptanalysis.

**Conclusion.** The AES-256 comparison is false on two independent grounds:
wrong round count, and fundamentally different (and weaker) round structure.

---

### Finding 4 — MEDIUM: Key-Space Collapse for Narrow Block Widths

Round keys are derived via HMAC-SHA256 (256 bits of output) and then masked
to `w` bits:

```python
rk = int.from_bytes(rk_bytes[:half_bytes], "big") & self._half_mask
```

For narrow blocks, `half_mask` truncates the round key severely:

| bit_width | w | Round key bits | Distinct round-key tuples | Effective security |
|-----------|---|----------------|---------------------------|--------------------|
| 4 | 2 | 2 | 4^16 ≈ 2^32 | **32 bits** |
| 8 | 4 | 4 | 16^16 = 2^64 | 64 bits |
| 16 | 8 | 8 | 256^16 = 2^128 | 128 bits |
| 32 | 16 | 16 | 2^256 | 256 bits |
| 64 | 32 | 32 | 2^512 (> 256-bit key) | 256 bits (key-limited) |

For `bit_width=4`, regardless of the 256-bit master key, only 2^32 distinct
round-key tuples exist. An exhaustive search over all 2^32 tuples can
uniquely identify the effective cipher, breaking the key in ~4 billion
operations. The 256-bit master key provides no additional security for
`bit_width ≤ 8`.

---

### Finding 5 — MEDIUM: Rotation Amount is Fixed Across All Rounds and All Keys

```python
rot = max(1, w // 6)
```

For a 64-bit block (w=32), `rot = 5` in every round for every key. The
rotation is:

- **Not key-dependent** — the same rotation for every master key.
- **Not round-dependent** — the same rotation in all 16 rounds.

A known fixed rotation simplifies algebraic analysis: an attacker can absorb
the rotation into the basis of GF(2)^w and eliminate it from the linear system
(Finding 2), reducing the effective linear algebra problem.

Compare with ARX designs (ChaCha20, Salsa20), where rotation constants are
chosen by differential analysis to maximise avalanche; or with DES, where
per-round rotations are variable.

---

### Finding 6 — MEDIUM: Round Key Reused for Both XOR and Multiplication

Within a single round, the same `round_key` value is used in two operations:

```python
x = half ^ round_key          # XOR
...
x = (x * (round_key | 1)) & mask   # multiply
```

This creates an algebraic dependency: if an adversary can write the round
output as a function of `round_key` via either operation, they gain information
about `round_key` that simultaneously aids the other. In linear cryptanalysis,
a single linear approximation of the round output becomes a function of only
`round_key` rather than of two independent key values, reducing the linear
bias the attacker must distinguish.

Stronger constructions assign independent key material to each keyed operation
within a round (e.g., Camellia's `k_L ‖ k_R` split for its two-layer F-function,
or the independent SubKey and AddRound distinction in AES).

---

### Finding 7 — LOW: Implicit Rather than Explicit Type Checking

`_check_range` validates only the numeric range:

```python
def _check_range(self, value: int) -> None:
    if not (0 <= value <= self._full_mask):
        raise ValueError(...)
```

For a float argument within range (e.g., `sa.anonymize(3.14)` when
`0 ≤ 3.14 ≤ 2^64−1` evaluates to `True`), the function silently passes.
The subsequent `(3.14 >> self._half)` raises `TypeError` only because Python's
`>>` operator rejects floats.

This is a fragile implicit contract: a custom `int` subclass that overrides
`__rshift__` to return an integer could bypass the check entirely. Explicit
type gating (`isinstance(value, int) and not isinstance(value, bool)`) should
precede the range check.

---

### Finding 8 — LOW: `salt` Attribute Appears Only on Passphrase-Derived Instances

```python
instance = cls(key=key, bit_width=bit_width)
instance.salt = salt   # dynamically attached attribute
return instance
```

Instances created via `SnowflakeAnonymizer(key=...)` have no `salt` attribute.
Code that unconditionally accesses `.salt` (e.g., for serialisation) raises
`AttributeError` on directly-constructed instances. The attribute should either
be declared in `__init__` (defaulting to `None`) or exposed through a defined
protocol.

---

### Finding 9 — INFORMATIONAL: SplitMix64 is Not Cryptographically Secure

`CubeRandomizer._SplitMix64` is seeded directly from the 64-bit snowflake
value. SplitMix64 is a well-regarded statistical PRNG with excellent speed and
distribution but makes no cryptographic security claims.

Given any contiguous subsequence of 64-bit outputs from SplitMix64, the full
internal state (and thus the seed) can be recovered in closed form by inverting
the mixing function:

```
z^31 = output
z^27 = z^31 ⊕ (z^31 >> 31)
z^27 = z^27 · (0x94D049BB133111EB)^{-1}  mod 2^64
...
```

An adversary who observes the generated Rubik's cube scramble can therefore
recover the snowflake seed that produced it. If the anonymized value is
sensitive and the scramble string is public, this leaks the anonymized number
entirely.

This is by design (scrambles are deterministic and reproducible), but it means
the scramble output must not be treated as a secure commitment or hash of the
original number.

---

## 3. Summary Table

| # | Severity | Finding |
|---|----------|---------|
| 1 | **Critical** | `anonymize(n) = n` (identity) for all n and all keys when `bit_width=2` |
| 2 | **High** | Round function is GF(2)-affine; 64 known plaintext–ciphertext pairs break the cipher |
| 3 | **High** | AES-256 comparison is factually wrong (14 rounds, not 16) and structurally misleading |
| 4 | **Medium** | Key space collapses to ≤32 bits of security for `bit_width ≤ 4` |
| 5 | **Medium** | Rotation constant is fixed across all rounds and all keys |
| 6 | **Medium** | Same round-key material drives both the XOR and the multiplication |
| 7 | **Low** | Type checking is implicit via Python's `>>` operator, not explicit validation |
| 8 | **Low** | `salt` attribute present only on passphrase-derived instances; direct-constructed instances lack it |
| 9 | **Informational** | SplitMix64 PRNG state is invertible from its output; scramble leaks the snowflake seed |

---

## 4. Scope and Caveats

The findings above assume a **known-plaintext adversary** for Finding 2 and an
**implementation-analysis adversary** for all others. The cipher does fulfil its
*stated* purpose — deterministic, reversible, bijective number anonymization with
a secret key — provided:

- `bit_width ≥ 4` (Finding 1 eliminates `bit_width=2`).
- The key is kept secret and no plaintext–ciphertext pairs are observable
  (Finding 2 requires known pairs to exploit).
- Users do not rely on security claims stronger than what a keyed bijective PRF
  provides.

The documentation's comparisons to AES-256 and "bank-grade" standards should
be removed or substantially qualified to avoid misrepresenting the cipher's
actual security level.
