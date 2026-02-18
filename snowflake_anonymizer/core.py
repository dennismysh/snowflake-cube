"""
Snowflake Number Anonymizer — Core Algorithm

A real snowflake grows from a single water molecule outward, branching into
six identical arms driven by the same local temperature and humidity.  The
result is deterministic (same conditions → same crystal) yet unique (no two
snowflakes experience exactly the same conditions).

This anonymizer mirrors that geometry:

  • 6 Feistel rounds  — one per snowflake arm
  • Key = the "atmospheric conditions" that shape the crystal
  • Bijective         — every input maps to a *unique* output (no collisions)
  • Reversible        — the original number is recoverable with the same key

Algorithm: Balanced Feistel network
  Split number into two equal halves (L, R).
  For each of 6 rounds:
      L, R = R,  L ⊕ arm_function(R, round_key[i])
  Reassemble halves into the anonymized number.

Because the Feistel structure is inherently bijective, the arm_function
itself need not be invertible — it just needs good diffusion (avalanche).
"""

import hashlib

# ---------------------------------------------------------------------------
# Six mixing constants — one per snowflake arm.
# Derived from well-known mathematical constants and hash primes so that
# they are "as random as possible" while remaining reproducible.
# ---------------------------------------------------------------------------
_ARM_CONSTANTS: tuple[int, ...] = (
    0x9E3779B97F4A7C15,  # Arm 1 – φ  (golden ratio) × 2⁶⁴
    0x6C62272E07BB0142,  # Arm 2 – FNV-1a 64-bit prime
    0x94D049BB133111EB,  # Arm 3 – Splitmix64 finalizer constant
    0xBF58476D1CE4E5B9,  # Arm 4 – Murmur3 64-bit finalizer constant
    0x517CC1B727220A95,  # Arm 5 – xxHash mixing constant
    0xD2A98B26625EEE7B,  # Arm 6 – Derived from hexagonal lattice spacing
)

_U64_MASK = 0xFFFFFFFFFFFFFFFF


def _mix64(x: int) -> int:
    """Bijective 64-bit integer hash (Murmur3 / Splitmix64 finalizer blend).

    Used only in the key schedule to spread a master key into round keys.
    """
    x &= _U64_MASK
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & _U64_MASK
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & _U64_MASK
    x ^= x >> 31
    return x


class SnowflakeAnonymizer:
    """Bijective number anonymizer based on a 6-round Feistel cipher.

    Args:
        key:       Integer secret key (any size).  Different keys produce
                   completely different anonymization mappings.
        bit_width: Total bit width of numbers to anonymize.  Must be even.
                   Defaults to 64 (handles values 0 … 2⁶⁴-1).

    Example::

        sa = SnowflakeAnonymizer(key=0xDEADBEEF)
        anon   = sa.anonymize(42)        # e.g. 9827364501234
        orig   = sa.deanonymize(anon)    # → 42
    """

    def __init__(self, key: int = 0, bit_width: int = 64) -> None:
        if bit_width < 2 or bit_width % 2 != 0:
            raise ValueError("bit_width must be a positive even integer")

        self._half = bit_width // 2
        self._half_mask = (1 << self._half) - 1
        self._full_mask = (1 << bit_width) - 1

        self._round_keys = self._crystallize(key)

    # ------------------------------------------------------------------
    # Key schedule
    # ------------------------------------------------------------------

    def _crystallize(self, key: int) -> list[int]:
        """Expand the master key into six arm-specific round keys.

        Like a snowflake crystallising from a seed nucleus, the key fans out
        into six structurally independent sub-keys — one per arm.
        """
        round_keys: list[int] = []
        for arm_index, arm_constant in enumerate(_ARM_CONSTANTS):
            rk = key ^ arm_constant
            # Mix in the arm index so each arm diverges even for key=0
            rk ^= (arm_index * 0x1111111111111111) & _U64_MASK
            rk = _mix64(rk)
            round_keys.append(rk & self._half_mask)
        return round_keys

    # ------------------------------------------------------------------
    # Round (arm) function
    # ------------------------------------------------------------------

    def _arm(self, half: int, round_key: int) -> int:
        """Non-linear mixing function applied at each Feistel round.

        Models the branching complexity of a single snowflake arm:
          1. XOR with round key   — introduces key material
          2. Rotated left by ⌊w/6⌋ bits — mirrors 60° rotational symmetry
          3. Multiply by odd round key — non-linear diffusion
          4. Fold upper bits down — final avalanche

        The Feistel construction guarantees global bijectivity regardless of
        what this function does, so we optimise purely for diffusion.
        """
        w = self._half
        mask = self._half_mask

        x = half ^ round_key

        # Rotate left by 1/6th of the word width (snowflake's 60° symmetry)
        rot = max(1, w // 6)
        x = ((x << rot) | (x >> (w - rot))) & mask

        # Multiply by an odd number derived from the round key for non-linearity
        x = (x * (round_key | 1)) & mask

        # Fold: mix upper half of the word into the lower half
        x ^= x >> (w // 2)

        return x

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def anonymize(self, number: int) -> int:
        """Return the unique snowflake representation of *number*.

        The six-round Feistel network guarantees that no two distinct inputs
        produce the same output — just as no two snowflakes are alike.

        Args:
            number: Non-negative integer within ``[0, 2**bit_width)``.

        Returns:
            Anonymized integer in the same range.
        """
        self._check_range(number)

        L = (number >> self._half) & self._half_mask
        R = number & self._half_mask

        for arm_key in self._round_keys:          # 6 arms, 6 rounds
            L, R = R, L ^ self._arm(R, arm_key)

        return (L << self._half) | R

    def deanonymize(self, snowflake: int) -> int:
        """Recover the original number from its snowflake representation.

        Args:
            snowflake: Value previously returned by :meth:`anonymize`.

        Returns:
            Original integer.
        """
        self._check_range(snowflake)

        L = (snowflake >> self._half) & self._half_mask
        R = snowflake & self._half_mask

        for arm_key in reversed(self._round_keys):   # reverse the 6 rounds
            R, L = L, R ^ self._arm(L, arm_key)

        return (L << self._half) | R

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_passphrase(cls, passphrase: str, bit_width: int = 64) -> "SnowflakeAnonymizer":
        """Create an anonymizer keyed from a human-readable passphrase.

        The passphrase is hashed with SHA-256 so even short strings produce a
        well-distributed 64-bit key.

        Example::

            sa = SnowflakeAnonymizer.from_passphrase("winter is cold")
        """
        digest = hashlib.sha256(passphrase.encode()).digest()
        key = int.from_bytes(digest[:8], "big")
        return cls(key=key, bit_width=bit_width)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_range(self, value: int) -> None:
        if not (0 <= value <= self._full_mask):
            raise ValueError(
                f"Value {value!r} is out of range for a {self._half * 2}-bit anonymizer "
                f"(must be 0 … {self._full_mask})"
            )
