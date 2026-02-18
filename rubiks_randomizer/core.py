"""
Rubik's Cube Randomizer — Core Algorithm

A Rubik's cube scramble is a sequence of face turns that brings the cube from
a solved state into a random configuration.  Each turn twists one of six faces
(U, D, R, L, F, B) by one of three amounts:

  90° clockwise      →  U
  90° counter-clockwise → U'
  180°                →  U2

Valid scrambles obey two constraints that prevent redundant moves:

  1. No consecutive moves on the same face — "U U2" is redundant (just do U').
  2. No three consecutive moves on the same axis — faces share axes in pairs
     (U/D, R/L, F/B).  After two moves on the same axis, the next must differ.

This randomizer converts a large integer — typically the output of a
SnowflakeAnonymizer — into a deterministic, valid scramble sequence.

Pipeline:

  number ──► SnowflakeAnonymizer ──► snowflake ──► CubeRandomizer ──► scramble

The snowflake's properties carry through: deterministic input always yields
the same scramble, and the bijective avalanche effect means small changes in
the original number produce radically different cube states.
"""

import hashlib

# ---------------------------------------------------------------------------
# Standard Rubik's cube notation
# ---------------------------------------------------------------------------

FACES: tuple[str, ...] = ('U', 'D', 'R', 'L', 'F', 'B')

# Axis grouping — faces that share a rotation axis
AXIS_OF: dict[str, int] = {
    'U': 0, 'D': 0,   # Up / Down axis
    'R': 1, 'L': 1,   # Right / Left axis
    'F': 2, 'B': 2,   # Front / Back axis
}

SUFFIXES: tuple[str, ...] = ('', "'", '2')   # clockwise, counter-clockwise, half-turn

DEFAULT_SCRAMBLE_LENGTH = 20

_U64_MASK = 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Deterministic PRNG — splitmix64
# ---------------------------------------------------------------------------

class _SplitMix64:
    """Deterministic PRNG seeded from a snowflake integer.

    Uses the splitmix64 generator — the same family of constants found in
    the snowflake anonymizer's key schedule — to produce a stream of
    pseudo-random 64-bit values from a single seed.
    """

    def __init__(self, seed: int) -> None:
        # Hash the seed with SHA-256 so that the PRNG state cannot be
        # inverted back to the original snowflake.  SplitMix64's mixing
        # function is fully invertible; without this pre-hash an observer
        # who sees the scramble output could recover the seed in closed form.
        seed_bytes = seed.to_bytes((seed.bit_length() + 7) // 8 or 1, "little")
        digest = hashlib.sha256(seed_bytes).digest()
        self._state = int.from_bytes(digest[:8], "little") & _U64_MASK

    def _next(self) -> int:
        """Advance state and return a 64-bit value."""
        self._state = (self._state + 0x9E3779B97F4A7C15) & _U64_MASK
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _U64_MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _U64_MASK
        z ^= z >> 31
        return z

    def choice(self, n: int) -> int:
        """Return a uniformly distributed integer in ``[0, n)``.

        Uses rejection sampling to avoid modulo bias.
        """
        if n <= 0:
            raise ValueError("n must be positive")
        limit = _U64_MASK - (_U64_MASK % n)
        while True:
            val = self._next()
            if val <= limit:
                return val % n


# ---------------------------------------------------------------------------
# CubeRandomizer
# ---------------------------------------------------------------------------

class CubeRandomizer:
    """Rubik's cube scramble generator driven by snowflake-anonymized numbers.

    Args:
        scramble_length: Number of moves in the generated scramble.
                         Defaults to 20 (WCA-style competition scrambles use
                         roughly this length for a 3x3 cube).

    Example::

        from snowflake_anonymizer import SnowflakeAnonymizer
        from rubiks_randomizer import CubeRandomizer

        sa = SnowflakeAnonymizer(key=0xDEADBEEF)
        cr = CubeRandomizer()

        scramble = cr.scramble_string(sa.anonymize(42))
        # e.g. "R2 U' F D2 L B' R U2 F' D ..."
    """

    def __init__(self, scramble_length: int = DEFAULT_SCRAMBLE_LENGTH) -> None:
        if scramble_length < 1:
            raise ValueError("scramble_length must be at least 1")
        self._length = scramble_length

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def randomize(self, snowflake: int) -> list[str]:
        """Convert a snowflake integer into a valid Rubik's cube scramble.

        Args:
            snowflake: Non-negative integer, typically the output of
                       ``SnowflakeAnonymizer.anonymize()``.

        Returns:
            List of move strings, e.g. ``["R2", "U'", "F", "D2", ...]``.
        """
        if snowflake < 0:
            raise ValueError("snowflake must be non-negative")

        rng = _SplitMix64(snowflake)

        moves: list[str] = []
        prev_face: str | None = None
        prev_prev_face: str | None = None

        for _ in range(self._length):
            available = self._available_faces(prev_face, prev_prev_face)
            face = available[rng.choice(len(available))]
            suffix = SUFFIXES[rng.choice(len(SUFFIXES))]

            moves.append(face + suffix)

            prev_prev_face = prev_face
            prev_face = face

        return moves

    def scramble_string(self, snowflake: int) -> str:
        """Return the scramble as a single space-separated string.

        Args:
            snowflake: Non-negative integer seed.

        Returns:
            Scramble notation, e.g. ``"R2 U' F D2 L B' R U2 F' D ..."``.
        """
        return ' '.join(self.randomize(snowflake))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _available_faces(
        prev_face: str | None,
        prev_prev_face: str | None,
    ) -> list[str]:
        """Determine which faces are legal for the next move.

        Rules:
          - Cannot repeat the immediately preceding face.
          - After two consecutive moves on the same axis, the next move
            must be on a different axis.
        """
        available = list(FACES)

        if prev_face is not None:
            # Rule 1: no same-face repeats
            available = [f for f in available if f != prev_face]

            if (
                prev_prev_face is not None
                and AXIS_OF[prev_face] == AXIS_OF[prev_prev_face]
            ):
                # Rule 2: after two same-axis moves, change axis
                blocked_axis = AXIS_OF[prev_face]
                available = [f for f in available if AXIS_OF[f] != blocked_axis]

        return available
