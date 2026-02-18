"""Tests for CubeRandomizer.

Validates the scramble generator across several dimensions:
  1. Validity    – generated scrambles obey Rubik's cube move constraints
  2. Determinism – same snowflake always produces the same scramble
  3. Variety     – different snowflakes produce different scrambles
  4. Coverage    – all faces and suffixes appear in generated scrambles
  5. Integration – end-to-end pipeline with SnowflakeAnonymizer
  6. Edge cases  – boundary inputs and error handling
"""

import pytest
from rubiks_randomizer import CubeRandomizer
from rubiks_randomizer.core import FACES, AXIS_OF, SUFFIXES
from snowflake_anonymizer import SnowflakeAnonymizer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cr():
    return CubeRandomizer()


@pytest.fixture
def sa():
    return SnowflakeAnonymizer(key=0xDEADBEEF_CAFEBABE)


# ---------------------------------------------------------------------------
# 1. Validity — scrambles obey move constraints
# ---------------------------------------------------------------------------

def _parse_move(move: str) -> tuple[str, str]:
    """Split a move string into (face, suffix)."""
    face = move[0]
    suffix = move[1:]
    return face, suffix


def _validate_scramble(moves: list[str]) -> None:
    """Assert that a scramble obeys the two constraint rules."""
    for i, move in enumerate(moves):
        face, suffix = _parse_move(move)

        # Every face must be a valid Rubik's cube face
        assert face in FACES, f"Invalid face '{face}' in move '{move}'"

        # Every suffix must be valid
        assert suffix in SUFFIXES, f"Invalid suffix '{suffix}' in move '{move}'"

        if i > 0:
            prev_face = _parse_move(moves[i - 1])[0]
            # Rule 1: no consecutive same-face moves
            assert face != prev_face, (
                f"Same-face repeat at position {i}: {moves[i-1]} then {move}"
            )

        if i > 1:
            prev_face = _parse_move(moves[i - 1])[0]
            prev_prev_face = _parse_move(moves[i - 2])[0]
            # Rule 2: no three consecutive same-axis moves
            if AXIS_OF[prev_face] == AXIS_OF[prev_prev_face]:
                assert AXIS_OF[face] != AXIS_OF[prev_face], (
                    f"Three same-axis moves at position {i}: "
                    f"{moves[i-2]}, {moves[i-1]}, {move}"
                )


def test_default_scramble_is_valid(cr):
    """A scramble from an arbitrary snowflake must obey all move rules."""
    for seed in [0, 1, 42, 999, 2**32, 2**64 - 1]:
        moves = cr.randomize(seed)
        assert len(moves) == 20
        _validate_scramble(moves)


def test_validity_across_many_seeds(cr):
    """Validate move constraints over 1 000 different seeds."""
    for seed in range(1000):
        _validate_scramble(cr.randomize(seed))


def test_custom_length_scramble_is_valid():
    cr = CubeRandomizer(scramble_length=50)
    moves = cr.randomize(12345)
    assert len(moves) == 50
    _validate_scramble(moves)


def test_single_move_scramble():
    cr = CubeRandomizer(scramble_length=1)
    moves = cr.randomize(0)
    assert len(moves) == 1
    _validate_scramble(moves)


# ---------------------------------------------------------------------------
# 2. Determinism
# ---------------------------------------------------------------------------

def test_deterministic(cr):
    """Same snowflake must always produce the same scramble."""
    a = cr.randomize(42)
    b = cr.randomize(42)
    assert a == b


def test_deterministic_string(cr):
    a = cr.scramble_string(42)
    b = cr.scramble_string(42)
    assert a == b


def test_separate_instances_same_result():
    cr1 = CubeRandomizer()
    cr2 = CubeRandomizer()
    assert cr1.randomize(999) == cr2.randomize(999)


# ---------------------------------------------------------------------------
# 3. Variety — different snowflakes → different scrambles
# ---------------------------------------------------------------------------

def test_different_seeds_different_scrambles(cr):
    """100 different snowflakes should produce 100 different scrambles."""
    scrambles = {cr.scramble_string(seed) for seed in range(100)}
    assert len(scrambles) == 100


def test_similar_seeds_different_scrambles(cr):
    """Adjacent snowflake values should produce completely different scrambles."""
    s1 = cr.randomize(1000)
    s2 = cr.randomize(1001)
    # They should differ in most positions
    diffs = sum(1 for a, b in zip(s1, s2) if a != b)
    assert diffs >= len(s1) // 2, (
        f"Only {diffs}/{len(s1)} moves differ between seeds 1000 and 1001"
    )


# ---------------------------------------------------------------------------
# 4. Coverage — all faces and suffixes appear
# ---------------------------------------------------------------------------

def test_all_faces_appear(cr):
    """Over many scrambles, every face should appear at least once."""
    seen_faces: set[str] = set()
    for seed in range(50):
        for move in cr.randomize(seed):
            seen_faces.add(_parse_move(move)[0])
    assert seen_faces == set(FACES)


def test_all_suffixes_appear(cr):
    """Over many scrambles, every suffix type should appear at least once."""
    seen_suffixes: set[str] = set()
    for seed in range(50):
        for move in cr.randomize(seed):
            seen_suffixes.add(_parse_move(move)[1])
    assert seen_suffixes == set(SUFFIXES)


# ---------------------------------------------------------------------------
# 5. Integration with SnowflakeAnonymizer
# ---------------------------------------------------------------------------

def test_end_to_end_pipeline(sa, cr):
    """number → anonymize → randomize should produce a valid scramble."""
    for number in [0, 1, 42, 2**32, 2**64 - 1]:
        snowflake = sa.anonymize(number)
        moves = cr.randomize(snowflake)
        assert len(moves) == 20
        _validate_scramble(moves)


def test_pipeline_determinism(sa, cr):
    """The full pipeline must be deterministic."""
    s1 = cr.scramble_string(sa.anonymize(42))
    s2 = cr.scramble_string(sa.anonymize(42))
    assert s1 == s2


def test_pipeline_different_inputs_different_scrambles(sa, cr):
    """Different input numbers (through the anonymizer) produce different scrambles."""
    scrambles = {cr.scramble_string(sa.anonymize(n)) for n in range(100)}
    assert len(scrambles) == 100


def test_pipeline_different_keys(cr):
    """Different anonymizer keys produce different scrambles for the same input."""
    scrambles = set()
    for key in range(20):
        sa = SnowflakeAnonymizer(key=key)
        scrambles.add(cr.scramble_string(sa.anonymize(42)))
    assert len(scrambles) == 20


def test_pipeline_with_passphrase(cr):
    """Works with passphrase-keyed anonymizers."""
    sa = SnowflakeAnonymizer.from_passphrase("winter is cold")
    moves = cr.randomize(sa.anonymize(42))
    _validate_scramble(moves)


def test_pipeline_32bit(cr):
    """Works with 32-bit anonymizer output."""
    sa = SnowflakeAnonymizer(key=0xDEAD, bit_width=32)
    for n in [0, 1, 2**32 - 1]:
        moves = cr.randomize(sa.anonymize(n))
        _validate_scramble(moves)


# ---------------------------------------------------------------------------
# 6. scramble_string format
# ---------------------------------------------------------------------------

def test_scramble_string_format(cr):
    """scramble_string should return moves separated by single spaces."""
    result = cr.scramble_string(42)
    parts = result.split(' ')
    assert len(parts) == 20
    # Re-parsing should match the list form
    assert parts == cr.randomize(42)


# ---------------------------------------------------------------------------
# 7. Edge cases & error handling
# ---------------------------------------------------------------------------

def test_zero_snowflake(cr):
    """Zero is a valid snowflake value."""
    moves = cr.randomize(0)
    assert len(moves) == 20
    _validate_scramble(moves)


def test_large_snowflake(cr):
    """Very large snowflake values should work fine."""
    moves = cr.randomize(2**128)
    assert len(moves) == 20
    _validate_scramble(moves)


def test_negative_snowflake_raises(cr):
    with pytest.raises(ValueError):
        cr.randomize(-1)


def test_invalid_scramble_length():
    with pytest.raises(ValueError):
        CubeRandomizer(scramble_length=0)
    with pytest.raises(ValueError):
        CubeRandomizer(scramble_length=-5)
