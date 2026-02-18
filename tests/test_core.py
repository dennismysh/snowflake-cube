"""Tests for SnowflakeAnonymizer.

Validates the four properties that make it a sound anonymizer:
  1. Bijectivity  – no two distinct inputs share the same output
  2. Reversibility – deanonymize(anonymize(n)) == n
  3. Determinism   – same key + input always yields the same output
  4. Avalanche     – a 1-bit change in the input flips ≥ 25% of output bits
"""

import pytest
from snowflake_anonymizer import SnowflakeAnonymizer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sa():
    return SnowflakeAnonymizer(key=0xDEADBEEF_CAFEBABE)


@pytest.fixture
def sa32():
    return SnowflakeAnonymizer(key=0xDEADBEEF_CAFEBABE, bit_width=32)


# ---------------------------------------------------------------------------
# 1. Basic transformation
# ---------------------------------------------------------------------------

def test_anonymize_changes_value(sa):
    """The output should differ from the input (with overwhelming probability)."""
    results = {sa.anonymize(n) for n in range(1000)}
    inputs = set(range(1000))
    # Allow at most a handful of coincidental fixed points
    assert len(results - inputs) > 990


def test_output_within_range(sa):
    upper = 2**64 - 1
    for n in [0, 1, upper // 2, upper - 1, upper]:
        out = sa.anonymize(n)
        assert 0 <= out <= upper


def test_output_within_range_32bit(sa32):
    upper = 2**32 - 1
    for n in [0, 1, upper // 2, upper - 1, upper]:
        out = sa32.anonymize(n)
        assert 0 <= out <= upper


# ---------------------------------------------------------------------------
# 2. Bijectivity (no collisions)
# ---------------------------------------------------------------------------

def test_bijective_small_range(sa):
    """1 000 distinct inputs must produce 1 000 distinct outputs."""
    outputs = [sa.anonymize(i) for i in range(1000)]
    assert len(set(outputs)) == 1000


def test_bijective_large_sparse(sa):
    """Outputs across a large sparse sample must all be distinct."""
    inputs = [i * 10**9 for i in range(500)]
    outputs = [sa.anonymize(n) for n in inputs]
    assert len(set(outputs)) == len(inputs)


def test_bijective_32bit(sa32):
    outputs = [sa32.anonymize(i) for i in range(2000)]
    assert len(set(outputs)) == 2000


# ---------------------------------------------------------------------------
# 3. Reversibility
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [
    0, 1, 255, 65535, 2**32 - 1, 2**32, 2**48, 2**64 - 1,
])
def test_round_trip_64bit(sa, n):
    assert sa.deanonymize(sa.anonymize(n)) == n


@pytest.mark.parametrize("n", [0, 1, 1000, 2**16 - 1, 2**32 - 1])
def test_round_trip_32bit(sa32, n):
    assert sa32.deanonymize(sa32.anonymize(n)) == n


def test_deanonymize_is_left_inverse(sa):
    """deanonymize ∘ anonymize = identity over a range of values."""
    for n in range(0, 10_000, 7):
        assert sa.deanonymize(sa.anonymize(n)) == n


# ---------------------------------------------------------------------------
# 4. Determinism
# ---------------------------------------------------------------------------

def test_deterministic(sa):
    a = sa.anonymize(123456789)
    b = sa.anonymize(123456789)
    assert a == b


def test_same_key_same_output():
    sa1 = SnowflakeAnonymizer(key=99)
    sa2 = SnowflakeAnonymizer(key=99)
    assert sa1.anonymize(42) == sa2.anonymize(42)


def test_different_keys_different_outputs():
    """Different keys must produce different anonymization mappings."""
    results = {SnowflakeAnonymizer(key=k).anonymize(42) for k in range(20)}
    assert len(results) == 20


# ---------------------------------------------------------------------------
# 5. Avalanche effect
# ---------------------------------------------------------------------------

def test_avalanche_one_bit_flip(sa):
    """Flipping a single input bit should flip ≥ 25% of output bits."""
    base = 0x0000_0000_DEAD_BEEF
    out_base = sa.anonymize(base)

    for bit in range(0, 64, 4):          # sample every 4th bit position
        flipped_input = base ^ (1 << bit)
        out_flipped = sa.anonymize(flipped_input)
        diff_bits = bin(out_base ^ out_flipped).count("1")
        assert diff_bits >= 16, (
            f"Poor avalanche at bit {bit}: only {diff_bits}/64 bits differ"
        )


def test_avalanche_sequential_inputs(sa):
    """Sequential inputs (n, n+1) should produce very different outputs."""
    for n in range(0, 100):
        a = sa.anonymize(n)
        b = sa.anonymize(n + 1)
        diff_bits = bin(a ^ b).count("1")
        assert diff_bits >= 8, (
            f"Poor avalanche between {n} and {n+1}: only {diff_bits}/64 bits differ"
        )


# ---------------------------------------------------------------------------
# 6. from_passphrase constructor
# ---------------------------------------------------------------------------

def test_from_passphrase_round_trip():
    sa = SnowflakeAnonymizer.from_passphrase("winter is cold")
    for n in [0, 42, 2**32, 2**64 - 1]:
        assert sa.deanonymize(sa.anonymize(n)) == n


def test_from_passphrase_different_phrases():
    sa1 = SnowflakeAnonymizer.from_passphrase("alpha")
    sa2 = SnowflakeAnonymizer.from_passphrase("beta")
    assert sa1.anonymize(1) != sa2.anonymize(1)


def test_from_passphrase_same_phrase_same_output():
    sa1 = SnowflakeAnonymizer.from_passphrase("same")
    sa2 = SnowflakeAnonymizer.from_passphrase("same")
    assert sa1.anonymize(999) == sa2.anonymize(999)


# ---------------------------------------------------------------------------
# 7. Edge cases & error handling
# ---------------------------------------------------------------------------

def test_zero_key():
    sa = SnowflakeAnonymizer(key=0)
    assert sa.deanonymize(sa.anonymize(0)) == 0
    assert sa.deanonymize(sa.anonymize(2**64 - 1)) == 2**64 - 1


def test_out_of_range_raises(sa):
    with pytest.raises(ValueError):
        sa.anonymize(-1)
    with pytest.raises(ValueError):
        sa.anonymize(2**64)


def test_invalid_bit_width():
    with pytest.raises(ValueError):
        SnowflakeAnonymizer(bit_width=3)   # odd
    with pytest.raises(ValueError):
        SnowflakeAnonymizer(bit_width=0)


def test_128bit():
    sa = SnowflakeAnonymizer(key=42, bit_width=128)
    n = 2**127
    assert sa.deanonymize(sa.anonymize(n)) == n
    outputs = {sa.anonymize(i) for i in range(500)}
    assert len(outputs) == 500
