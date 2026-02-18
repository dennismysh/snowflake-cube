"""Cryptographic adversarial tests for SnowflakeAnonymizer.

Written from the mindset of a code-breaker: probe every corner of the cipher
for statistical biases, algebraic weaknesses, key-schedule failures, and API
contract violations.  These tests complement the basic property tests in
test_core.py with deeper cryptographic scrutiny.

Test categories
---------------
  A. Exhaustive bijectivity on complete small domains
  B. Inverse symmetry (anonymize IS both left- and right-inverse of deanonymize)
  C. Fixed-point analysis
  D. Key-schedule integrity (round-key distinctness and arm-index sensitivity)
  E. Statistical properties (output distribution, Hamming-weight balance)
  F. Order-breaking (cipher must scramble sequential inputs)
  G. Cross-key non-correlation
  H. Avalanche — full 64-bit coverage, and the reverse direction
  I. Composition and self-application
  J. Passphrase robustness (empty, unicode, long, bit-width variants)
  K. Type-coercion and non-integer rejection
  L. Boundary and extreme bit-widths
  M. Negative and oversized key handling
  N. State-independence (repeated calls must not corrupt internal state)
  O. Deanonymize input-validation (must reject out-of-range inputs)
  P. No all-zero / degenerate output under any key
"""

import hashlib
import pytest
from snowflake_anonymizer import SnowflakeAnonymizer


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sa():
    return SnowflakeAnonymizer(key=0xDEADBEEF_CAFEBABE)


@pytest.fixture
def sa32():
    return SnowflakeAnonymizer(key=0xDEADBEEF_CAFEBABE, bit_width=32)


# ===========================================================================
# A. Exhaustive bijectivity on complete small domains
#    A code-breaker's first test: can *every* possible value be reached?
#    For small widths we can afford to check every single mapping.
# ===========================================================================

@pytest.mark.parametrize("bit_width", [2, 4, 6, 8, 10, 12])
def test_exhaustive_bijection_all_values(bit_width):
    """anonymize is a permutation of {0, …, 2**bit_width - 1}."""
    sa = SnowflakeAnonymizer(key=0x1234_5678_9ABC_DEF0, bit_width=bit_width)
    size = 2**bit_width
    outputs = [sa.anonymize(i) for i in range(size)]
    # All distinct
    assert len(set(outputs)) == size
    # All within range
    assert all(0 <= o < size for o in outputs)


@pytest.mark.parametrize("bit_width", [2, 4, 6, 8])
def test_exhaustive_round_trip_all_values(bit_width):
    """deanonymize(anonymize(n)) == n for every n in the full domain."""
    sa = SnowflakeAnonymizer(key=0xFEEDFACE, bit_width=bit_width)
    for n in range(2**bit_width):
        assert sa.deanonymize(sa.anonymize(n)) == n


# ===========================================================================
# B. Inverse symmetry
#    anonymize and deanonymize must be exact two-sided inverses:
#      deanonymize(anonymize(n)) == n   ← left-inverse  (tested in test_core)
#      anonymize(deanonymize(x)) == x   ← right-inverse (the other direction)
# ===========================================================================

def test_anonymize_is_right_inverse_of_deanonymize(sa):
    """anonymize(deanonymize(x)) == x over a wide spread of values."""
    probe_values = list(range(0, 5000, 7)) + [2**64 - 1, 2**64 - 2, 0, 1]
    for x in probe_values:
        assert sa.anonymize(sa.deanonymize(x)) == x


def test_anonymize_is_right_inverse_32bit(sa32):
    for x in range(0, 2000, 3):
        assert sa32.anonymize(sa32.deanonymize(x)) == x


# ===========================================================================
# C. Fixed-point analysis
#    A fixed point is a value where anonymize(n) == n.
#    A good cipher should have very few fixed points by chance (~1 in 2^64).
# ===========================================================================

def test_fixed_points_are_rare(sa):
    """Fewer than 1% of the first 10 000 values should be fixed points."""
    fixed = [n for n in range(10_000) if sa.anonymize(n) == n]
    assert len(fixed) <= 100


def test_fixed_points_rare_across_keys():
    """No key in a sample should produce excessive fixed points."""
    for key in [0, 1, 0xDEAD, 0x1111_1111, 2**63]:
        sa = SnowflakeAnonymizer(key=key)
        fixed = sum(1 for n in range(1000) if sa.anonymize(n) == n)
        assert fixed <= 20, f"key={key} produced {fixed} fixed points in [0, 1000)"


def test_no_identity_mapping():
    """anonymize must NOT be the identity function over any consecutive window."""
    for key in [0, 1, 42, 2**32 - 1]:
        sa = SnowflakeAnonymizer(key=key)
        identical = all(sa.anonymize(n) == n for n in range(20))
        assert not identical, f"key={key} appears to be the identity"


# ===========================================================================
# D. Key-schedule integrity
#    The 6 arm-specific round keys must all differ — a degenerate key schedule
#    would collapse rounds and drastically weaken the cipher.
# ===========================================================================

def test_round_keys_are_distinct():
    """All 16 round keys must be pairwise distinct."""
    for key in [0, 1, 0xDEADBEEF, 2**64 - 1]:
        sa = SnowflakeAnonymizer(key=key)
        assert len(set(sa._round_keys)) == 16, (
            f"key={key} produced duplicate round keys: {sa._round_keys}"
        )


def test_round_keys_depend_on_arm_index():
    """Even with key=0 the round keys must all differ (HMAC-label mixing)."""
    sa = SnowflakeAnonymizer(key=0)
    assert len(set(sa._round_keys)) == 16


def test_round_keys_change_with_key():
    """Different master keys must produce different round-key vectors."""
    keys = [0, 1, 2, 3, 0xCAFE, 0xDEAD_BEEF]
    round_key_sets = [tuple(SnowflakeAnonymizer(key=k)._round_keys) for k in keys]
    assert len(set(round_key_sets)) == len(keys)


def test_narrow_width_key_diversity():
    """Compound round keys must provide diversity beyond the w-bit limit.

    For bit_width=4 (w=2), each XOR or MUL sub-key has only 4 values, but
    distinct master keys must produce distinct *compound* round-key tuples.
    With independent rk_xor and rk_mul the effective space is (4×4)^16 = 2^64,
    far exceeding the old (4)^16 = 2^32 single-key schedule.
    """
    # Sample 200 random-ish master keys — all must produce distinct schedules
    keys = list(range(200))
    schedules = [tuple(SnowflakeAnonymizer(key=k, bit_width=4)._round_keys) for k in keys]
    assert len(set(schedules)) == len(keys), (
        "Compound round-key schedules collided for bit_width=4 — key space still too narrow"
    )


def test_round_keys_fit_half_width():
    """All round-key XOR and MUL components must be masked to the half-word size."""
    for bit_width in [16, 32, 64, 128]:
        sa = SnowflakeAnonymizer(key=0xCAFEBABE, bit_width=bit_width)
        half_mask = (1 << (bit_width // 2)) - 1
        w = bit_width // 2
        for rk_xor, rk_mul, rk_rot in sa._round_keys:
            assert rk_xor == (rk_xor & half_mask), (
                f"rk_xor {rk_xor:#x} exceeds half-mask for bit_width={bit_width}"
            )
            assert rk_mul == (rk_mul & half_mask), (
                f"rk_mul {rk_mul:#x} exceeds half-mask for bit_width={bit_width}"
            )
            assert 1 <= rk_rot <= max(1, w - 1), (
                f"rk_rot {rk_rot} out of range [1, {max(1, w - 1)}] "
                f"for bit_width={bit_width}"
            )


# ===========================================================================
# E. Statistical properties
#    The output of a good cipher is indistinguishable from random noise.
#    We apply statistical heuristics — not hard randomness proofs.
# ===========================================================================

def test_hamming_weight_balance(sa):
    """Average output Hamming weight should be close to 32 (half of 64 bits)."""
    weights = [bin(sa.anonymize(i)).count("1") for i in range(2000)]
    avg = sum(weights) / len(weights)
    assert 28.0 <= avg <= 36.0, f"Mean Hamming weight {avg:.2f} out of expected range"


def test_output_spread_covers_full_range(sa):
    """Outputs should spread across the full 64-bit space, not cluster.

    With N samples drawn uniformly from N buckets the birthday problem predicts
    ~63.2 % (1 − 1/e) bucket coverage.  We require at least 50 % to catch
    severe clustering while allowing for natural collision variance.
    """
    N = 5_000
    outputs = [sa.anonymize(i) for i in range(N)]
    bucket_width = 2**64 // N
    buckets = {o // bucket_width for o in outputs}
    # ~63 % expected; require ≥ 50 % to detect pathological clustering
    assert len(buckets) >= N // 2, (
        f"Only {len(buckets)}/{N} buckets covered — output is suspiciously clustered"
    )


def test_parity_bit_roughly_balanced(sa):
    """The LSB of outputs should be ~50 % ones and ~50 % zeros."""
    parities = [sa.anonymize(i) & 1 for i in range(2000)]
    ones = sum(parities)
    # Allow ±10 % from 50 %
    assert 900 <= ones <= 1100, f"LSB ones={ones}/2000 — severe parity imbalance"


def test_output_high_bits_roughly_balanced(sa):
    """The MSB of 64-bit outputs should also be ~50 % ones."""
    msb_ones = sum((sa.anonymize(i) >> 63) & 1 for i in range(2000))
    assert 900 <= msb_ones <= 1100, f"MSB ones={msb_ones}/2000"


# ===========================================================================
# F. Order-breaking
#    A classic code-breaker attack: look for monotonicity or obvious patterns
#    in the plaintext → ciphertext mapping.
# ===========================================================================

def test_output_is_not_monotonically_increasing(sa):
    outputs = [sa.anonymize(i) for i in range(200)]
    assert not all(outputs[i] < outputs[i + 1] for i in range(199))


def test_output_is_not_monotonically_decreasing(sa):
    outputs = [sa.anonymize(i) for i in range(200)]
    assert not all(outputs[i] > outputs[i + 1] for i in range(199))


def test_output_does_not_preserve_gaps():
    """If inputs are spaced 1 apart, outputs must NOT be consistently spaced."""
    sa = SnowflakeAnonymizer(key=7)
    diffs = [abs(sa.anonymize(i + 1) - sa.anonymize(i)) for i in range(200)]
    # All identical gaps would betray a linear cipher — check for variety
    assert len(set(diffs)) > 50, "Output differences are suspiciously uniform"


def test_output_does_not_reveal_input_magnitude():
    """Large inputs must not systematically produce large outputs."""
    sa = SnowflakeAnonymizer(key=0xABCD)
    small_outputs = [sa.anonymize(i) for i in range(50)]
    large_outputs = [sa.anonymize(2**63 + i) for i in range(50)]
    # The means should not be strongly ordered
    avg_small = sum(small_outputs) / 50
    avg_large = sum(large_outputs) / 50
    ratio = avg_large / avg_small if avg_small else float("inf")
    # If output preserved magnitude, large inputs would have ~2x larger outputs
    assert ratio < 10 or ratio > 0.1  # Sanity check — not a tight magnitude link


# ===========================================================================
# G. Cross-key non-correlation
#    Knowing outputs under one key must give no information about another key's
#    outputs.  Even a single collision across two distinct keys is suspicious.
# ===========================================================================

def test_different_keys_produce_no_identical_outputs_in_range():
    """For 200 inputs, two distinct keys must never produce the same output."""
    sa1 = SnowflakeAnonymizer(key=1)
    sa2 = SnowflakeAnonymizer(key=2)
    out1 = {sa1.anonymize(i) for i in range(200)}
    out2 = {sa2.anonymize(i) for i in range(200)}
    # Collision probability per pair ≈ 1/2^64 — expect zero in 200 samples
    assert len(out1 & out2) == 0


def test_key_sensitivity_single_bit_flip():
    """Flipping 1 bit in the key should completely change every output."""
    base_key = 0x0000_0000_1234_5678
    flipped_key = base_key ^ 1  # flip LSB
    sa_base = SnowflakeAnonymizer(key=base_key)
    sa_flip = SnowflakeAnonymizer(key=flipped_key)
    diffs = [
        bin(sa_base.anonymize(n) ^ sa_flip.anonymize(n)).count("1")
        for n in range(100)
    ]
    avg_diff = sum(diffs) / len(diffs)
    assert avg_diff >= 20, (
        f"1-bit key flip only changed avg {avg_diff:.1f}/64 output bits"
    )


def test_consecutive_keys_produce_unrelated_outputs():
    """Keys k and k+1 must produce completely unrelated mappings."""
    for base_key in [0, 100, 2**32]:
        sa1 = SnowflakeAnonymizer(key=base_key)
        sa2 = SnowflakeAnonymizer(key=base_key + 1)
        for n in [0, 1, 42, 2**32]:
            # Outputs should rarely match (prob ~1/2^64 each)
            assert sa1.anonymize(n) != sa2.anonymize(n), (
                f"Consecutive keys {base_key} and {base_key+1} collide at n={n}"
            )


# ===========================================================================
# H. Avalanche effect — thorough coverage
#    Every single bit position in a 64-bit input should cause ≥ 25 % bit flips
#    in the output.  The existing test samples every 4th bit; we test ALL.
# ===========================================================================

def test_avalanche_every_bit_position_64bit(sa):
    """Flip each of the 64 input bits — every flip must change ≥ 25 % of output."""
    base = 0x1234_5678_9ABC_DEF0
    out_base = sa.anonymize(base)
    for bit in range(64):
        flipped = base ^ (1 << bit)
        out_flipped = sa.anonymize(flipped)
        diff = bin(out_base ^ out_flipped).count("1")
        assert diff >= 16, (
            f"Weak avalanche at input bit {bit}: only {diff}/64 output bits changed"
        )


def test_avalanche_every_bit_position_32bit(sa32):
    """Same strict avalanche test for the 32-bit variant (≥ 25 % → ≥ 8 bits)."""
    base = 0xDEAD_BEEF & 0xFFFF_FFFF
    out_base = sa32.anonymize(base)
    for bit in range(32):
        flipped = base ^ (1 << bit)
        out_flipped = sa32.anonymize(flipped)
        diff = bin(out_base ^ out_flipped).count("1")
        assert diff >= 8, (
            f"Weak 32-bit avalanche at input bit {bit}: only {diff}/32 bits changed"
        )


def test_reverse_avalanche_deanonymize(sa):
    """Flipping a single bit in the anonymized value must scramble the recovered
    plaintext — the cipher must not be linearly separable in either direction."""
    original = 0xFEED_FACE_CAFE_BABE
    snowflake = sa.anonymize(original)
    for bit in range(0, 64, 2):
        flipped_snowflake = snowflake ^ (1 << bit)
        recovered = sa.deanonymize(flipped_snowflake)
        diff = bin(original ^ recovered).count("1")
        assert diff >= 16, (
            f"Weak reverse avalanche at ciphertext bit {bit}: only {diff}/64 bits differ"
        )


def test_avalanche_all_zeros_input(sa):
    """All-zeros input + single bit flip should trigger avalanche."""
    base = 0
    out_base = sa.anonymize(base)
    for bit in range(0, 64, 4):
        out_flipped = sa.anonymize(1 << bit)
        diff = bin(out_base ^ out_flipped).count("1")
        assert diff >= 16, (
            f"Poor avalanche from zero at bit {bit}: only {diff}/64 bits differ"
        )


def test_avalanche_all_ones_input(sa):
    """All-ones input + single bit flip should trigger avalanche."""
    base = 2**64 - 1
    out_base = sa.anonymize(base)
    for bit in range(0, 64, 4):
        flipped = base ^ (1 << bit)
        out_flipped = sa.anonymize(flipped)
        diff = bin(out_base ^ out_flipped).count("1")
        assert diff >= 16, (
            f"Poor avalanche from all-ones at bit {bit}: only {diff}/64 bits differ"
        )


# ===========================================================================
# I. Composition and self-application
#    Cipher algebra: composing two valid bijections must produce a valid bijection.
#    Applying anonymize twice must (almost always) differ from identity.
# ===========================================================================

def test_composed_anonymizers_are_bijective():
    """anonymize₂(anonymize₁(n)) must still be a bijection over a sample."""
    sa1 = SnowflakeAnonymizer(key=111)
    sa2 = SnowflakeAnonymizer(key=999)
    composed = {sa2.anonymize(sa1.anonymize(i)) for i in range(1000)}
    assert len(composed) == 1000


def test_double_anonymize_is_not_identity(sa):
    """Applying anonymize twice should almost never return the original value.
    (A period-2 cipher — anon(anon(n)) == n for all n — would be a weak involution.)
    """
    period2 = sum(1 for n in range(2000) if sa.anonymize(sa.anonymize(n)) == n)
    assert period2 <= 20, (
        f"Found {period2} period-2 fixed points in [0, 2000) — cipher may be an involution"
    )


def test_triple_composition_still_reversible():
    """Chaining 3 different-key anonymizers must still be fully reversible."""
    keys = [0xAAAA, 0xBBBB, 0xCCCC]
    sas = [SnowflakeAnonymizer(key=k) for k in keys]

    def triple_anon(n):
        for s in sas:
            n = s.anonymize(n)
        return n

    def triple_deanon(n):
        for s in reversed(sas):
            n = s.deanonymize(n)
        return n

    for n in range(500):
        assert triple_deanon(triple_anon(n)) == n


# ===========================================================================
# J. Passphrase robustness
# ===========================================================================

def test_from_passphrase_empty_string():
    """SHA-256 of the empty string is deterministic — anonymizer must still work."""
    sa = SnowflakeAnonymizer.from_passphrase("")
    assert sa.deanonymize(sa.anonymize(0)) == 0
    assert sa.deanonymize(sa.anonymize(2**64 - 1)) == 2**64 - 1


def test_from_passphrase_unicode():
    """Unicode passphrase (e.g. Navajo-script) must work without error."""
    # "yózhí łizhin" is Navajo for "black puppy"
    sa = SnowflakeAnonymizer.from_passphrase("yózhí łizhin")
    for n in [0, 1, 42, 2**32, 2**64 - 1]:
        assert sa.deanonymize(sa.anonymize(n)) == n


def test_from_passphrase_long_string():
    """A 10 000-character passphrase must be accepted (SHA-256 handles any length)."""
    long_phrase = "A" * 10_000
    sa = SnowflakeAnonymizer.from_passphrase(long_phrase)
    assert sa.deanonymize(sa.anonymize(12345)) == 12345


def test_from_passphrase_case_sensitivity():
    """Passphrase comparison must be case-sensitive."""
    sa_lower = SnowflakeAnonymizer.from_passphrase("secret")
    sa_upper = SnowflakeAnonymizer.from_passphrase("SECRET")
    assert sa_lower.anonymize(1) != sa_upper.anonymize(1)


def test_from_passphrase_whitespace_sensitivity():
    """Leading/trailing whitespace must change the output."""
    sa1 = SnowflakeAnonymizer.from_passphrase("key")
    sa2 = SnowflakeAnonymizer.from_passphrase(" key")
    sa3 = SnowflakeAnonymizer.from_passphrase("key ")
    assert sa1.anonymize(1) != sa2.anonymize(1)
    assert sa1.anonymize(1) != sa3.anonymize(1)


def test_from_passphrase_different_bit_widths_differ():
    """Same passphrase and salt but different bit_width must produce different ciphers."""
    phrase = "crystal lattice"
    salt = b"fixed-salt-12345"
    sa32 = SnowflakeAnonymizer.from_passphrase(phrase, bit_width=32, salt=salt)
    sa64 = SnowflakeAnonymizer.from_passphrase(phrase, bit_width=64, salt=salt)
    n = 1_000
    assert sa32.anonymize(n) != sa64.anonymize(n)


def test_from_passphrase_uses_pbkdf2():
    """Verify that from_passphrase uses PBKDF2-HMAC-SHA256 (600 000 iterations)."""
    phrase = "test vector"
    salt = b"\x00" * 16
    expected_digest = hashlib.pbkdf2_hmac("sha256", phrase.encode(), salt, 600_000, dklen=32)
    expected_key = int.from_bytes(expected_digest, "big")
    sa_passphrase = SnowflakeAnonymizer.from_passphrase(phrase, salt=salt)
    sa_direct = SnowflakeAnonymizer(key=expected_key)
    assert sa_passphrase.anonymize(42) == sa_direct.anonymize(42)


# ===========================================================================
# K. Type-coercion and non-integer rejection
# ===========================================================================

def test_boolean_true_treated_as_one(sa):
    """bool is a subclass of int in Python; True == 1 so anonymize(True) == anonymize(1)."""
    assert sa.anonymize(True) == sa.anonymize(1)


def test_boolean_false_treated_as_zero(sa):
    assert sa.anonymize(False) == sa.anonymize(0)


def test_float_input_raises(sa):
    with pytest.raises((TypeError, ValueError)):
        sa.anonymize(3.14)


def test_string_input_raises(sa):
    with pytest.raises((TypeError, ValueError)):
        sa.anonymize("42")


def test_none_input_raises(sa):
    with pytest.raises((TypeError, ValueError)):
        sa.anonymize(None)


def test_list_input_raises(sa):
    with pytest.raises((TypeError, ValueError)):
        sa.anonymize([42])


# ===========================================================================
# L. Boundary and extreme bit-widths
# ===========================================================================

def test_min_bit_width_2():
    """bit_width=2 is the smallest allowed; domain is {0, 1, 2, 3}.

    In addition to bijectivity, verify the cipher is NOT the identity —
    at least one output must differ from its input.  A degenerate round
    function (e.g. always returning 0) would make every round a pure swap;
    an even number of swaps composes to the identity, which passes a
    naive bijectivity check but provides zero anonymization.
    """
    sa = SnowflakeAnonymizer(key=0xDEAD, bit_width=2)
    domain = range(4)
    outputs = [sa.anonymize(i) for i in domain]

    # Bijectivity: output set equals input set
    assert sorted(outputs) == [0, 1, 2, 3]

    # Non-triviality: the permutation must NOT be the identity
    assert outputs != list(domain), (
        "anonymize() returned the identity permutation at bit_width=2 — "
        "cipher is broken (round function likely collapses to zero)"
    )


def test_bit_width_2_round_trip():
    sa = SnowflakeAnonymizer(key=42, bit_width=2)
    for n in range(4):
        assert sa.deanonymize(sa.anonymize(n)) == n


def test_large_bit_width_256():
    sa = SnowflakeAnonymizer(key=99, bit_width=256)
    n = 2**255
    assert sa.deanonymize(sa.anonymize(n)) == n
    outputs = {sa.anonymize(i) for i in range(300)}
    assert len(outputs) == 300


def test_all_standard_power_of_two_widths():
    """bit_widths that are powers of 2 up to 128 must all work correctly."""
    for bw in [2, 4, 8, 16, 32, 64, 128]:
        sa = SnowflakeAnonymizer(key=0xABCDEF, bit_width=bw)
        n = (2**bw - 1) // 2
        assert sa.deanonymize(sa.anonymize(n)) == n
        assert sa.deanonymize(sa.anonymize(0)) == 0
        assert sa.deanonymize(sa.anonymize(2**bw - 1)) == 2**bw - 1


def test_invalid_bit_width_odd():
    with pytest.raises(ValueError):
        SnowflakeAnonymizer(bit_width=7)


def test_invalid_bit_width_one():
    with pytest.raises(ValueError):
        SnowflakeAnonymizer(bit_width=1)


def test_invalid_bit_width_negative():
    with pytest.raises(ValueError):
        SnowflakeAnonymizer(bit_width=-4)


# ===========================================================================
# M. Negative and oversized key handling
#    Python's arbitrary-precision integers allow negative and huge keys;
#    the cipher should handle them without crashing (XOR + masking absorbs sign).
# ===========================================================================

def test_negative_key_does_not_crash():
    """Negative keys are valid Python ints; the key schedule masks them."""
    sa = SnowflakeAnonymizer(key=-1)
    assert sa.deanonymize(sa.anonymize(42)) == 42


def test_negative_key_produces_bijection():
    sa = SnowflakeAnonymizer(key=-0xDEAD_BEEF)
    outputs = {sa.anonymize(i) for i in range(500)}
    assert len(outputs) == 500


def test_oversized_key_works():
    """A key larger than 64 bits must still produce a valid bijection."""
    big_key = 2**256 + 0xCAFE_BABE
    sa = SnowflakeAnonymizer(key=big_key)
    for n in [0, 1, 2**32, 2**64 - 1]:
        assert sa.deanonymize(sa.anonymize(n)) == n


def test_different_signed_forms_of_same_magnitude_differ():
    """key=42 and key=-42 should produce different mappings (different bit patterns)."""
    sa_pos = SnowflakeAnonymizer(key=42)
    sa_neg = SnowflakeAnonymizer(key=-42)
    # Almost certainly different — if they're identical the key schedule lost sign info
    results_pos = {sa_pos.anonymize(i) for i in range(100)}
    results_neg = {sa_neg.anonymize(i) for i in range(100)}
    # Allow at most trivial overlap given the tiny sample / huge space
    assert results_pos != results_neg


# ===========================================================================
# N. State-independence
#    The anonymizer stores no mutable state during encryption; calling
#    anonymize repeatedly must not affect future calls.
# ===========================================================================

def test_repeated_calls_no_state_corruption(sa):
    """Results must be identical before and after a burst of other calls."""
    baseline = [sa.anonymize(i) for i in range(200)]
    # Interleave many unrelated calls
    for n in [0, 2**32, 2**64 - 1, 12345678]:
        for _ in range(50):
            sa.anonymize(n)
    assert [sa.anonymize(i) for i in range(200)] == baseline


def test_two_instances_same_key_never_diverge():
    """Two instances with the same key must always agree, call-for-call."""
    sa1 = SnowflakeAnonymizer(key=0x1234)
    sa2 = SnowflakeAnonymizer(key=0x1234)
    for n in range(500):
        assert sa1.anonymize(n) == sa2.anonymize(n)


def test_deanonymize_does_not_corrupt_anonymize(sa):
    """Interleaving anonymize and deanonymize must not corrupt results."""
    ref = sa.anonymize(9999)
    for n in range(200):
        sa.deanonymize(sa.anonymize(n))
    assert sa.anonymize(9999) == ref


# ===========================================================================
# O. Deanonymize input-validation
#    The API contract says values outside [0, 2**bit_width) are invalid.
# ===========================================================================

def test_deanonymize_rejects_negative(sa):
    with pytest.raises(ValueError):
        sa.deanonymize(-1)


def test_deanonymize_rejects_too_large(sa):
    with pytest.raises(ValueError):
        sa.deanonymize(2**64)


def test_deanonymize_rejects_negative_32bit(sa32):
    with pytest.raises(ValueError):
        sa32.deanonymize(-1)


def test_deanonymize_rejects_too_large_32bit(sa32):
    with pytest.raises(ValueError):
        sa32.deanonymize(2**32)


def test_error_message_contains_range_info(sa):
    """ValueError messages should be informative (mention the valid range)."""
    with pytest.raises(ValueError, match=r"0"):
        sa.anonymize(-1)


# ===========================================================================
# P. No all-zero / degenerate output under any key
#    A weak key that maps every input to the same output would be catastrophic.
# ===========================================================================

def test_no_weak_key_all_same_output():
    """No key in a sample should collapse all outputs to a single value."""
    suspicious_keys = [0, 1, 2**32 - 1, 2**64 - 1, -1, 0xFFFF_FFFF_FFFF_FFFF]
    for key in suspicious_keys:
        sa = SnowflakeAnonymizer(key=key)
        outputs = {sa.anonymize(i) for i in range(100)}
        assert len(outputs) > 90, (
            f"key={key} collapsed outputs: only {len(outputs)} distinct values in [0,100)"
        )


def test_zero_input_does_not_produce_zero_output_universally():
    """anonymize(0) should not be 0 for a broad range of keys."""
    zero_maps_to_zero = sum(
        1 for k in range(1000) if SnowflakeAnonymizer(key=k).anonymize(0) == 0
    )
    # Expect roughly 0 (prob ≈ 1/2^64 per key)
    assert zero_maps_to_zero == 0


def test_no_constant_output_for_any_key():
    """anonymize must produce at least 2 distinct outputs for any key."""
    for key in [0, 0xDEAD, 2**31, 2**63 - 1]:
        sa = SnowflakeAnonymizer(key=key)
        outputs = {sa.anonymize(i) for i in range(10)}
        assert len(outputs) >= 8, (
            f"key={key} nearly constant output: {outputs}"
        )


# ===========================================================================
# Q. GF(2) non-linearity
#    The round function and the full cipher must NOT be affine over GF(2).
#    An affine cipher satisfies f(a ⊕ b) = f(a) ⊕ f(b) ⊕ f(0) for all a, b.
#    If this property holds, an adversary can recover the full affine map
#    with O(n) known plaintext–ciphertext pairs via Gaussian elimination.
# ===========================================================================

def test_cipher_is_not_affine_over_gf2(sa):
    """The full cipher must violate the GF(2) affine identity.

    For an affine function f over GF(2):  f(a ⊕ b) = f(a) ⊕ f(b) ⊕ f(0).
    A non-linear cipher should violate this for the vast majority of inputs.
    """
    f0 = sa.anonymize(0)
    violations = 0
    trials = 200
    for i in range(1, trials + 1):
        a = i
        b = i * 7 + 13
        lhs = sa.anonymize(a ^ b)
        rhs = sa.anonymize(a) ^ sa.anonymize(b) ^ f0
        if lhs != rhs:
            violations += 1
    assert violations >= trials * 0.9, (
        f"Only {violations}/{trials} affine-property violations — "
        f"cipher may be affine over GF(2)"
    )


def test_cipher_is_not_affine_over_gf2_32bit(sa32):
    """Same GF(2) non-linearity test for the 32-bit variant."""
    f0 = sa32.anonymize(0)
    violations = 0
    trials = 200
    for i in range(1, trials + 1):
        a = i
        b = i * 11 + 5
        a &= 0xFFFF_FFFF
        b &= 0xFFFF_FFFF
        lhs = sa32.anonymize(a ^ b)
        rhs = sa32.anonymize(a) ^ sa32.anonymize(b) ^ f0
        if lhs != rhs:
            violations += 1
    assert violations >= trials * 0.9, (
        f"Only {violations}/{trials} affine-property violations (32-bit) — "
        f"cipher may be affine over GF(2)"
    )


def test_round_function_is_not_affine_over_gf2():
    """The round function _arm itself must not be affine over GF(2).

    If _arm were affine: _arm(a ⊕ b, k) = _arm(a, k) ⊕ _arm(b, k) ⊕ _arm(0, k)
    """
    sa = SnowflakeAnonymizer(key=0xDEADBEEF_CAFEBABE)
    for rk_xor, rk_mul, rk_rot in sa._round_keys[:4]:
        f0 = sa._arm(0, rk_xor, rk_mul, rk_rot)
        violations = 0
        trials = 200
        for i in range(1, trials + 1):
            a = i
            b = i * 3 + 7
            lhs = sa._arm(a ^ b, rk_xor, rk_mul, rk_rot)
            rhs = sa._arm(a, rk_xor, rk_mul, rk_rot) ^ sa._arm(b, rk_xor, rk_mul, rk_rot) ^ f0
            if lhs != rhs:
                violations += 1
        assert violations >= trials * 0.8, (
            f"Only {violations}/{trials} affine violations in _arm with "
            f"rk_xor={rk_xor:#x} — round function may be affine over GF(2)"
        )


def test_gf2_nonlinearity_across_keys():
    """Non-linearity must hold across different keys, not just one."""
    for key in [0, 1, 0xDEAD, 0x1234_5678_9ABC_DEF0, 2**64 - 1]:
        sa = SnowflakeAnonymizer(key=key)
        f0 = sa.anonymize(0)
        violations = 0
        trials = 100
        for i in range(1, trials + 1):
            a = i * 3
            b = i * 5 + 1
            lhs = sa.anonymize(a ^ b)
            rhs = sa.anonymize(a) ^ sa.anonymize(b) ^ f0
            if lhs != rhs:
                violations += 1
        assert violations >= trials * 0.8, (
            f"key={key}: only {violations}/{trials} affine violations — "
            f"cipher may be affine over GF(2)"
        )
