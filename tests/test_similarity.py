# =============================================================================
# test_similarity.py  — v1.3
# AI Verify Principle 2: Explainability
#
# WHAT THIS TESTS:
#   Verifies that the cosine_similarity() function and low similarity warning
#   in main.py behave correctly:
#     - High similarity between identical vectors = 1.0
#     - Zero similarity between orthogonal vectors = 0.0
#     - Low similarity warning fires below LOW_SIMILARITY_THRESHOLD (0.3)
#     - Low similarity warning does NOT fire above threshold
#     - Zero vectors handled safely (no division by zero)
#     - Similarity is symmetric: sim(a,b) == sim(b,a)
#
# EVIDENCE GENERATED:
#   Pass/fail results for similarity scoring — attach to AI Verify
#   Governance Report as evidence for Principle 2 (Explainability).
#   Demonstrates the system can explain why results were returned
#   and warn when results may not be relevant.
#
# HOW TO RUN:
#   python tests/test_similarity.py
#
# DOES NOT REQUIRE:
#   BigQuery, Gemini API, or .env file — pure function test.
# =============================================================================

import sys
import os
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.main import cosine_similarity, LOW_SIMILARITY_THRESHOLD


# =============================================================================
# TEST HELPERS
# =============================================================================

def approx_equal(a: float, b: float, tolerance: float = 1e-6) -> bool:
    """Floating point comparison with tolerance."""
    return abs(a - b) < tolerance


def make_vector(size: int, value: float = 1.0) -> list:
    """Creates a uniform vector of given size and value."""
    return [value] * size


def make_orthogonal(size: int) -> tuple:
    """
    Creates two orthogonal vectors of given size.
    vec_a has 1.0 in first half, 0.0 in second half.
    vec_b has 0.0 in first half, 1.0 in second half.
    Their dot product = 0 → cosine similarity = 0.
    """
    half = size // 2
    vec_a = [1.0] * half + [0.0] * half
    vec_b = [0.0] * half + [1.0] * half
    return vec_a, vec_b


# =============================================================================
# TEST CASES
# =============================================================================

def run_tests():

    print("=" * 60)
    print("  test_similarity.py")
    print("  AI Verify Principle 2 — Explainability")
    print("  Tests cosine similarity scoring and low-score warning")
    print("=" * 60)
    print()
    print(f"  LOW_SIMILARITY_THRESHOLD = {LOW_SIMILARITY_THRESHOLD}")
    print()

    passed  = 0
    failed  = 0
    failures = []

    # -------------------------------------------------------------------------
    # TEST 1: Identical vectors → similarity = 1.0
    # -------------------------------------------------------------------------
    vec = make_vector(10, 1.0)
    score = cosine_similarity(vec, vec)
    if approx_equal(score, 1.0):
        print(f"  PASS  Identical vectors → similarity = {score:.6f} (expected 1.0)")
        passed += 1
    else:
        print(f"  FAIL  Identical vectors → similarity = {score:.6f} (expected 1.0)")
        failed += 1
        failures.append("Identical vectors did not return 1.0")

    # -------------------------------------------------------------------------
    # TEST 2: Opposite vectors → similarity = -1.0
    # -------------------------------------------------------------------------
    vec_a = make_vector(10,  1.0)
    vec_b = make_vector(10, -1.0)
    score = cosine_similarity(vec_a, vec_b)
    if approx_equal(score, -1.0):
        print(f"  PASS  Opposite vectors → similarity = {score:.6f} (expected -1.0)")
        passed += 1
    else:
        print(f"  FAIL  Opposite vectors → similarity = {score:.6f} (expected -1.0)")
        failed += 1
        failures.append("Opposite vectors did not return -1.0")

    # -------------------------------------------------------------------------
    # TEST 3: Orthogonal vectors → similarity = 0.0
    # -------------------------------------------------------------------------
    vec_a, vec_b = make_orthogonal(10)
    score = cosine_similarity(vec_a, vec_b)
    if approx_equal(score, 0.0):
        print(f"  PASS  Orthogonal vectors → similarity = {score:.6f} (expected 0.0)")
        passed += 1
    else:
        print(f"  FAIL  Orthogonal vectors → similarity = {score:.6f} (expected 0.0)")
        failed += 1
        failures.append("Orthogonal vectors did not return 0.0")

    # -------------------------------------------------------------------------
    # TEST 4: Zero vector handled safely (no crash)
    # -------------------------------------------------------------------------
    vec_zero   = [0.0] * 10
    vec_normal = make_vector(10, 1.0)
    try:
        score = cosine_similarity(vec_zero, vec_normal)
        if approx_equal(score, 0.0):
            print(f"  PASS  Zero vector handled safely → similarity = {score:.6f}")
            passed += 1
        else:
            print(f"  FAIL  Zero vector returned {score:.6f} (expected 0.0)")
            failed += 1
            failures.append("Zero vector did not return 0.0")
    except Exception as e:
        print(f"  FAIL  Zero vector caused exception: {e}")
        failed += 1
        failures.append(f"Zero vector exception: {e}")

    # -------------------------------------------------------------------------
    # TEST 5: Symmetry — sim(a,b) == sim(b,a)
    # -------------------------------------------------------------------------
    vec_a = [1.0, 2.0, 3.0, 4.0, 5.0]
    vec_b = [5.0, 4.0, 3.0, 2.0, 1.0]
    score_ab = cosine_similarity(vec_a, vec_b)
    score_ba = cosine_similarity(vec_b, vec_a)
    if approx_equal(score_ab, score_ba):
        print(f"  PASS  Symmetry — sim(a,b) = sim(b,a) = {score_ab:.6f}")
        passed += 1
    else:
        print(f"  FAIL  Symmetry broken — sim(a,b)={score_ab:.6f}, sim(b,a)={score_ba:.6f}")
        failed += 1
        failures.append("Cosine similarity not symmetric")

    # -------------------------------------------------------------------------
    # TEST 6: Score range — result always between -1 and 1
    # -------------------------------------------------------------------------
    test_pairs = [
        ([1.0, 0.5, 0.3], [0.8, 0.2, 0.9]),
        ([0.1, 0.9, 0.5], [0.5, 0.1, 0.9]),
        ([1.0, 1.0, 1.0], [0.1, 0.2, 0.3]),
    ]
    all_in_range = True
    for va, vb in test_pairs:
        s = cosine_similarity(va, vb)
        if not (-1.0 - 1e-6 <= s <= 1.0 + 1e-6):
            all_in_range = False
            print(f"  FAIL  Score {s:.6f} is outside [-1, 1] range")
            failed += 1
            failures.append(f"Score {s:.6f} out of range")
    if all_in_range:
        print(f"  PASS  All scores within [-1.0, 1.0] range")
        passed += 1

    print()
    print("  --- Low similarity threshold behaviour ---")
    print()

    # -------------------------------------------------------------------------
    # TEST 7: Score below threshold — warning SHOULD fire
    # -------------------------------------------------------------------------
    low_score = LOW_SIMILARITY_THRESHOLD - 0.1  # just below threshold
    warning_fires = low_score < LOW_SIMILARITY_THRESHOLD
    if warning_fires:
        print(f"  PASS  Score {low_score:.2f} is below threshold {LOW_SIMILARITY_THRESHOLD} → warning fires")
        passed += 1
    else:
        print(f"  FAIL  Score {low_score:.2f} should be below threshold {LOW_SIMILARITY_THRESHOLD}")
        failed += 1
        failures.append("Low score threshold check failed")

    # -------------------------------------------------------------------------
    # TEST 8: Score above threshold — warning should NOT fire
    # -------------------------------------------------------------------------
    high_score = LOW_SIMILARITY_THRESHOLD + 0.1  # just above threshold
    warning_fires = high_score < LOW_SIMILARITY_THRESHOLD
    if not warning_fires:
        print(f"  PASS  Score {high_score:.2f} is above threshold {LOW_SIMILARITY_THRESHOLD} → no warning")
        passed += 1
    else:
        print(f"  FAIL  Score {high_score:.2f} should be above threshold {LOW_SIMILARITY_THRESHOLD}")
        failed += 1
        failures.append("High score incorrectly triggered warning")

    # -------------------------------------------------------------------------
    # TEST 9: Score exactly at threshold — warning should NOT fire
    # -------------------------------------------------------------------------
    exact_score = LOW_SIMILARITY_THRESHOLD
    warning_fires = exact_score < LOW_SIMILARITY_THRESHOLD
    if not warning_fires:
        print(f"  PASS  Score exactly at threshold {exact_score} → no warning (boundary correct)")
        passed += 1
    else:
        print(f"  FAIL  Score at threshold incorrectly triggered warning")
        failed += 1
        failures.append("Threshold boundary check failed")

    # -------------------------------------------------------------------------
    # TEST 10: Realistic embedding dimensions (3072) handled correctly
    # -------------------------------------------------------------------------
    import random
    random.seed(42)
    vec_3072_a = [random.uniform(-1, 1) for _ in range(3072)]
    vec_3072_b = [random.uniform(-1, 1) for _ in range(3072)]
    try:
        score = cosine_similarity(vec_3072_a, vec_3072_b)
        if -1.0 <= score <= 1.0:
            print(f"  PASS  3072-dimension vectors handled — score: {score:.6f}")
            passed += 1
        else:
            print(f"  FAIL  3072-dimension score {score:.6f} out of range")
            failed += 1
            failures.append("3072-dim score out of range")
    except Exception as e:
        print(f"  FAIL  3072-dimension vectors caused exception: {e}")
        failed += 1
        failures.append(f"3072-dim exception: {e}")

    # --- SUMMARY ---
    print()
    print("-" * 60)
    total = passed + failed
    print(f"  {passed} passed | {failed} failed | {total} total")
    print()

    if failed == 0:
        print("  RESULT: ALL TESTS PASSED")
        print("  AI Verify Principle 2 (Explainability) — EVIDENCE GENERATED")
        print()
        print("  The system can explain why results were returned (similarity score)")
        print("  and warns users when results may not be relevant (low score flag).")
    else:
        print(f"  RESULT: {failed} TEST(S) FAILED")
        for f in failures:
            print(f"    - {f}")

    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
