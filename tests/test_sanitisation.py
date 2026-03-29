# =============================================================================
# test_sanitisation.py  — v1.3
# AI Verify Principle 6: Robustness
#
# WHAT THIS TESTS:
#   Verifies that the sanitise_query() function in input_guard.py correctly
#   handles malformed, empty, oversized, and symbol-only inputs.
#
# EVIDENCE GENERATED:
#   Pass/fail results for each sanitisation case — attach to AI Verify
#   Governance Report as evidence for Principle 6 (Robustness).
#
# HOW TO RUN:
#   python tests/test_sanitisation.py
#
# DOES NOT REQUIRE:
#   BigQuery, Gemini API, or .env file — pure function test.
# =============================================================================

import sys
import os

# Add project root to path so src.security.input_guard resolves correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.security.input_guard import sanitise_query, MAX_QUERY_LENGTH, MIN_QUERY_LENGTH

# =============================================================================
# TEST CASES
# Each tuple: (test_name, input_query, expect_valid, expect_fragment_in_reason)
# expect_valid = True means we expect the query to PASS sanitisation
# expect_valid = False means we expect it to be REJECTED
# =============================================================================

TEST_CASES = [

    # --- SHOULD BE REJECTED ---
    (
        "Empty string",
        "",
        False,
        "too short"
    ),
    (
        "Single space",
        " ",
        False,
        "too short"
    ),
    (
        "Single character",
        "a",
        False,
        "too short"
    ),
    (
        "Symbols only — exclamation marks",
        "!!!???###",
        False,
        "only symbols"
    ),
    (
        "Symbols only — dashes and dots",
        "---...---",
        False,
        "only symbols"
    ),
    (
        "Query exceeds maximum length",
        "a" * (MAX_QUERY_LENGTH + 1),
        False,
        "maximum length"
    ),
    (
        "Control characters embedded",
        "show me\x00employees\x01data",
        True,
        # Control chars are stripped but remaining text is valid
        ""
    ),
    (
        "Newlines and tabs normalised",
        "show me\n\nemployee\t\tdata",
        True,
        ""
    ),

    # --- SHOULD PASS ---
    (
        "Normal query — General_Staff",
        "show me staff information",
        True,
        ""
    ),
    (
        "Normal query — HR_Admin",
        "show me employee NRIC details",
        True,
        ""
    ),
    (
        "Normal query — Finance_Lead",
        "show me financial records for engineering team",
        True,
        ""
    ),
    (
        "Normal query — Medical_Lead",
        "show me medical records for operations staff",
        True,
        ""
    ),
    (
        "Query at exactly maximum length",
        "a" * MAX_QUERY_LENGTH,
        True,
        ""
    ),
    (
        "Query at exactly minimum length",
        "ab",
        True,
        ""
    ),
    (
        "Query with numbers",
        "show me employee S1234567A",
        True,
        ""
    ),
    (
        "Query with mixed case",
        "Show Me Employee Information For HR Department",
        True,
        ""
    ),
]


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_tests():

    print("=" * 60)
    print("  test_sanitisation.py")
    print("  AI Verify Principle 6 — Robustness")
    print("  Tests that malformed inputs are handled cleanly")
    print("=" * 60)
    print()

    passed = 0
    failed = 0
    failures = []

    for test_name, input_query, expect_valid, expect_fragment in TEST_CASES:

        is_valid, clean_query, reason = sanitise_query(input_query)

        # Check outcome matches expectation
        outcome_correct = (is_valid == expect_valid)

        # If rejected, check the reason contains the expected fragment
        reason_correct = True
        if not expect_valid and expect_fragment:
            reason_correct = expect_fragment.lower() in reason.lower()

        if outcome_correct and reason_correct:
            print(f"  PASS  {test_name}")
            passed += 1
        else:
            print(f"  FAIL  {test_name}")
            if not outcome_correct:
                print(f"        Expected valid={expect_valid}, got valid={is_valid}")
            if not reason_correct:
                print(f"        Expected reason to contain '{expect_fragment}'")
                print(f"        Actual reason: '{reason}'")
            failed += 1
            failures.append(test_name)

    # --- ADDITIONAL CHECK: control chars are actually stripped ---
    print()
    print("  --- Additional verification ---")
    _, clean, _ = sanitise_query("show\x00me\x01employees")
    if "\x00" not in clean and "\x01" not in clean:
        print("  PASS  Control characters stripped from output")
        passed += 1
    else:
        print("  FAIL  Control characters NOT stripped from output")
        failed += 1

    _, clean, _ = sanitise_query("show  me   employees")
    if "  " not in clean:
        print("  PASS  Multiple spaces collapsed to single space")
        passed += 1
    else:
        print("  FAIL  Multiple spaces NOT collapsed")
        failed += 1

    # --- SUMMARY ---
    print()
    print("-" * 60)
    total = passed + failed
    print(f"  {passed} passed | {failed} failed | {total} total")
    print()

    if failed == 0:
        print("  RESULT: ALL TESTS PASSED")
        print("  AI Verify Principle 6 (Robustness) — EVIDENCE GENERATED")
    else:
        print(f"  RESULT: {failed} TEST(S) FAILED")
        print("  Failed tests:")
        for f in failures:
            print(f"    - {f}")

    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
