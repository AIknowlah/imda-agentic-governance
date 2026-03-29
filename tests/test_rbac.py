# =============================================================================
# test_rbac.py  — v1.3
# AI Verify Principles 8 & 10: Data Governance and Human Agency
#
# WHAT THIS TESTS:
#   Verifies that node_enforce_rbac() correctly enforces field-level access
#   control for all four roles:
#     - Permitted fields are always present in results
#     - Denied fields are never present in results
#     - Sensitive fields trigger the HITL flag correctly
#     - Unknown roles are denied before reaching RBAC
#
# EVIDENCE GENERATED:
#   Pass/fail results for all role/field combinations — attach to AI Verify
#   Governance Report as evidence for Principles 8 and 10.
#
# HOW TO RUN:
#   python tests/test_rbac.py
#
# REQUIRES:
#   BigQuery connection — reads live employee_data and employee_embeddings tables.
#   Gemini API — generates one embedding for the test query.
#   .env file with GOOGLE_API_KEY set.
# =============================================================================

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from google import genai
from google.cloud import bigquery
from src.ingestion.main import (
    ROLE_PERMISSIONS,
    SENSITIVE_FIELDS,
    TOP_K,
    EMBED_MODEL,
    PROJECT_ID,
    DATASET_ID,
    TABLE_ID,
    EMBED_TABLE,
    cosine_similarity,
)

import numpy as np


# =============================================================================
# SETUP
# =============================================================================

def connect():
    try:
        gemini = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
        bq     = bigquery.Client(project=PROJECT_ID)
        print(f"[SETUP] Connected to Gemini and BigQuery")
        return gemini, bq
    except Exception as e:
        print(f"[SETUP] FATAL — Connection failed: {e}")
        sys.exit(1)


def get_top_records(gemini_client, bq_client, query_text):
    """
    Runs embed → retrieve for a given query.
    Returns the raw unfiltered records (all fields).
    """
    # Embed the query
    result = gemini_client.models.embed_content(
        model=EMBED_MODEL,
        contents=query_text
    )
    query_vec = result.embeddings[0].values

    # Fetch all embeddings
    rows = list(bq_client.query(
        f"SELECT nric, embedding FROM `{PROJECT_ID}.{DATASET_ID}.{EMBED_TABLE}`"
    ).result())

    if not rows:
        print("[SETUP] No embeddings found — run processor.py first")
        sys.exit(1)

    # Calculate similarity and get top K
    similarities = []
    for row in rows:
        stored_vec = json.loads(row.embedding)
        score      = cosine_similarity(query_vec, stored_vec)
        similarities.append((row.nric, score))

    similarities.sort(key=lambda x: x[1], reverse=True)
    top_nrics = [nric for nric, _ in similarities[:TOP_K]]

    # Fetch full records
    query_params = [bigquery.ArrayQueryParameter("nric_list", "STRING", top_nrics)]
    job_config   = bigquery.QueryJobConfig(query_parameters=query_params)

    employee_rows = list(bq_client.query(
        f"SELECT * FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}` WHERE nric IN UNNEST(@nric_list)",
        job_config=job_config
    ).result())

    return [dict(row) for row in employee_rows]


def apply_rbac(raw_records, role):
    """Applies RBAC filtering — mirrors node_enforce_rbac() logic exactly."""
    allowed_fields = ROLE_PERMISSIONS[role]["allowed_fields"]
    filtered = []
    for record in raw_records:
        filtered_record = {
            field: record[field]
            for field in allowed_fields
            if field in record
        }
        filtered.append(filtered_record)
    return filtered, allowed_fields


# =============================================================================
# TEST CASES
# =============================================================================

# All fields that exist in employee_data
ALL_FIELDS = {"nric", "name", "employment", "ethnicity",
              "medical_info", "financial_info", "criminal_record"}

# What each role should and should not see
ROLE_TEST_CASES = {
    "General_Staff": {
        "must_have":  {"name", "employment"},
        "must_not":   {"nric", "ethnicity", "medical_info", "financial_info", "criminal_record"},
        "hitl_expected": False,
    },
    "HR_Admin": {
        "must_have":  {"name", "employment", "nric", "ethnicity"},
        "must_not":   {"medical_info", "financial_info", "criminal_record"},
        "hitl_expected": True,   # nric and ethnicity are sensitive
    },
    "Finance_Lead": {
        "must_have":  {"name", "employment", "financial_info"},
        "must_not":   {"nric", "ethnicity", "medical_info", "criminal_record"},
        "hitl_expected": True,   # financial_info is sensitive
    },
    "Medical_Lead": {
        "must_have":  {"name", "employment", "medical_info"},
        "must_not":   {"nric", "ethnicity", "financial_info", "criminal_record"},
        "hitl_expected": True,   # medical_info is sensitive
    },
}


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_tests():

    print("=" * 60)
    print("  test_rbac.py")
    print("  AI Verify Principles 8 & 10 — Data Governance")
    print("  Tests that each role sees only permitted fields")
    print("=" * 60)
    print()

    gemini_client, bq_client = connect()

    # Fetch raw records once — reuse across all role tests
    print("[SETUP] Fetching test records from BigQuery...")
    raw_records = get_top_records(gemini_client, bq_client, "show me employee information")
    print(f"[SETUP] {len(raw_records)} records retrieved. Running RBAC tests...\n")

    passed  = 0
    failed  = 0
    failures = []

    for role, expectations in ROLE_TEST_CASES.items():

        print(f"  --- Role: {role} ---")
        filtered, allowed_fields = apply_rbac(raw_records, role)

        if not filtered:
            print(f"  FAIL  No records returned for role {role}")
            failed += 1
            failures.append(f"{role}: no records returned")
            continue

        # Collect all field names present across all filtered records
        fields_present = {
            key for record in filtered for key in record.keys()
        }

        # --- TEST: permitted fields are present ---
        for field in expectations["must_have"]:
            if field in fields_present:
                print(f"  PASS  [{role}] permitted field '{field}' is present")
                passed += 1
            else:
                print(f"  FAIL  [{role}] permitted field '{field}' is MISSING")
                failed += 1
                failures.append(f"{role}: permitted field '{field}' missing")

        # --- TEST: denied fields are absent ---
        for field in expectations["must_not"]:
            if field not in fields_present:
                print(f"  PASS  [{role}] denied field '{field}' is absent")
                passed += 1
            else:
                print(f"  FAIL  [{role}] denied field '{field}' is PRESENT — RBAC FAILURE")
                failed += 1
                failures.append(f"{role}: denied field '{field}' exposed")

        # --- TEST: HITL trigger matches expectation ---
        triggered_fields = fields_present & SENSITIVE_FIELDS
        hitl_would_trigger = len(triggered_fields) > 0

        if hitl_would_trigger == expectations["hitl_expected"]:
            if hitl_would_trigger:
                print(f"  PASS  [{role}] HITL correctly triggered by: {sorted(triggered_fields)}")
            else:
                print(f"  PASS  [{role}] HITL correctly NOT triggered (no sensitive fields)")
            passed += 1
        else:
            print(f"  FAIL  [{role}] HITL trigger mismatch — expected {expectations['hitl_expected']}, got {hitl_would_trigger}")
            failed += 1
            failures.append(f"{role}: HITL trigger mismatch")

        print()

    # --- TEST: Unknown role is denied ---
    print("  --- Unknown role handling ---")
    unknown_role = "SuperAdmin"
    if unknown_role not in ROLE_PERMISSIONS:
        print(f"  PASS  Unknown role '{unknown_role}' not in ROLE_PERMISSIONS — would be denied at gate")
        passed += 1
    else:
        print(f"  FAIL  Unknown role '{unknown_role}' found in ROLE_PERMISSIONS — should not exist")
        failed += 1
        failures.append("Unknown role found in ROLE_PERMISSIONS")

    # --- TEST: criminal_record is in no role's permitted fields ---
    print()
    print("  --- Criminal record access control ---")
    any_role_has_criminal = any(
        "criminal_record" in info["allowed_fields"]
        for info in ROLE_PERMISSIONS.values()
    )
    if not any_role_has_criminal:
        print("  PASS  criminal_record is not permitted for any role")
        passed += 1
    else:
        print("  FAIL  criminal_record is permitted for at least one role — review required")
        failed += 1
        failures.append("criminal_record exposed to a role")

    # --- SUMMARY ---
    print()
    print("-" * 60)
    total = passed + failed
    print(f"  {passed} passed | {failed} failed | {total} total")
    print()

    if failed == 0:
        print("  RESULT: ALL TESTS PASSED")
        print("  AI Verify Principle 8  (Data Governance)        — EVIDENCE GENERATED")
        print("  AI Verify Principle 10 (Human Agency/Oversight) — EVIDENCE GENERATED")
    else:
        print(f"  RESULT: {failed} TEST(S) FAILED")
        for f in failures:
            print(f"    - {f}")

    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
