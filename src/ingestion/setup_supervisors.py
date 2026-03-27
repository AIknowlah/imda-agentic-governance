# =============================================================================
# setup_supervisors.py  — v1.1
# Phase 3 Enhancement: HITL Two-Person Governance Setup
#
# WHAT THIS FILE DOES:
#   1. Creates the 'supervisors' table in BigQuery
#   2. Creates the 'managers' table in BigQuery
#   3. Seeds both tables with test data for v1.1 development
#
# RUN ORDER:
#   1. python processor.py          (loads employee data)
#   2. python setup_supervisors.py  (creates supervisor/manager tables)
#   3. python main.py               (runs the agent)
#
# GOVERNANCE NOTES:
#   - PINs are stored as SHA-256 hashes — never plain text
#   - This satisfies AI Verify Principle 5 (Security)
#   - Supervisor identity verification satisfies Principle 10 (Human Agency)
#
# TEST DATA (from Session Report 12 Mar 2026):
#   SUP001 — Alice Tan    — HR_Admin, Medical_Lead  — PIN: 1234
#   SUP002 — Bob Lim      — Finance_Lead            — PIN: 5678
#   SUP003 — Carol Wong   — All roles               — PIN: 9999
#   MGR001 — David Chen   — Manager (receives escalation emails)
# =============================================================================


# --- IMPORTS ---

import os
import hashlib
from dotenv import load_dotenv
from google.cloud import bigquery


# =============================================================================
# CONFIGURATION — must match processor.py and main.py exactly
# =============================================================================

load_dotenv()

PROJECT_ID  = "secure-rag-sg"
REGION      = "asia-southeast1"
DATASET_ID  = "secure_rag"

SUPERVISOR_TABLE = "supervisors"
MANAGER_TABLE    = "managers"

MANAGER_EMAIL = os.getenv("MANAGER_EMAIL", "")
# Loaded from .env — the Gmail address that receives escalation emails.


# =============================================================================
# HELPER: HASH A PIN
# =============================================================================

def hash_pin(plain_pin: str) -> str:
    """
    Converts a plain text PIN into a SHA-256 hash.
    The hash is what gets stored in BigQuery — never the plain PIN.

    Example:
        hash_pin("1234") → "03ac674216f3e15c761ee1a5e255f067..."

    WHY SHA-256?
        One-way function — you cannot reverse a hash back to the PIN.
        When a supervisor enters their PIN, we hash what they typed
        and compare it to the stored hash. If they match — correct PIN.
        If not — wrong PIN. The actual PIN never touches the database.

    This satisfies AI Verify Principle 5 (Security) — protecting
    credentials at rest.
    """
    return hashlib.sha256(plain_pin.encode()).hexdigest()


# =============================================================================
# STEP 1: CONNECT TO BIGQUERY
# =============================================================================

def init_bigquery():
    """Connects to BigQuery and returns the client."""

    print("[INIT] Connecting to BigQuery...")

    try:
        bq_client = bigquery.Client(project=PROJECT_ID)
        print(f"[INIT] Connected to BigQuery: {PROJECT_ID}.{DATASET_ID} ({REGION})\n")
        return bq_client
    except Exception as e:
        print(f"[INIT] FATAL — Could not connect to BigQuery: {e}")
        raise SystemExit(1)


# =============================================================================
# STEP 2: CREATE SUPERVISORS TABLE
# =============================================================================

def create_supervisors_table(bq_client):
    """
    Creates the supervisors table in BigQuery.
    Safe to run multiple times — exists_ok=True prevents overwriting.

    SCHEMA:
        supervisor_id    — Unique ID (e.g. SUP001)
        name             — Full name
        email            — Email address
        hashed_pin       — SHA-256 hash of their PIN (never plain text)
        can_approve_roles — JSON list of roles this supervisor can approve
                           e.g. '["HR_Admin", "Medical_Lead"]'
        is_locked        — True if account is locked after 3 failed attempts
        failed_attempts  — Count of consecutive wrong PINs this session
        locked_by_session — The request_id that triggered the lockout
    """

    print("[SETUP] Creating supervisors table...")

    schema = [
        bigquery.SchemaField("supervisor_id",     "STRING",  mode="REQUIRED"),
        bigquery.SchemaField("name",              "STRING",  mode="NULLABLE"),
        bigquery.SchemaField("email",             "STRING",  mode="NULLABLE"),
        bigquery.SchemaField("hashed_pin",        "STRING",  mode="NULLABLE"),
        # SHA-256 hash only — plain PIN is never stored.

        bigquery.SchemaField("can_approve_roles", "STRING",  mode="NULLABLE"),
        # Stored as a JSON string: '["HR_Admin", "Medical_Lead"]'
        # Parsed at runtime to check if supervisor can approve a given role.

        bigquery.SchemaField("is_locked",         "BOOLEAN", mode="NULLABLE"),
        # True = account locked, no further PIN attempts allowed.

        bigquery.SchemaField("failed_attempts",   "INTEGER", mode="NULLABLE"),
        # Incremented on each wrong PIN. Reset to 0 on correct PIN.
        # Locked when this reaches 3.

        bigquery.SchemaField("locked_by_session", "STRING",  mode="NULLABLE"),
        # The request_id of the session that triggered the lockout.
        # Logged for audit trail — links lockout to a specific query.
    ]

    try:
        table_ref = bigquery.Table(
            f"{PROJECT_ID}.{DATASET_ID}.{SUPERVISOR_TABLE}",
            schema=schema
        )
        bq_client.create_table(table_ref, exists_ok=True)
        print(f"[SETUP] Table '{SUPERVISOR_TABLE}' ready.\n")
    except Exception as e:
        print(f"[SETUP] ERROR — Could not create supervisors table: {e}")
        raise


# =============================================================================
# STEP 3: CREATE MANAGERS TABLE
# =============================================================================

def create_managers_table(bq_client):
    """
    Creates the managers table in BigQuery.
    Managers receive escalation emails when a supervisor is locked out.
    They do not approve queries — they only unlock supervisors.

    SCHEMA:
        manager_id             — Unique ID (e.g. MGR001)
        name                   — Full name
        email                  — Gmail address for escalation emails
        can_unlock_supervisors — True = authorised to unlock accounts
    """

    print("[SETUP] Creating managers table...")

    schema = [
        bigquery.SchemaField("manager_id",             "STRING",  mode="REQUIRED"),
        bigquery.SchemaField("name",                   "STRING",  mode="NULLABLE"),
        bigquery.SchemaField("email",                  "STRING",  mode="NULLABLE"),
        # This email receives the escalation alert when a lockout occurs.

        bigquery.SchemaField("can_unlock_supervisors", "BOOLEAN", mode="NULLABLE"),
        # Governance flag — only True managers can unlock accounts.
    ]

    try:
        table_ref = bigquery.Table(
            f"{PROJECT_ID}.{DATASET_ID}.{MANAGER_TABLE}",
            schema=schema
        )
        bq_client.create_table(table_ref, exists_ok=True)
        print(f"[SETUP] Table '{MANAGER_TABLE}' ready.\n")
    except Exception as e:
        print(f"[SETUP] ERROR — Could not create managers table: {e}")
        raise


# =============================================================================
# STEP 4: SEED TEST DATA
# =============================================================================

def seed_supervisors(bq_client):
    """
    Seeds the supervisors table with test data.
    Clears existing data first to avoid duplicates on re-run.

    TEST SUPERVISORS (from Session Report 12 Mar 2026):
        SUP001 — Alice Tan    — HR_Admin, Medical_Lead  — PIN: 1234
        SUP002 — Bob Lim      — Finance_Lead            — PIN: 5678
        SUP003 — Carol Wong   — All roles               — PIN: 9999
    """

    print("[SEED] Clearing and seeding supervisors table...")

    # Clear existing data
    try:
        bq_client.query(
            f"DELETE FROM `{PROJECT_ID}.{DATASET_ID}.{SUPERVISOR_TABLE}` WHERE TRUE"
        ).result()
    except Exception as e:
        print(f"[SEED] Warning — could not clear supervisors table: {e}")

    import json

    supervisors = [
        {
            "supervisor_id":     "SUP001",
            "name":              "Alice Tan",
            "email":             "alice.tan@example.com",
            "hashed_pin":        hash_pin("1234"),
            "can_approve_roles": json.dumps(["HR_Admin", "Medical_Lead"]),
            "is_locked":         False,
            "failed_attempts":   0,
            "locked_by_session": None,
        },
        {
            "supervisor_id":     "SUP002",
            "name":              "Bob Lim",
            "email":             "bob.lim@example.com",
            "hashed_pin":        hash_pin("5678"),
            "can_approve_roles": json.dumps(["Finance_Lead"]),
            "is_locked":         False,
            "failed_attempts":   0,
            "locked_by_session": None,
        },
        {
            "supervisor_id":     "SUP003",
            "name":              "Carol Wong",
            "email":             "carol.wong@example.com",
            "hashed_pin":        hash_pin("9999"),
            "can_approve_roles": json.dumps(["HR_Admin", "Medical_Lead", "Finance_Lead", "General_Staff"]),
            "is_locked":         False,
            "failed_attempts":   0,
            "locked_by_session": None,
        },
    ]

    try:
        errors = bq_client.insert_rows_json(
            f"{PROJECT_ID}.{DATASET_ID}.{SUPERVISOR_TABLE}",
            supervisors
        )
        if errors:
            print(f"[SEED] ERROR — Supervisor insert errors: {errors}")
        else:
            print(f"[SEED] {len(supervisors)} supervisors seeded successfully.")
    except Exception as e:
        print(f"[SEED] ERROR — Could not seed supervisors: {e}")


def seed_managers(bq_client):
    """
    Seeds the managers table with test data.

    TEST MANAGER (from Session Report 12 Mar 2026):
        MGR001 — David Chen — receives escalation emails
    """

    print("[SEED] Clearing and seeding managers table...")

    # Clear existing data
    try:
        bq_client.query(
            f"DELETE FROM `{PROJECT_ID}.{DATASET_ID}.{MANAGER_TABLE}` WHERE TRUE"
        ).result()
    except Exception as e:
        print(f"[SEED] Warning — could not clear managers table: {e}")

    # Use MANAGER_EMAIL from .env for David Chen's email
    # This ensures escalation emails actually arrive at your inbox during testing.
    manager_email = MANAGER_EMAIL if MANAGER_EMAIL else "manager@example.com"

    managers = [
        {
            "manager_id":             "MGR001",
            "name":                   "David Chen",
            "email":                  manager_email,
            "can_unlock_supervisors": True,
        },
    ]

    try:
        errors = bq_client.insert_rows_json(
            f"{PROJECT_ID}.{DATASET_ID}.{MANAGER_TABLE}",
            managers
        )
        if errors:
            print(f"[SEED] ERROR — Manager insert errors: {errors}")
        else:
            print(f"[SEED] {len(managers)} manager seeded successfully.")
            print(f"[SEED] Escalation emails will be sent to: {manager_email}")
    except Exception as e:
        print(f"[SEED] ERROR — Could not seed managers: {e}")


# =============================================================================
# STEP 5: VERIFY — PRINT WHAT WAS CREATED
# =============================================================================

def verify_setup(bq_client):
    """
    Reads back the seeded data from BigQuery and prints it.
    Confirms everything was created correctly before we build hitl_gate.py.
    """

    print("\n[VERIFY] Reading back seeded data from BigQuery...")

    print("\n  SUPERVISORS:")
    print(f"  {'ID':<10} {'Name':<15} {'Can Approve':<40} {'Locked'}")
    print(f"  {'-'*80}")

    try:
        import json
        rows = list(bq_client.query(
            f"SELECT supervisor_id, name, can_approve_roles, is_locked "
            f"FROM `{PROJECT_ID}.{DATASET_ID}.{SUPERVISOR_TABLE}` "
            f"ORDER BY supervisor_id"
        ).result())

        for row in rows:
            roles = json.loads(row.can_approve_roles)
            print(f"  {row.supervisor_id:<10} {row.name:<15} {str(roles):<40} {row.is_locked}")

    except Exception as e:
        print(f"  [VERIFY] Could not read supervisors: {e}")

    print("\n  MANAGERS:")
    print(f"  {'ID':<10} {'Name':<15} {'Email':<35} {'Can Unlock'}")
    print(f"  {'-'*80}")

    try:
        rows = list(bq_client.query(
            f"SELECT manager_id, name, email, can_unlock_supervisors "
            f"FROM `{PROJECT_ID}.{DATASET_ID}.{MANAGER_TABLE}` "
            f"ORDER BY manager_id"
        ).result())

        for row in rows:
            print(f"  {row.manager_id:<10} {row.name:<15} {row.email:<35} {row.can_unlock_supervisors}")

    except Exception as e:
        print(f"  [VERIFY] Could not read managers: {e}")

    print()


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":

    print("=" * 60)
    print("  AGENTIC ETL — SETUP SUPERVISORS v1.1")
    print("  BigQuery Supervisor & Manager Table Setup")
    print("  IMDA 2026 Aligned | PDPA Singapore")
    print("=" * 60)
    print()

    bq_client = init_bigquery()

    create_supervisors_table(bq_client)
    create_managers_table(bq_client)

    seed_supervisors(bq_client)
    seed_managers(bq_client)

    verify_setup(bq_client)

    print("=" * 60)
    print("  SETUP COMPLETE")
    print("  Next step: build src/hitl/hitl_gate.py")
    print("=" * 60)
