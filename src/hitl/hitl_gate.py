# =============================================================================
# hitl_gate.py  — v1.1
# Human-in-the-Loop Gate: Two-Person Governance Mechanism
#
# WHAT THIS FILE DOES:
#   Implements the full v1.1 HITL redesign with 5 governance rules:
#
#   Rule 1: Two-Person Rule
#       The requester cannot approve their own sensitive data release.
#       Enforced by checking requester_role against supervisor's approved roles.
#
#   Rule 2: Supervisor PIN Verification
#       Approver must authenticate with a PIN stored as SHA-256 hash in BigQuery.
#       Proves identity — not just that someone typed "approve" at the keyboard.
#
#   Rule 3: Three-Strike Lockout
#       3 wrong PINs locks the supervisor account in BigQuery.
#       No further attempts permitted in this session.
#
#   Rule 4: Gmail Escalation to Manager
#       Lockout triggers automatic escalation email to manager via Gmail API.
#       Email contains full context: request_id, who was locked, why, query details.
#
#   Rule 5: Full Audit Trail
#       Every approval, rejection, failed attempt, lockout, and escalation
#       logged in BigQuery audit_log linked to request_id.
#
# GOVERNANCE ALIGNMENT:
#   AI Verify Principle 9  — Accountability (PIN identity verification)
#   AI Verify Principle 10 — Human Agency (two-person rule, lockout)
#   IMDA 2026              — Meaningful Human Control
#
# CALLED BY:
#   main.py → node_human_review()
# =============================================================================


# --- IMPORTS ---

import os
import json
import hashlib
import base64
import datetime
from email.mime.text import MIMEText
from dotenv import load_dotenv
from google.cloud import bigquery
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# =============================================================================
# CONFIGURATION
# =============================================================================

load_dotenv()

PROJECT_ID       = "secure-rag-sg"
DATASET_ID       = "secure_rag"
SUPERVISOR_TABLE = "supervisors"
MANAGER_TABLE    = "managers"
AUDIT_TABLE      = "audit_log"

MANAGER_EMAIL    = os.getenv("MANAGER_EMAIL", "")
ESCALATION_FROM  = os.getenv("ESCALATION_FROM", "")

MAX_FAILED_ATTEMPTS = 3
# Three-strike rule — lockout after 3 wrong PINs.

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
# Least-privilege — send only, no inbox access.

CREDENTIALS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "credentials.json"
)
TOKEN_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "token.json"
)
# Both files live at the project root — never inside src/.


# =============================================================================
# HELPER: HASH A PIN
# =============================================================================

def hash_pin(plain_pin: str) -> str:
    """SHA-256 hash of a PIN — matches setup_supervisors.py."""
    return hashlib.sha256(plain_pin.encode()).hexdigest()


# =============================================================================
# SECTION 1: BIGQUERY HELPERS
# =============================================================================

def get_supervisor(bq_client, supervisor_id: str) -> dict | None:
    """
    Fetches a supervisor record from BigQuery by ID.
    Returns a dict or None if not found.
    """
    try:
        rows = list(bq_client.query(
            f"SELECT * FROM `{PROJECT_ID}.{DATASET_ID}.{SUPERVISOR_TABLE}` "
            f"WHERE supervisor_id = @sup_id LIMIT 1",
            job_config=bigquery.QueryJobConfig(query_parameters=[
                bigquery.ScalarQueryParameter("sup_id", "STRING", supervisor_id)
            ])
        ).result())

        if not rows:
            return None
        return dict(rows[0])

    except Exception as e:
        print(f"[HITL] ERROR — Could not fetch supervisor {supervisor_id}: {e}")
        return None


def get_manager_email(bq_client) -> str:
    """
    Fetches the manager's email from BigQuery.
    Falls back to MANAGER_EMAIL from .env if query fails.
    """
    try:
        rows = list(bq_client.query(
            f"SELECT email FROM `{PROJECT_ID}.{DATASET_ID}.{MANAGER_TABLE}` "
            f"WHERE can_unlock_supervisors = TRUE LIMIT 1"
        ).result())

        if rows:
            return rows[0].email
    except Exception as e:
        print(f"[HITL] Warning — could not fetch manager email from BigQuery: {e}")

    return MANAGER_EMAIL


def increment_failed_attempts(bq_client, supervisor_id: str, request_id: str) -> int:
    """
    Increments failed_attempts for a supervisor.
    Locks the account if MAX_FAILED_ATTEMPTS is reached.
    Returns the new failed_attempts count.
    """
    supervisor = get_supervisor(bq_client, supervisor_id)
    if not supervisor:
        return MAX_FAILED_ATTEMPTS

    new_count = (supervisor.get("failed_attempts") or 0) + 1
    is_locked = new_count >= MAX_FAILED_ATTEMPTS

    try:
        bq_client.query(
            f"UPDATE `{PROJECT_ID}.{DATASET_ID}.{SUPERVISOR_TABLE}` "
            f"SET failed_attempts = @count, "
            f"    is_locked = @locked, "
            f"    locked_by_session = @session "
            f"WHERE supervisor_id = @sup_id",
            job_config=bigquery.QueryJobConfig(query_parameters=[
                bigquery.ScalarQueryParameter("count",   "INTEGER", new_count),
                bigquery.ScalarQueryParameter("locked",  "BOOL",    is_locked),
                bigquery.ScalarQueryParameter("session", "STRING",  request_id if is_locked else ""),
                bigquery.ScalarQueryParameter("sup_id",  "STRING",  supervisor_id),
            ])
        ).result()
    except Exception as e:
        print(f"[HITL] Warning — could not update failed attempts: {e}")

    return new_count


def reset_failed_attempts(bq_client, supervisor_id: str):
    """Resets failed_attempts to 0 after a successful PIN entry."""
    try:
        bq_client.query(
            f"UPDATE `{PROJECT_ID}.{DATASET_ID}.{SUPERVISOR_TABLE}` "
            f"SET failed_attempts = 0, is_locked = FALSE, locked_by_session = '' "
            f"WHERE supervisor_id = @sup_id",
            job_config=bigquery.QueryJobConfig(query_parameters=[
                bigquery.ScalarQueryParameter("sup_id", "STRING", supervisor_id),
            ])
        ).result()
    except Exception as e:
        print(f"[HITL] Warning — could not reset failed attempts: {e}")


# =============================================================================
# SECTION 2: GMAIL API
# =============================================================================

def get_gmail_service():
    """
    Authenticates with Gmail API using OAuth 2.0.
    First run: opens browser for consent.
    Subsequent runs: uses saved token.json.
    """
    creds = None

    # Load existing token if available
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, GMAIL_SCOPES)
        except Exception:
            creds = None

    # If no valid token, authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None

        if not creds:
            if not os.path.exists(CREDENTIALS_FILE):
                print(f"[GMAIL] ERROR — credentials.json not found at: {CREDENTIALS_FILE}")
                print("[GMAIL] Please download it from Google Cloud Console.")
                return None

            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, GMAIL_SCOPES)
            creds = flow.run_local_server(port=0)

        # Save token for future runs
        try:
            with open(TOKEN_FILE, "w") as token:
                token.write(creds.to_json())
        except Exception as e:
            print(f"[GMAIL] Warning — could not save token: {e}")

    try:
        return build("gmail", "v1", credentials=creds)
    except Exception as e:
        print(f"[GMAIL] ERROR — Could not build Gmail service: {e}")
        return None


def send_escalation_email(
    supervisor_id: str,
    supervisor_name: str,
    requester_role: str,
    query: str,
    request_id: str,
    failed_attempts: int,
    manager_email: str
):
    """
    Sends an escalation email to the manager when a supervisor is locked out.

    EMAIL CONTAINS:
        - request_id (for audit trail cross-reference)
        - Which supervisor was locked and why
        - Who made the original query
        - The query that triggered the HITL gate
        - Number of failed PIN attempts
        - Confirmation that the request was auto-rejected
    """

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = f"[ALERT] Supervisor Lockout — Request {request_id[:8]}..."

    body = f"""
AGENTIC ETL GATEKEEPER — SUPERVISOR LOCKOUT ALERT
==================================================

This is an automated security alert from the Agentic ETL Gatekeeper.
A supervisor account has been locked after {failed_attempts} failed PIN attempts.

REQUEST DETAILS
---------------
Request ID       : {request_id}
Timestamp        : {timestamp}
Requester Role   : {requester_role}
Query            : "{query}"

LOCKOUT DETAILS
---------------
Supervisor ID    : {supervisor_id}
Supervisor Name  : {supervisor_name}
Failed Attempts  : {failed_attempts} of {MAX_FAILED_ATTEMPTS}
Account Status   : LOCKED

OUTCOME
-------
This request has been AUTO-REJECTED.
No sensitive data was released.

ACTION REQUIRED
---------------
Please review this incident and unlock the supervisor account if appropriate.
Contact the supervisor directly to verify their identity before unlocking.

--
Agentic ETL Gatekeeper | IMDA 2026 AI Governance Framework
PDPA Singapore | secure-rag-sg
"""

    try:
        service = get_gmail_service()
        if not service:
            print("[GMAIL] Could not send escalation email — Gmail service unavailable.")
            return False

        message          = MIMEText(body)
        message["to"]    = manager_email
        message["from"]  = ESCALATION_FROM
        message["subject"] = subject

        raw     = base64.urlsafe_b64encode(message.as_bytes()).decode()
        service.users().messages().send(
            userId="me",
            body={"raw": raw}
        ).execute()

        print(f"[GMAIL] Escalation email sent to: {manager_email}")
        return True

    except Exception as e:
        print(f"[GMAIL] ERROR — Could not send escalation email: {e}")
        return False


# =============================================================================
# SECTION 3: MAIN HITL GATE FUNCTION
# =============================================================================

def run_hitl_gate(
    bq_client,
    request_id: str,
    requester_role: str,
    query: str,
    filtered_results: list,
    triggered_fields: set,
    audit_log: dict
) -> dict:
    """
    Main entry point for the v1.1 HITL gate.
    Called by node_human_review() in main.py.

    Returns updated audit_log with HITL decision recorded.

    FLOW:
        1. Display summary-only preview (no field values shown)
        2. Ask for supervisor ID
        3. Check supervisor exists and is not locked
        4. Check supervisor can approve this role (two-person rule)
        5. Ask for PIN — up to 3 attempts
        6. On success: approve and reset failed attempts
        7. On lockout: send escalation email and auto-reject
    """

    print("\n" + "!" * 60)
    print("  !! HUMAN REVIEW REQUIRED — SENSITIVE DATA DETECTED !!")
    print("!" * 60)
    print(f"\n  Request ID       : {request_id}")
    print(f"  Requester Role   : [{requester_role}]")
    print(f"  Query            : \"{query}\"")
    print(f"  Records pending  : {len(filtered_results)}")
    print(f"  Sensitive fields : {sorted(triggered_fields)}")

    # --- RULE 1 & 2: SUMMARY-ONLY PREVIEW ---
    # v1.1: Show record count and field names only — no actual values.
    # Prevents the requester from reading sensitive data through the HITL screen.
    print("\n  --- DATA SUMMARY (field names only — values hidden) ---")
    for i, record in enumerate(filtered_results, 1):
        visible_fields = [k for k in record.keys() if not k.startswith("_")]
        print(f"  Record {i}: fields present → {visible_fields}")
    print("  " + "-" * 40)

    print("\n  A supervisor must authenticate to approve this release.")
    print("  The requester cannot approve their own query (Two-Person Rule).\n")

    # --- GET SUPERVISOR ID ---
    supervisor_id = input("  Enter Supervisor ID (e.g. SUP001): ").strip().upper()

    if not supervisor_id:
        print("\n[HITL] No supervisor ID entered. Auto-rejecting.")
        audit_log["hitl_decision"] = "reject"
        audit_log["decision"]      = "DENIED — No supervisor ID entered"
        return audit_log

    # --- FETCH SUPERVISOR FROM BIGQUERY ---
    supervisor = get_supervisor(bq_client, supervisor_id)

    if not supervisor:
        print(f"\n[HITL] Supervisor '{supervisor_id}' not found. Auto-rejecting.")
        audit_log["hitl_decision"] = "reject"
        audit_log["decision"]      = f"DENIED — Supervisor {supervisor_id} not found"
        return audit_log

    supervisor_name = supervisor.get("name", "Unknown")

    # --- CHECK IF ACCOUNT IS LOCKED ---
    if supervisor.get("is_locked"):
        print(f"\n[HITL] Supervisor '{supervisor_name}' account is LOCKED.")
        print("[HITL] Contact your manager to unlock this account.")
        audit_log["hitl_decision"] = "reject"
        audit_log["decision"]      = f"DENIED — Supervisor {supervisor_id} account is locked"
        return audit_log

    # --- RULE 1: TWO-PERSON RULE ---
    # Check if supervisor is authorised to approve this requester's role.
    try:
        can_approve = json.loads(supervisor.get("can_approve_roles", "[]"))
    except Exception:
        can_approve = []

    if requester_role not in can_approve:
        print(f"\n[HITL] Supervisor '{supervisor_name}' is not authorised to approve role '{requester_role}'.")
        print(f"[HITL] This supervisor can approve: {can_approve}")
        audit_log["hitl_decision"] = "reject"
        audit_log["decision"]      = f"DENIED — Supervisor not authorised for role {requester_role}"
        return audit_log

    # --- RULE 2: PIN VERIFICATION (up to 3 attempts) ---
    print(f"\n  Supervisor: {supervisor_name} ({supervisor_id})")
    print(f"  Authorised to approve role: [{requester_role}] ✓")
    print(f"  Please enter your PIN to approve this release.")
    print(f"  ⚠ Account will lock after {MAX_FAILED_ATTEMPTS} failed attempts.\n")

    current_attempts = supervisor.get("failed_attempts") or 0
    manager_email    = get_manager_email(bq_client)

    for attempt in range(MAX_FAILED_ATTEMPTS - current_attempts):

        pin_input    = input(f"  PIN (attempt {attempt + 1} of {MAX_FAILED_ATTEMPTS - current_attempts}): ").strip()
        hashed_input = hash_pin(pin_input)

        if hashed_input == supervisor.get("hashed_pin"):
            # --- CORRECT PIN — APPROVE ---
            reset_failed_attempts(bq_client, supervisor_id)

            print(f"\n[HITL] PIN verified. Approved by {supervisor_name} ({supervisor_id}).")
            print("[HITL] Releasing results.\n")

            audit_log["hitl_decision"]    = "approve"
            audit_log["decision"]         = "APPROVED"
            audit_log["rbac_rule_applied"] = (
                audit_log.get("rbac_rule_applied", "") +
                f" | HITL approved by {supervisor_id}"
            )
            return audit_log

        else:
            # --- WRONG PIN ---
            new_count = increment_failed_attempts(bq_client, supervisor_id, request_id)
            remaining = MAX_FAILED_ATTEMPTS - new_count

            if remaining <= 0:
                # --- RULE 3: LOCKOUT ---
                print(f"\n[HITL] !! ACCOUNT LOCKED — {supervisor_name} ({supervisor_id}) !!")
                print(f"[HITL] {MAX_FAILED_ATTEMPTS} failed PIN attempts. No further attempts permitted.")
                print("[HITL] Auto-rejecting this request.")

                # --- RULE 4: GMAIL ESCALATION ---
                print(f"[HITL] Sending escalation email to manager ({manager_email})...")
                send_escalation_email(
                    supervisor_id    = supervisor_id,
                    supervisor_name  = supervisor_name,
                    requester_role   = requester_role,
                    query            = query,
                    request_id       = request_id,
                    failed_attempts  = new_count,
                    manager_email    = manager_email
                )

                audit_log["hitl_decision"] = "reject"
                audit_log["decision"]      = f"DENIED — Supervisor {supervisor_id} locked after {MAX_FAILED_ATTEMPTS} failed attempts"
                audit_log["error"]         = f"Supervisor lockout — escalation sent to manager"
                return audit_log

            else:
                print(f"\n  ✗ Incorrect PIN. {remaining} attempt(s) remaining.\n")

    # Should not reach here — but safety fallback
    audit_log["hitl_decision"] = "reject"
    audit_log["decision"]      = "DENIED — PIN verification failed"
    return audit_log
