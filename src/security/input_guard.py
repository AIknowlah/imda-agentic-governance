# =============================================================================
# input_guard.py  — v1.2
# Security Module: Input Hardening
#
# WHAT THIS FILE DOES:
#   Three layered controls applied to every query before any data is accessed:
#
#   Control 1: Query Sanitisation
#       Strips control characters, enforces max length, rejects empty/symbol-only queries.
#       Returns a cleaned query string safe for embedding and audit logging.
#
#   Control 2: Prompt Injection Detection
#       Scans for known injection patterns — role override attempts, instruction
#       hijacking, SYSTEM: prefixes, TOP_K manipulation, and encoded bypass attempts.
#       Blocked queries are rejected immediately — never reach the embedding node.
#
#   Control 3: Rate Limiting per Role
#       Tracks query counts per role per time window in BigQuery (rate_limit_log table).
#       Roles exceeding MAX_QUERIES_PER_WINDOW are blocked and their attempt logged.
#
# GOVERNANCE ALIGNMENT:
#   AI Verify Principle 4  — Safety    (injection blocked before data access)
#   AI Verify Principle 5  — Security  (rate limiting + blocked attempt logging)
#   AI Verify Principle 6  — Robustness (sanitisation handles malformed inputs cleanly)
#   IMDA 2026              — Bounded Autonomy (agent cannot be instructed to override controls)
#
# CALLED BY:
#   main.py → node_validate_role() — after role check, before embedding
#
# RETURNS:
#   InputGuardResult (TypedDict):
#       allowed      : bool   — True = proceed, False = block
#       clean_query  : str    — sanitised query (use this downstream, not the raw input)
#       block_reason : str    — human-readable reason if blocked, empty string if allowed
#       flag         : str    — short machine-readable code for audit log
#                               "INJECTION", "RATE_LIMITED", "INVALID_QUERY", or ""
# =============================================================================


# --- IMPORTS ---

import re
import datetime
from typing import TypedDict, Optional
from google.cloud import bigquery


# =============================================================================
# CONFIGURATION
# =============================================================================

PROJECT_ID = "secure-rag-sg"
DATASET_ID = "secure_rag"
RATE_LIMIT_TABLE = "rate_limit_log"

MAX_QUERY_LENGTH = 500
# Queries longer than this are rejected.
# Rationale: legitimate employee search queries are short.
# Very long queries are a signal of prompt injection or abuse.

MIN_QUERY_LENGTH = 2
# Single character queries are rejected as meaningless.

MAX_QUERIES_PER_WINDOW = 10
# A role may not submit more than 10 queries per hour.
# Protects against automated scraping of the employee database.
# Per-role, not per-user — enforced at the role level.

RATE_LIMIT_WINDOW_MINUTES = 60
# The rolling window for rate limiting.


# =============================================================================
# RETURN TYPE
# =============================================================================

class InputGuardResult(TypedDict):
    allowed:      bool
    clean_query:  str
    block_reason: str
    flag:         str


# =============================================================================
# CONTROL 1: QUERY SANITISATION
# =============================================================================

# Control characters to strip — everything below ASCII 32 except tab (0x09)
# and newline (0x0A which we convert to space). These can confuse embeddings
# and logging systems and have no place in a natural language search query.
CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')

# Pattern to detect queries that are pure punctuation/symbols with no word characters.
# A query like "!!!???###" has no semantic content and should be rejected.
SYMBOL_ONLY_PATTERN = re.compile(r'^[^\w\s]+$')


def sanitise_query(raw_query: str) -> tuple[bool, str, str]:
    """
    Cleans a raw query string and validates it is usable.

    Returns:
        (is_valid, clean_query, rejection_reason)
        is_valid      — True if the query is acceptable after cleaning
        clean_query   — the sanitised query to use downstream
        rejection_reason — non-empty string if rejected, empty if valid
    """

    # Step 1: Strip control characters
    clean = CONTROL_CHAR_PATTERN.sub('', raw_query)

    # Step 2: Normalise internal whitespace — collapse multiple spaces/newlines to single space
    clean = re.sub(r'\s+', ' ', clean).strip()

    # Step 3: Check length — reject if empty or too short after cleaning
    if len(clean) < MIN_QUERY_LENGTH:
        return False, clean, f"Query too short — minimum {MIN_QUERY_LENGTH} characters required."

    # Step 4: Check length — reject if too long
    if len(clean) > MAX_QUERY_LENGTH:
        return False, clean[:MAX_QUERY_LENGTH], (
            f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters. "
            f"Original length: {len(raw_query)}."
        )

    # Step 5: Reject symbol-only queries
    if SYMBOL_ONLY_PATTERN.match(clean):
        return False, clean, "Query contains only symbols — no searchable content."

    return True, clean, ""


# =============================================================================
# CONTROL 2: PROMPT INJECTION DETECTION
# =============================================================================

# --- INJECTION PATTERN LIBRARY ---
# Each tuple: (compiled_regex, human_readable_description)
# Patterns are case-insensitive and match partial strings within the query.
#
# DESIGN PRINCIPLE: Prefer false positives over false negatives for a governance system.
# A legitimate query that accidentally matches a pattern is a minor inconvenience.
# A successful injection attack is a governance failure.

INJECTION_PATTERNS = [

    # --- INSTRUCTION OVERRIDE ATTEMPTS ---
    # Classic prompt injection openers that attempt to override the system's behaviour.
    (re.compile(r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?)', re.IGNORECASE),
     "Instruction override attempt: 'ignore previous instructions'"),

    (re.compile(r'disregard\s+(all\s+)?(previous|prior|above|earlier|your)', re.IGNORECASE),
     "Instruction override attempt: 'disregard previous'"),

    (re.compile(r'forget\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?)', re.IGNORECASE),
     "Instruction override attempt: 'forget previous instructions'"),

    (re.compile(r'(new|your new|updated|revised)\s+(instructions?|rules?|directives?|orders?|task)\s*(are|is|follow|:)', re.IGNORECASE),
     "Instruction replacement attempt"),

    # --- ROLE / PERMISSION ESCALATION ---
    # Attempts to claim a higher role or override RBAC.
    (re.compile(r'(you are now|act as|pretend (to be|you are)|roleplay as|imagine you are)\s+(admin|root|superuser|system|god|unrestricted)', re.IGNORECASE),
     "Role escalation attempt: claiming elevated identity"),

    (re.compile(r'(grant|give|assign|elevate)\s+(me|my|user|role)\s+(admin|root|superuser|full|all)\s+(access|permissions?|rights?|privileges?)', re.IGNORECASE),
     "Permission escalation attempt"),

    (re.compile(r'(bypass|override|circumvent|skip|disable)\s+(the\s+)?(rbac|security|access control|permission|role|filter|gate|hitl|audit)', re.IGNORECASE),
     "Security bypass attempt"),

    (re.compile(r'show\s+(me\s+)?(all|every|hidden|restricted|sensitive|protected)\s+(fields?|data|records?|columns?|information)', re.IGNORECASE),
     "Restricted data access attempt"),

    # --- SYSTEM PROMPT / CONTEXT MANIPULATION ---
    # Attempts to read, replace, or inject into system-level context.
    (re.compile(r'\bSYSTEM\s*:', re.IGNORECASE),
     "System prompt injection attempt: SYSTEM: prefix"),

    (re.compile(r'\bUSER\s*:', re.IGNORECASE),
     "Context injection attempt: USER: prefix"),

    (re.compile(r'\bASSISTANT\s*:', re.IGNORECASE),
     "Context injection attempt: ASSISTANT: prefix"),

    (re.compile(r'(reveal|print|display|output|show|repeat|echo)\s+(your\s+)?(system\s+prompt|instructions?|context|configuration|rules?|constraints?)', re.IGNORECASE),
     "System prompt extraction attempt"),

    (re.compile(r'what\s+(are\s+)?(your|the)\s+(instructions?|rules?|constraints?|system\s+prompt)', re.IGNORECASE),
     "System prompt extraction attempt"),

    # --- PIPELINE / PARAMETER MANIPULATION ---
    # Attempts to manipulate TOP_K, timeouts, or pipeline behaviour.
    (re.compile(r'TOP_K\s*=', re.IGNORECASE),
     "Pipeline parameter manipulation: TOP_K override attempt"),

    (re.compile(r'(set|change|modify|update|override)\s+(TOP_K|LIMIT|MAX|timeout|threshold)\s*(=|to)', re.IGNORECASE),
     "Pipeline parameter manipulation attempt"),

    (re.compile(r'return\s+(all|every|\d{2,})\s+(records?|rows?|results?|employees?)', re.IGNORECASE),
     "Result limit bypass attempt"),

    # --- CODE / COMMAND INJECTION ---
    # Attempts to inject executable code or SQL.
    (re.compile(r'(--|;\s*DROP|;\s*DELETE|;\s*INSERT|;\s*UPDATE|UNION\s+SELECT|OR\s+1\s*=\s*1)', re.IGNORECASE),
     "SQL injection attempt"),

    (re.compile(r'(__import__|eval\s*\(|exec\s*\(|os\.system|subprocess)', re.IGNORECASE),
     "Python code injection attempt"),

    (re.compile(r'<script\b', re.IGNORECASE),
     "Script injection attempt"),

    # --- ENCODED / OBFUSCATED BYPASS ---
    # Attempts to hide injection using encoding.
    (re.compile(r'base64\s*:\s*[A-Za-z0-9+/]{10,}', re.IGNORECASE),
     "Encoded injection attempt: base64 payload detected"),

    (re.compile(r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}'),
     "Encoded injection attempt: hex escape sequence"),

    # --- JAILBREAK LANGUAGE ---
    # Common jailbreak framings used to lower the system's guard.
    (re.compile(r'(developer\s+mode|jailbreak|DAN\s+mode|do\s+anything\s+now)', re.IGNORECASE),
     "Jailbreak attempt: developer/DAN mode"),

    (re.compile(r'(hypothetically|theoretically|for\s+(a\s+)?(story|test|demo|simulation))\s*,?\s*(show|give|reveal|output|return)\s+(all|every|hidden|sensitive)', re.IGNORECASE),
     "Hypothetical framing to extract restricted data"),

    (re.compile(r'this\s+is\s+(just\s+a\s+)?(test|demo|simulation|example|hypothetical)', re.IGNORECASE),
     "Test/simulation framing — potential injection bypass attempt"),

]


def check_injection(clean_query: str) -> tuple[bool, str]:
    """
    Scans a sanitised query for prompt injection patterns.

    Returns:
        (injection_detected, matched_description)
        injection_detected    — True if any pattern matched
        matched_description   — which pattern matched (for audit log), empty if clean
    """

    for pattern, description in INJECTION_PATTERNS:
        if pattern.search(clean_query):
            return True, description

    return False, ""


# =============================================================================
# CONTROL 3: RATE LIMITING PER ROLE
# =============================================================================

def ensure_rate_limit_table(bq_client) -> None:
    """
    Creates the rate_limit_log table in BigQuery if it does not exist.
    Called once at pipeline startup from main.py.

    SCHEMA:
        timestamp   — when the query was made (UTC)
        user_role   — the role that made the query
        request_id  — links to the audit_log entry
        blocked     — True if this entry was a rate-limit block event
    """

    schema = [
        bigquery.SchemaField("timestamp",   "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("user_role",   "STRING",    mode="REQUIRED"),
        bigquery.SchemaField("request_id",  "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("blocked",     "BOOLEAN",   mode="NULLABLE"),
    ]

    try:
        table_ref = bigquery.Table(
            f"{PROJECT_ID}.{DATASET_ID}.{RATE_LIMIT_TABLE}",
            schema=schema
        )
        bq_client.create_table(table_ref, exists_ok=True)
    except Exception as e:
        print(f"[GUARD] Warning — could not ensure rate_limit_log table: {e}")


def count_recent_queries(bq_client, user_role: str) -> int:
    """
    Counts how many queries this role has made in the current time window.
    Uses a parameterised query — SQL injection safe.
    """

    window_start = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES)
    ).isoformat()

    try:
        rows = list(bq_client.query(
            f"SELECT COUNT(*) AS query_count "
            f"FROM `{PROJECT_ID}.{DATASET_ID}.{RATE_LIMIT_TABLE}` "
            f"WHERE user_role = @role "
            f"AND timestamp >= @window_start "
            f"AND blocked = FALSE",
            job_config=bigquery.QueryJobConfig(query_parameters=[
                bigquery.ScalarQueryParameter("role",         "STRING", user_role),
                bigquery.ScalarQueryParameter("window_start", "STRING", window_start),
            ])
        ).result())

        return rows[0].query_count if rows else 0

    except Exception as e:
        print(f"[GUARD] Warning — could not count rate limit queries: {e}")
        # Fail open on rate limit count error — do not block legitimate queries
        # due to a monitoring table failure. Log the error.
        return 0


def log_rate_limit_entry(bq_client, user_role: str, request_id: str, blocked: bool) -> None:
    """
    Logs a query attempt to rate_limit_log.
    Called for both allowed queries (blocked=False) and blocked ones (blocked=True).
    """

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        bq_client.insert_rows_json(
            f"{PROJECT_ID}.{DATASET_ID}.{RATE_LIMIT_TABLE}",
            [{
                "timestamp":  timestamp,
                "user_role":  user_role,
                "request_id": request_id,
                "blocked":    blocked,
            }]
        )
    except Exception as e:
        print(f"[GUARD] Warning — could not log rate limit entry: {e}")


def check_rate_limit(bq_client, user_role: str, request_id: str) -> tuple[bool, str]:
    """
    Checks whether the role has exceeded its query rate limit.

    Returns:
        (is_rate_limited, reason_message)
        is_rate_limited — True if limit exceeded (query should be blocked)
        reason_message  — description for audit log
    """

    count = count_recent_queries(bq_client, user_role)

    if count >= MAX_QUERIES_PER_WINDOW:
        log_rate_limit_entry(bq_client, user_role, request_id, blocked=True)
        return True, (
            f"Rate limit exceeded — role '{user_role}' has made {count} queries "
            f"in the last {RATE_LIMIT_WINDOW_MINUTES} minutes "
            f"(limit: {MAX_QUERIES_PER_WINDOW})."
        )

    return False, ""


# =============================================================================
# MAIN ENTRY POINT: check_query()
# =============================================================================

def check_query(
    raw_query:  str,
    user_role:  str,
    request_id: str,
    bq_client
) -> InputGuardResult:
    """
    Runs all three input hardening controls in sequence.
    Returns an InputGuardResult — the caller (node_validate_role) uses this
    to decide whether to proceed or block the pipeline.

    ORDER OF CONTROLS:
        1. Sanitise first — work with the clean string for all subsequent checks.
        2. Injection check — reject malicious queries before logging to rate limiter.
        3. Rate limit — count and log only legitimate (non-injected) queries.

    This order ensures:
        - Injection attempts are NOT counted as legitimate queries against the rate limit.
        - Rate limit logs only reflect real usage, not attack traffic.
    """

    # --- CONTROL 1: SANITISATION ---
    is_valid, clean_query, rejection_reason = sanitise_query(raw_query)

    if not is_valid:
        print(f"[GUARD] Query rejected — sanitisation failed: {rejection_reason}")
        return InputGuardResult(
            allowed      = False,
            clean_query  = clean_query,
            block_reason = rejection_reason,
            flag         = "INVALID_QUERY",
        )

    # --- CONTROL 2: INJECTION DETECTION ---
    injection_detected, matched_pattern = check_injection(clean_query)

    if injection_detected:
        print(f"[GUARD] !! PROMPT INJECTION DETECTED !!")
        print(f"[GUARD] Pattern matched: {matched_pattern}")
        print(f"[GUARD] Query blocked. Role: [{user_role}] | Request ID: {request_id}")
        # Note: injection attempts are NOT logged to rate_limit_log.
        # They are logged to audit_log via the injection_flag field in main.py.
        return InputGuardResult(
            allowed      = False,
            clean_query  = clean_query,
            block_reason = f"Prompt injection detected — {matched_pattern}",
            flag         = "INJECTION",
        )

    # --- CONTROL 3: RATE LIMITING ---
    is_rate_limited, rate_reason = check_rate_limit(bq_client, user_role, request_id)

    if is_rate_limited:
        print(f"[GUARD] Rate limit exceeded for role [{user_role}].")
        print(f"[GUARD] {rate_reason}")
        return InputGuardResult(
            allowed      = False,
            clean_query  = clean_query,
            block_reason = rate_reason,
            flag         = "RATE_LIMITED",
        )

    # --- ALL CONTROLS PASSED ---
    # Log this as a legitimate query attempt.
    log_rate_limit_entry(bq_client, user_role, request_id, blocked=False)

    print(f"[GUARD] Query passed all input checks.")
    return InputGuardResult(
        allowed      = True,
        clean_query  = clean_query,
        block_reason = "",
        flag         = "",
    )