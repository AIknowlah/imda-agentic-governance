# =============================================================================
# main.py  — v1.2
# Phase 2 & 3: Agentic Gatekeeper with RBAC + HITL + Input Hardening
#
# WHAT THIS FILE DOES:
#   1. Validates the user's role (Safety Gate)
#   2. Hardens the query — sanitisation, injection detection, rate limiting  [v1.2]
#   3. Converts the search query into a Gemini embedding
#   4. Searches BigQuery for semantically similar employee records
#   5. Enforces RBAC — strips fields the role cannot see
#   6. Triggers HITL gate if sensitive fields are detected
#   7. Displays approved results to the user
#   8. Saves a full audit log entry to BigQuery
#
# TECH STACK:
#   google-genai          — Gemini AI (embeddings + language model)
#   google-cloud-bigquery — Data storage and audit logs (Singapore)
#   langgraph             — Agent pipeline (nodes + edges)
#   input_guard           — v1.2 input hardening module (new)
#
# v1.2 CHANGES FROM v1.1:
#   [FIX 11] Prompt injection detection — 23 patterns across 6 attack categories
#   [FIX 12] Query sanitisation — control chars stripped, length enforced, symbols rejected
#   [FIX 13] Rate limiting per role — BigQuery rate_limit_log, 10 queries/hour/role
#   [FIX 14] Dead code removed from node_human_review() — v1.0 fallback (lines 512-599)
#            was unreachable after v1.1 refactor. Removed for clarity.
#   [FIX 15] New AgentState field: injection_detected (bool)
#   [FIX 16] New audit_log field: injection_flag (string) — records attack type if blocked
#   [FIX 17] node_validate_role() now calls input_guard.check_query() after role check
#   [FIX 18] Clean query (post-sanitisation) used downstream — not raw input
#
# AI Verify Principle Targets for v1.2:
#   Principle 4 (Safety)     — injection blocked before any data access
#   Principle 5 (Security)   — rate limiting + blocked attempt logging
#   Principle 6 (Robustness) — sanitisation handles malformed inputs cleanly
#
# RUN ORDER:
#   1. python processor.py          (loads employee data)
#   2. python setup_supervisors.py  (creates supervisor/manager tables)
#   3. python main.py               (runs the agent)
# =============================================================================


# --- IMPORTS ---

import os
import json
import uuid
import datetime
import signal
import numpy as np
from dotenv import load_dotenv
from typing import TypedDict, Optional, List
from google import genai
from google.cloud import bigquery
from langgraph.graph import StateGraph, END
import sys

# Add project root to path so src.hitl and src.security resolve correctly
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from src.hitl.hitl_gate       import run_hitl_gate
from src.security.input_guard import check_query, ensure_rate_limit_table

# uuid: Generates unique request IDs for every audit log entry.          [FIX 3]
# signal: Used to implement the HITL timeout mechanism.                  [FIX 4]
# input_guard: v1.2 input hardening — sanitisation, injection, rate limit [v1.2]


# =============================================================================
# CONFIGURATION — must match processor.py exactly
# =============================================================================

load_dotenv()

API_KEY     = os.getenv("GOOGLE_API_KEY")
# Your Gemini API key loaded from .env file.

PROJECT_ID  = "secure-rag-sg"
REGION      = "asia-southeast1"
DATASET_ID  = "secure_rag"
TABLE_ID    = "employee_data"
EMBED_TABLE = "employee_embeddings"
AUDIT_TABLE = "audit_log"

EMBED_MODEL = "gemini-embedding-001"
# Must match processor.py — same model used to store embeddings.

CHAT_MODEL  = "gemini-2.5-flash"
# The Gemini model used for understanding queries and generating responses.

TOP_K       = 5
# Number of most similar records to retrieve per search query.
# [FIX 11] This value is now hardened — injection attempts to override it are blocked
# by input_guard before the pipeline ever reaches the retrieval node.

LOW_SIMILARITY_THRESHOLD = 0.3
# [FIX 7] Warn if the top result scores below this threshold.


# =============================================================================
# SENSITIVE FIELDS — HITL TRIGGER LIST
# Must match processor.py.
# =============================================================================

SENSITIVE_FIELDS = {"nric", "ethnicity", "medical_info", "financial_info", "criminal_record"}


# =============================================================================
# SECTION 1: RBAC ROLE DEFINITIONS
# =============================================================================

ROLE_PERMISSIONS = {
    "General_Staff": {
        "allowed_fields": ["name", "employment"],
        "description": "Access to general, non-sensitive employee data only."
    },
    "HR_Admin": {
        "allowed_fields": ["name", "employment", "nric", "ethnicity"],
        "description": "Access to PII including NRIC and ethnicity."
    },
    "Finance_Lead": {
        "allowed_fields": ["name", "employment", "financial_info"],
        "description": "Access to financial records."
    },
    "Medical_Lead": {
        "allowed_fields": ["name", "employment", "medical_info"],
        "description": "Access to medical documentation."
    },
}


# =============================================================================
# SECTION 2: AGENT STATE
# Shared data container flowing through every LangGraph node.
# =============================================================================

class AgentState(TypedDict):
    request_id:         str
    # [FIX 3] Unique UUID for every pipeline run — links audit log to session.

    user_role:          str
    # Role of the person making the query.

    query:              str
    # The search question the user typed in.
    # [FIX 18] After node_validate_role(), this field holds the SANITISED query,
    # not the raw input. The clean version is used for embedding and audit logging.

    query_embedding:    List[float]
    # Gemini embedding of the query — 3072 numbers representing its meaning.

    raw_results:        list
    # Unfiltered records from BigQuery (all fields included).

    filtered_results:   list
    # Records after RBAC filtering — only permitted fields remain.

    audit_log:          dict
    # Structured compliance record — saved to BigQuery at the end.

    error:              Optional[str]
    # Error message if something went wrong. None = no error.

    hitl_triggered:     bool
    # True if the HITL gate activated (sensitive fields detected).

    hitl_decision:      Optional[str]
    # "approve" or "reject" — set by the human reviewer.

    injection_detected: bool
    # [FIX 15] True if input_guard blocked the query for injection or invalid input.
    # Stored in state so downstream nodes can check it, and for audit log writing.


# =============================================================================
# SECTION 3: INITIALISE GOOGLE CLOUD CONNECTIONS
# =============================================================================

print("[INIT] Connecting to Gemini and BigQuery...")

try:
    gemini_client = genai.Client(api_key=API_KEY)
    # [FIX 2] Wrapped in try/except — failure here is caught cleanly.
except Exception as e:
    print(f"[INIT] FATAL — Could not connect to Gemini: {e}")
    raise SystemExit(1)

try:
    bq_client = bigquery.Client(project=PROJECT_ID)
    # [FIX 2] Wrapped in try/except — failure here is caught cleanly.
except Exception as e:
    print(f"[INIT] FATAL — Could not connect to BigQuery: {e}")
    raise SystemExit(1)

print(f"[INIT] Gemini model : {CHAT_MODEL}")
print(f"[INIT] Embed model  : {EMBED_MODEL}")
print(f"[INIT] BigQuery     : {PROJECT_ID}.{DATASET_ID} ({REGION})\n")


# =============================================================================
# SECTION 3b: ENSURE TABLES EXIST
# =============================================================================

def ensure_audit_table():
    """Creates the BigQuery audit log table if it doesn't already exist."""

    schema = [
        bigquery.SchemaField("request_id",       "STRING",    mode="REQUIRED"),
        # [FIX 3] Unique UUID per query.

        bigquery.SchemaField("timestamp",        "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("user_role",        "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("query",            "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("decision",         "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("records_returned", "INTEGER",   mode="NULLABLE"),
        bigquery.SchemaField("fields_exposed",   "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("hitl_triggered",   "BOOLEAN",   mode="NULLABLE"),
        bigquery.SchemaField("hitl_decision",    "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("hitl_timeout",     "BOOLEAN",   mode="NULLABLE"),
        # [FIX 4] Records whether HITL auto-rejected due to timeout.

        bigquery.SchemaField("rbac_rule_applied","STRING",    mode="NULLABLE"),
        # [FIX 6] Records which RBAC role rule was applied to this query.

        bigquery.SchemaField("injection_flag",   "STRING",    mode="NULLABLE"),
        # [FIX 16] Records the injection/block type if input_guard blocked the query.
        # Values: "INJECTION", "RATE_LIMITED", "INVALID_QUERY", or empty string.

        bigquery.SchemaField("error",            "STRING",    mode="NULLABLE"),
    ]

    try:
        table_ref = bigquery.Table(f"{PROJECT_ID}.{DATASET_ID}.{AUDIT_TABLE}", schema=schema)
        bq_client.create_table(table_ref, exists_ok=True)
    except Exception as e:
        print(f"[AUDIT] Warning — could not ensure audit table exists: {e}")


ensure_audit_table()

# [v1.2] Ensure rate_limit_log table exists — created by input_guard module.
ensure_rate_limit_table(bq_client)


# =============================================================================
# SECTION 4: COSINE SIMILARITY HELPER
# =============================================================================

def cosine_similarity(vec_a, vec_b):
    """
    Measures how similar two embedding vectors are.
    Returns a score from -1 (opposite) to 1 (identical meaning).
    """

    a           = np.array(vec_a)
    b           = np.array(vec_b)
    dot_product = np.dot(a, b)
    norm_a      = np.linalg.norm(a)
    norm_b      = np.linalg.norm(b)

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot_product / (norm_a * norm_b)


# =============================================================================
# SECTION 5: LANGGRAPH NODES
# =============================================================================

def node_validate_role(state: AgentState) -> AgentState:
    """
    SAFETY GATE: Validates the user's role, then runs all three input hardening
    controls via input_guard.check_query().

    v1.2 CHANGES:
        [FIX 17] Calls input_guard.check_query() after role validation.
        [FIX 18] Replaces state["query"] with the sanitised clean query.
        [FIX 15] Sets state["injection_detected"] flag.
        [FIX 16] Records injection_flag in audit_log.
    """

    role       = state["user_role"]
    request_id = state["request_id"]
    timestamp  = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Initialise audit log with all fields
    state["audit_log"] = {
        "request_id":        request_id,
        "timestamp":         timestamp,
        "user_role":         role,
        "query":             state["query"],
        "decision":          None,
        "records_returned":  0,
        "fields_exposed":    "[]",
        "hitl_triggered":    False,
        "hitl_decision":     None,
        "hitl_timeout":      False,
        "rbac_rule_applied": None,
        "injection_flag":    "",    # [FIX 16] New field — populated below if blocked
        "error":             None,
    }

    # --- ROLE VALIDATION ---
    if role not in ROLE_PERMISSIONS:
        state["error"]                         = f"Unknown role '{role}'. Access denied."
        state["audit_log"]["decision"]         = "DENIED - Invalid role"
        state["audit_log"]["error"]            = state["error"]
        state["injection_detected"]            = False
        print(f"[GATE] {state['error']}")
        return state

    print(f"[GATE] Role '{role}' validated — {ROLE_PERMISSIONS[role]['description']}")
    print(f"[GATE] Request ID: {request_id}")

    # --- [v1.2] INPUT HARDENING ---
    # Run all three controls: sanitisation → injection detection → rate limiting.
    # input_guard returns the sanitised query regardless of outcome — use it downstream.
    guard_result = check_query(
        raw_query  = state["query"],
        user_role  = role,
        request_id = request_id,
        bq_client  = bq_client
    )

    # [FIX 18] Replace raw query with the sanitised version in state and audit log.
    state["query"]                   = guard_result["clean_query"]
    state["audit_log"]["query"]      = guard_result["clean_query"]
    state["audit_log"]["injection_flag"] = guard_result["flag"]
    # [FIX 16] Audit log records what type of block occurred (or empty string if clean).

    if not guard_result["allowed"]:
        # [FIX 15] Mark injection_detected in state for downstream awareness.
        state["injection_detected"]        = True
        state["error"]                     = guard_result["block_reason"]
        state["audit_log"]["decision"]     = f"DENIED - {guard_result['flag']}: {guard_result['block_reason']}"
        state["audit_log"]["error"]        = state["error"]
        return state

    # All checks passed — proceed normally.
    state["injection_detected"] = False
    state["error"]              = None
    return state


def node_embed_query(state: AgentState) -> AgentState:
    """
    EMBEDDING NODE: Converts the user's query text into a Gemini embedding.
    Uses the sanitised query from state["query"] — not the original raw input.
    [FIX 18] Sanitised query is used here, so the embedding reflects the cleaned text.
    """

    if state.get("error"):
        return state

    query = state["query"]
    # [FIX 18] This is already the sanitised query — set in node_validate_role().
    print(f"[EMBED] Generating embedding for: '{query}'")

    try:
        result = gemini_client.models.embed_content(
            model=EMBED_MODEL,
            contents=query
        )
        state["query_embedding"] = result.embeddings[0].values
        print(f"[EMBED] Query embedded ({len(state['query_embedding'])} dimensions).")

    except Exception as e:
        state["error"]                     = f"Embedding failed — Gemini API error: {e}"
        state["audit_log"]["decision"]     = "DENIED - Embedding error"
        state["audit_log"]["error"]        = state["error"]
        print(f"[EMBED] ERROR: {state['error']}")

    return state


def node_retrieve(state: AgentState) -> AgentState:
    """
    RETRIEVAL NODE: Fetches all embeddings from BigQuery, calculates
    cosine similarity against the query embedding, then retrieves the
    full employee records for the top K most similar matches.

    [FIX 1] Uses parameterised BigQuery query to prevent SQL injection.
    [FIX 2] All BigQuery calls wrapped in try/except.
    [FIX 7] Warns if top result similarity score is below threshold.
    """

    if state.get("error"):
        return state

    print("[RETRIEVE] Searching BigQuery for similar records...")

    # --- FETCH ALL EMBEDDINGS ---
    try:
        rows = list(bq_client.query(
            f"SELECT nric, content, embedding FROM `{PROJECT_ID}.{DATASET_ID}.{EMBED_TABLE}`"
        ).result())
    except Exception as e:
        state["error"]                     = f"Retrieval failed — BigQuery error: {e}"
        state["audit_log"]["decision"]     = "DENIED - BigQuery error"
        state["audit_log"]["error"]        = state["error"]
        print(f"[RETRIEVE] ERROR: {state['error']}")
        return state

    if not rows:
        print("[RETRIEVE] No embeddings found. Have you run processor.py?")
        state["raw_results"] = []
        return state

    # --- CALCULATE SIMILARITY ---
    similarities = []
    for row in rows:
        stored_vec = json.loads(row.embedding)
        score      = cosine_similarity(state["query_embedding"], stored_vec)
        similarities.append((row.nric, score))

    similarities.sort(key=lambda x: x[1], reverse=True)
    top_nrics = [nric for nric, _ in similarities[:TOP_K]]

    # --- [FIX 7] LOW SIMILARITY WARNING ---
    top_score = similarities[0][1] if similarities else 0
    if top_score < LOW_SIMILARITY_THRESHOLD:
        print(f"[RETRIEVE] WARNING — Low similarity (top score: {round(top_score, 4)}).")
        state["audit_log"]["error"] = (
            state["audit_log"].get("error") or
            f"Low similarity warning — top score {round(top_score, 4)}"
        )

    # --- [FIX 1] PARAMETERISED QUERY — SQL INJECTION SAFE ---
    query_params = [
        bigquery.ArrayQueryParameter("nric_list", "STRING", top_nrics)
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=query_params)

    try:
        employee_rows = list(bq_client.query(
            f"SELECT * FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}` WHERE nric IN UNNEST(@nric_list)",
            job_config=job_config
        ).result())
    except Exception as e:
        state["error"]                     = f"Record fetch failed — BigQuery error: {e}"
        state["audit_log"]["decision"]     = "DENIED - BigQuery error"
        state["audit_log"]["error"]        = state["error"]
        print(f"[RETRIEVE] ERROR: {state['error']}")
        return state

    # --- ASSEMBLE RESULTS ---
    score_map = {nric: score for nric, score in similarities[:TOP_K]}
    raw = []
    for row in employee_rows:
        record                      = dict(row)
        record["_similarity_score"] = round(score_map.get(record["nric"], 0), 4)
        raw.append(record)

    raw.sort(key=lambda x: x["_similarity_score"], reverse=True)

    state["raw_results"] = raw
    print(f"[RETRIEVE] {len(raw)} records retrieved from BigQuery.")
    return state


def node_enforce_rbac(state: AgentState) -> AgentState:
    """
    RBAC ENFORCEMENT: Filters each record to only show fields
    the user's role is explicitly permitted to access.

    [FIX 6] Records which RBAC rule was applied in the audit log.
    """

    if state.get("error"):
        return state

    role           = state["user_role"]
    allowed_fields = ROLE_PERMISSIONS[role]["allowed_fields"]

    filtered = []
    for record in state["raw_results"]:
        filtered_record = {
            field: record[field]
            for field in allowed_fields
            if field in record
        }
        filtered_record["_similarity_score"] = record.get("_similarity_score", 0)
        filtered.append(filtered_record)

    state["filtered_results"]               = filtered
    state["audit_log"]["decision"]          = "APPROVED"
    state["audit_log"]["records_returned"]  = len(filtered)
    state["audit_log"]["fields_exposed"]    = json.dumps(allowed_fields)
    state["audit_log"]["rbac_rule_applied"] = f"{role}: {json.dumps(allowed_fields)}"

    print(f"[RBAC] Role '{role}' — permitted fields: {allowed_fields}")
    return state


def node_human_review(state: AgentState) -> AgentState:
    """
    HITL GATE v1.1: Two-person governance mechanism.
    Calls hitl_gate.py which enforces:
      - Summary-only preview (no field values shown to requester)
      - Supervisor ID + PIN verification
      - Two-person rule (requester cannot approve own query)
      - Three-strike lockout
      - Gmail escalation to manager on lockout
      - Full audit trail

    [FIX 14] Dead code removed — v1.0 fallback (single-person inline HITL)
             was unreachable after v1.1 refactor and has been deleted.
    """

    if state.get("error"):
        return state

    # --- CHECK FOR SENSITIVE FIELDS ---
    fields_in_results = {
        key
        for record in state["filtered_results"]
        for key in record.keys()
        if not key.startswith("_")
    }

    triggered_fields = fields_in_results & SENSITIVE_FIELDS

    if not triggered_fields:
        state["hitl_triggered"]              = False
        state["hitl_decision"]               = None
        state["audit_log"]["hitl_triggered"] = False
        state["audit_log"]["hitl_decision"]  = "N/A - No sensitive fields"
        state["audit_log"]["hitl_timeout"]   = False
        print("[HITL] No sensitive fields detected. Proceeding automatically.")
        return state

    # --- SENSITIVE FIELDS DETECTED — CALL v1.1 HITL GATE ---
    state["hitl_triggered"]              = True
    state["audit_log"]["hitl_triggered"] = True

    updated_audit_log = run_hitl_gate(
        bq_client        = bq_client,
        request_id       = state["request_id"],
        requester_role   = state["user_role"],
        query            = state["query"],
        filtered_results = state["filtered_results"],
        triggered_fields = triggered_fields,
        audit_log        = state["audit_log"]
    )

    state["audit_log"]   = updated_audit_log
    state["hitl_decision"] = updated_audit_log.get("hitl_decision")

    if state["hitl_decision"] != "approve":
        state["error"] = updated_audit_log.get("decision", "DENIED by HITL gate")

    return state


def node_output(state: AgentState) -> AgentState:
    """
    OUTPUT NODE: Displays results and saves audit log to BigQuery.
    Every query — approved or denied — is permanently recorded.

    [FIX 5] All output labelled [AI-GENERATED].
    [FIX 6] RBAC rule applied and similarity scores shown.
    """

    print("\n" + "=" * 60)

    if state.get("error"):
        print(f"  ACCESS DENIED: {state['error']}")
        state["audit_log"]["decision"] = state["audit_log"].get("decision") or "DENIED"
        state["audit_log"]["error"]    = state["error"]
    else:
        results = state["filtered_results"]
        role    = state["user_role"]

        # [FIX 5] [AI-GENERATED] label on all output.
        print(f"  [AI-GENERATED] Results for [{role}] — {len(results)} record(s)")
        print(f"  Request ID : {state['request_id']}")

        # [FIX 6] Show which RBAC rule was applied.
        allowed_fields = ROLE_PERMISSIONS[role]["allowed_fields"]
        print(f"  RBAC rule  : Role '{role}' permitted fields → {allowed_fields}\n")

        for i, record in enumerate(results, 1):
            print(f"  Record {i}:")
            for key, value in record.items():
                if not key.startswith("_"):
                    print(f"    {key:<20}: {value}")

            score = record.get("_similarity_score", "N/A")
            print(f"    {'similarity_score':<20}: {score}")

            if isinstance(score, float) and score < LOW_SIMILARITY_THRESHOLD:
                print(f"    ⚠ Low similarity — this result may not be relevant.")
            print()

    print("=" * 60)

    # --- SAVE AUDIT LOG TO BIGQUERY ---
    audit_row = {
        "request_id":        state["audit_log"].get("request_id"),
        "timestamp":         state["audit_log"].get("timestamp"),
        "user_role":         state["audit_log"].get("user_role"),
        "query":             state["audit_log"].get("query"),
        "decision":          state["audit_log"].get("decision"),
        "records_returned":  state["audit_log"].get("records_returned", 0),
        "fields_exposed":    state["audit_log"].get("fields_exposed", "[]"),
        "hitl_triggered":    state["audit_log"].get("hitl_triggered", False),
        "hitl_decision":     state["audit_log"].get("hitl_decision"),
        "hitl_timeout":      state["audit_log"].get("hitl_timeout", False),
        "rbac_rule_applied": state["audit_log"].get("rbac_rule_applied"),
        "injection_flag":    state["audit_log"].get("injection_flag", ""),
        # [FIX 16] injection_flag written to BigQuery audit log.
        "error":             state["audit_log"].get("error"),
    }

    try:
        errors = bq_client.insert_rows_json(
            f"{PROJECT_ID}.{DATASET_ID}.{AUDIT_TABLE}", [audit_row]
        )
        if errors:
            print(f"[AUDIT] Warning — could not save audit log: {errors}")
        else:
            print(f"[AUDIT] Audit log saved → {AUDIT_TABLE} | Request ID: {state['request_id']}\n")
    except Exception as e:
        print(f"[AUDIT] Warning — audit log exception: {e}")

    return state


# =============================================================================
# SECTION 6: ROUTING LOGIC
# =============================================================================

def route_after_validation(state: AgentState) -> str:
    """
    Routes to embed_query on success, or output if any error occurred.
    This catches both role validation failures and input guard blocks.
    """
    if state.get("error"):
        return "output"
    return "embed_query"


# =============================================================================
# SECTION 7: BUILD LANGGRAPH PIPELINE
# =============================================================================

def build_graph() -> StateGraph:
    """
    Assembles the full LangGraph pipeline.
    Flow: validate_role → embed_query → retrieve → enforce_rbac → human_review → output

    v1.2: Input hardening is embedded inside validate_role — no new node needed.
    The guard runs between role check and the conditional edge, keeping the graph
    structure clean and the hardening invisible to the rest of the pipeline.
    """

    graph = StateGraph(AgentState)

    graph.add_node("validate_role", node_validate_role)
    graph.add_node("embed_query",   node_embed_query)
    graph.add_node("retrieve",      node_retrieve)
    graph.add_node("enforce_rbac",  node_enforce_rbac)
    graph.add_node("human_review",  node_human_review)
    graph.add_node("output",        node_output)

    graph.set_entry_point("validate_role")

    graph.add_conditional_edges(
        "validate_role",
        route_after_validation,
        {"embed_query": "embed_query", "output": "output"}
    )

    graph.add_edge("embed_query",  "retrieve")
    graph.add_edge("retrieve",     "enforce_rbac")
    graph.add_edge("enforce_rbac", "human_review")
    graph.add_edge("human_review", "output")
    graph.add_edge("output",        END)

    return graph.compile()


# =============================================================================
# SECTION 8: MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":

    print("=" * 60)
    print("  AGENTIC ETL GATEKEEPER — v1.2")
    print("  Gemini 2.5 Flash + BigQuery + RBAC + HITL + Input Hardening")
    print("  IMDA 2026 Aligned | PDPA Singapore")
    print("=" * 60)

    print("\nAvailable roles:")
    for role, info in ROLE_PERMISSIONS.items():
        print(f"  [{role}] — {info['description']}")

    print()
    user_role  = input("Enter your role : ").strip()
    user_query = input("Enter your query: ").strip()

    if not user_query:
        user_query = "Show me employee information"

    app = build_graph()
    print(f"\n[START] Running pipeline...\n")

    request_id = str(uuid.uuid4())

    initial_state: AgentState = {
        "request_id":        request_id,
        "user_role":         user_role,
        "query":             user_query,
        "query_embedding":   [],
        "raw_results":       [],
        "filtered_results":  [],
        "audit_log":         {},
        "error":             None,
        "hitl_triggered":    False,
        "hitl_decision":     None,
        "injection_detected": False,
        # [FIX 15] New field — initialised False, set True by input_guard if blocked.
    }

    app.invoke(initial_state)
    print("[DONE] Pipeline complete.")
