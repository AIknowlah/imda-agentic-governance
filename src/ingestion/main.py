# =============================================================================
# main.py  — FINAL VERSION
# Phase 2 & 3: Agentic Gatekeeper with RBAC + HITL
#
# WHAT THIS FILE DOES:
#   1. Validates the user's role (Safety Gate)
#   2. Converts the search query into a Gemini embedding
#   3. Searches BigQuery for semantically similar employee records
#   4. Enforces RBAC — strips fields the role cannot see
#   5. Triggers HITL gate if sensitive fields are detected
#   6. Displays approved results to the user
#   7. Saves a full audit log entry to BigQuery
#
# TECH STACK:
#   google-genai          — Gemini AI (embeddings + language model)
#   google-cloud-bigquery — Data storage and audit logs (Singapore)
#   langgraph             — Agent pipeline (nodes + edges)
#
# RUN ORDER:
#   1. python processor.py first (to load data)
#   2. python main.py      (to run the agent)
# =============================================================================


# --- IMPORTS ---

import os
import json
import datetime
import numpy as np
from dotenv import load_dotenv
from typing import TypedDict, Optional, List
from google import genai
from google.cloud import bigquery
from langgraph.graph import StateGraph, END


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
# NEW: Audit logs now stored in BigQuery instead of a local JSON file.
# This makes every query permanently recorded and queryable.

EMBED_MODEL = "gemini-embedding-001"
# Must match processor.py — same model used to store embeddings.

CHAT_MODEL  = "gemini-2.5-flash"
# The Gemini model used for understanding queries and generating responses.

TOP_K       = 5
# Number of most similar records to retrieve per search query.


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
    user_role:          str
    # Role of the person making the query.

    query:              str
    # The search question the user typed in.

    query_embedding:    List[float]
    # Gemini embedding of the query — 768 numbers representing its meaning.

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


# =============================================================================
# SECTION 3: INITIALISE GOOGLE CLOUD CONNECTIONS
# =============================================================================

print("[INIT] Connecting to Gemini and BigQuery...")

gemini_client = genai.Client(api_key=API_KEY)
# Connect to Gemini using your AI Studio API key.

bq_client = bigquery.Client(project=PROJECT_ID)
# Connect to BigQuery using gcloud Application Default Credentials.

print(f"[INIT] Gemini model : {CHAT_MODEL}")
print(f"[INIT] Embed model  : {EMBED_MODEL}")
print(f"[INIT] BigQuery     : {PROJECT_ID}.{DATASET_ID} ({REGION})\n")


# =============================================================================
# SECTION 3b: ENSURE AUDIT LOG TABLE EXISTS
# =============================================================================

def ensure_audit_table():
    """Creates the BigQuery audit log table if it doesn't already exist."""

    schema = [
        bigquery.SchemaField("timestamp",        "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("user_role",        "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("query",            "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("decision",         "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("records_returned", "INTEGER",   mode="NULLABLE"),
        bigquery.SchemaField("fields_exposed",   "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("hitl_triggered",   "BOOLEAN",   mode="NULLABLE"),
        bigquery.SchemaField("hitl_decision",    "STRING",    mode="NULLABLE"),
        bigquery.SchemaField("error",            "STRING",    mode="NULLABLE"),
    ]

    table_ref = bigquery.Table(f"{PROJECT_ID}.{DATASET_ID}.{AUDIT_TABLE}", schema=schema)
    bq_client.create_table(table_ref, exists_ok=True)
    # exists_ok=True = don't crash if the table already exists.

ensure_audit_table()


# =============================================================================
# SECTION 4: COSINE SIMILARITY HELPER
# =============================================================================

def cosine_similarity(vec_a, vec_b):
    """
    Measures how similar two embedding vectors are.
    Returns a score from -1 (opposite) to 1 (identical meaning).
    We use this to rank BigQuery results by relevance to the search query.
    """

    a           = np.array(vec_a)
    b           = np.array(vec_b)
    dot_product = np.dot(a, b)
    # Dot product measures how much two vectors point in the same direction.

    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    # Magnitude (length) of each vector — needed to normalise the result.

    if norm_a == 0 or norm_b == 0:
        return 0.0
    # Avoid division by zero.

    return dot_product / (norm_a * norm_b)
    # Cosine similarity formula. Result is always between -1 and 1.


# =============================================================================
# SECTION 5: LANGGRAPH NODES
# =============================================================================

def node_validate_role(state: AgentState) -> AgentState:
    """
    SAFETY GATE: Validates the user's role before any data is accessed.
    Unknown roles are denied immediately — pipeline halts here.
    """

    role      = state["user_role"]
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # UTC timestamp — required format for BigQuery TIMESTAMP fields.

    # Initialise audit log with all fields
    state["audit_log"] = {
        "timestamp":        timestamp,
        "user_role":        role,
        "query":            state["query"],
        "decision":         None,
        "records_returned": 0,
        "fields_exposed":   "[]",
        "hitl_triggered":   False,
        "hitl_decision":    None,
        "error":            None,
    }

    if role not in ROLE_PERMISSIONS:
        state["error"] = f"Unknown role '{role}'. Access denied."
        state["audit_log"]["decision"] = "DENIED - Invalid role"
        state["audit_log"]["error"]    = state["error"]
        print(f"[GATE] {state['error']}")
    else:
        state["error"] = None
        print(f"[GATE] Role '{role}' validated — {ROLE_PERMISSIONS[role]['description']}")

    return state


def node_embed_query(state: AgentState) -> AgentState:
    """
    EMBEDDING NODE: Converts the user's query text into a Gemini embedding.
    This embedding is compared against stored embeddings to find similar records.
    """

    if state.get("error"):
        return state

    query = state["query"]
    print(f"[EMBED] Generating embedding for: '{query}'")

    result = gemini_client.models.embed_content(
        model=EMBED_MODEL,
        contents=query
        # Send the query to Gemini's embedding model.
        # Returns a list of 768 numbers representing the query's meaning.
    )

    state["query_embedding"] = result.embeddings[0].values
    # Store the embedding in state for the retrieve node to use.

    print(f"[EMBED] Query embedded ({len(state['query_embedding'])} dimensions).")
    return state


def node_retrieve(state: AgentState) -> AgentState:
    """
    RETRIEVAL NODE: Fetches all embeddings from BigQuery, calculates
    cosine similarity against the query embedding, then retrieves the
    full employee records for the top K most similar matches.
    """

    if state.get("error"):
        return state

    print("[RETRIEVE] Searching BigQuery for similar records...")

    # Fetch all stored embeddings
    rows = list(bq_client.query(
        f"SELECT nric, content, embedding FROM `{PROJECT_ID}.{DATASET_ID}.{EMBED_TABLE}`"
    ).result())
    # .result() waits for the BigQuery query to finish.
    # list() converts the RowIterator into a plain Python list.

    if not rows:
        print("[RETRIEVE] No embeddings found. Have you run processor.py?")
        state["raw_results"] = []
        return state

    # Calculate similarity for each stored embedding
    similarities = []
    for row in rows:
        stored_vec = json.loads(row.embedding)
        # json.loads() converts the stored JSON string back to a Python list.

        score = cosine_similarity(state["query_embedding"], stored_vec)
        # Compare query embedding to this record's embedding.

        similarities.append((row.nric, score))

    # Sort by similarity score — highest first
    similarities.sort(key=lambda x: x[1], reverse=True)
    # lambda x: x[1] means "sort by the second item in each tuple" (the score).
    # reverse=True = descending order (highest similarity first).

    top_nrics = [nric for nric, _ in similarities[:TOP_K]]
    # Extract the NRICs of the top K most similar records.

    # Fetch full employee records for top K NRICs
    nric_list = ", ".join([f"'{n}'" for n in top_nrics])
    # Build a SQL-safe comma-separated string: "'S1234A', 'S5678B'"

    employee_rows = list(bq_client.query(
        f"SELECT * FROM `{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}` WHERE nric IN ({nric_list})"
    ).result())
    # SELECT * = all columns. WHERE nric IN (...) = only the top K matches.

    # Build similarity score lookup
    score_map = {nric: score for nric, score in similarities[:TOP_K]}
    # Dictionary comprehension: {nric: similarity_score} for quick lookup.

    # Assemble raw results with similarity scores attached
    raw = []
    for row in employee_rows:
        record = dict(row)
        # dict(row) converts a BigQuery Row object to a plain Python dictionary.

        record["_similarity_score"] = round(score_map.get(record["nric"], 0), 4)
        # Attach the similarity score. "_" prefix = internal field, not user data.

        raw.append(record)

    raw.sort(key=lambda x: x["_similarity_score"], reverse=True)
    # Sort final results by similarity score, highest first.

    state["raw_results"] = raw
    print(f"[RETRIEVE] {len(raw)} records retrieved from BigQuery.")
    return state


def node_enforce_rbac(state: AgentState) -> AgentState:
    """
    RBAC ENFORCEMENT: Filters each record to only show fields
    the user's role is explicitly permitted to access.
    This is the core security control of the Agentic Gatekeeper.
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
        # Dictionary comprehension — only include permitted fields.
        # "if field in record" prevents KeyError for missing fields.

        filtered_record["_similarity_score"] = record.get("_similarity_score", 0)
        filtered.append(filtered_record)

    state["filtered_results"]              = filtered
    state["audit_log"]["decision"]         = "APPROVED"
    state["audit_log"]["records_returned"] = len(filtered)
    state["audit_log"]["fields_exposed"]   = json.dumps(allowed_fields)

    print(f"[RBAC] Showing {len(allowed_fields)} permitted fields for role '{role}'.")
    return state


def node_human_review(state: AgentState) -> AgentState:
    """
    HITL GATE: Pauses pipeline if sensitive fields are in the results.
    Human reviewer approves or rejects before results are released.
    Satisfies IMDA 2026 Meaningful Human Control requirement.
    """

    if state.get("error"):
        return state

    # Check which sensitive fields are in the results
    fields_in_results = {
        key
        for record in state["filtered_results"]
        for key in record.keys()
        if not key.startswith("_")
    }
    # Set comprehension — collects all field names across all result records.

    triggered_fields = fields_in_results & SENSITIVE_FIELDS
    # Intersection: sensitive fields that are actually present in results.

    if not triggered_fields:
        # No sensitive fields — proceed automatically, no human needed.
        state["hitl_triggered"] = False
        state["hitl_decision"]  = None
        state["audit_log"]["hitl_triggered"] = False
        state["audit_log"]["hitl_decision"]  = "N/A - No sensitive fields"
        print("[HITL] No sensitive fields detected. Proceeding automatically.")
        return state

    # Sensitive fields detected — request human review
    state["hitl_triggered"]              = True
    state["audit_log"]["hitl_triggered"] = True

    print("\n" + "!" * 60)
    print("  !! HUMAN REVIEW REQUIRED -- SENSITIVE DATA DETECTED !!")
    print("!" * 60)
    print("\n  Sensitive fields : " + str(sorted(triggered_fields)))
    print("  Role             : [" + state["user_role"] + "]")
    print("  Query            : \"" + state["query"] + "\"")
    print("  Records pending  : " + str(len(state["filtered_results"])))

    # Show data preview to reviewer
    print("\n  --- DATA PREVIEW (reviewer only) ---")
    for i, record in enumerate(state["filtered_results"], 1):
        print(f"  Record {i}:")
        for key, value in record.items():
            if not key.startswith("_"):
                label = " [SENSITIVE]" if key in SENSITIVE_FIELDS else ""
                print("    " + f"{key:<20}" + ": " + str(value) + label)
        print()
    print("  " + "-" * 40)

    # Wait for human decision
    while True:
        decision = input("\n  APPROVE or REJECT this release? (approve/reject): ").strip().lower()
        if decision in ("approve", "reject"):
            break
        print("  Please type 'approve' or 'reject'.")

    state["hitl_decision"]              = decision
    state["audit_log"]["hitl_decision"] = decision

    if decision == "approve":
        print("\n[HITL] APPROVED by reviewer. Releasing results.")
    else:
        state["error"]                     = "Data release REJECTED by human reviewer."
        state["audit_log"]["decision"]     = "DENIED - Rejected by human reviewer"
        print("\n[HITL] REJECTED by reviewer. Results blocked.")

    return state


def node_output(state: AgentState) -> AgentState:
    """
    OUTPUT NODE: Displays results and saves audit log to BigQuery.
    Every query — approved or denied — is permanently recorded.
    """

    print("\n" + "=" * 60)

    if state.get("error"):
        print(f"  ACCESS DENIED: {state['error']}")
        state["audit_log"]["decision"] = state["audit_log"].get("decision") or "DENIED"
        state["audit_log"]["error"]    = state["error"]
    else:
        results = state["filtered_results"]
        print(f"  Results for [{state['user_role']}] — {len(results)} record(s):\n")

        for i, record in enumerate(results, 1):
            print(f"  Record {i}:")
            for key, value in record.items():
                if not key.startswith("_"):
                    print(f"    {key:<20}: {value}")
            print(f"    {'similarity_score':<20}: {record.get('_similarity_score', 'N/A')}")
            print()

    print("=" * 60)

    # Save audit log to BigQuery
    audit_row = {
        "timestamp":        state["audit_log"].get("timestamp"),
        "user_role":        state["audit_log"].get("user_role"),
        "query":            state["audit_log"].get("query"),
        "decision":         state["audit_log"].get("decision"),
        "records_returned": state["audit_log"].get("records_returned", 0),
        "fields_exposed":   state["audit_log"].get("fields_exposed", "[]"),
        "hitl_triggered":   state["audit_log"].get("hitl_triggered", False),
        "hitl_decision":    state["audit_log"].get("hitl_decision"),
        "error":            state["audit_log"].get("error"),
    }

    errors = bq_client.insert_rows_json(
        f"{PROJECT_ID}.{DATASET_ID}.{AUDIT_TABLE}", [audit_row]
    )

    if errors:
        print(f"[AUDIT] Warning — could not save audit log: {errors}")
    else:
        print(f"[AUDIT] Audit log saved to BigQuery ({AUDIT_TABLE}).\n")

    return state


# =============================================================================
# SECTION 6: ROUTING LOGIC
# =============================================================================

def route_after_validation(state: AgentState) -> str:
    """Routes to embed_query on success, or output on role error."""
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
    print("  AGENTIC ETL GATEKEEPER")
    print("  Gemini 2.5 Flash + BigQuery + RBAC + HITL")
    print("  IMDA 2026 Compliant | PDPA Singapore")
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

    initial_state: AgentState = {
        "user_role":        user_role,
        "query":            user_query,
        "query_embedding":  [],
        "raw_results":      [],
        "filtered_results": [],
        "audit_log":        {},
        "error":            None,
        "hitl_triggered":   False,
        "hitl_decision":    None,
    }

    app.invoke(initial_state)
    print("[DONE] Pipeline complete.")
