# =============================================================================
# processor.py  — v1.0
# Phase 1: Data Governance & Ingestion
#
# WHAT THIS FILE DOES:
# Reads your Excel file and stores each row into BigQuery (Google Cloud).
# Uses Gemini (via Google AI Studio) to generate embeddings for AI search.
#
# TECH STACK:
#   google-genai     — new official Gemini library (replaces generativeai)
#   google-cloud-bigquery — stores data in Singapore (PDPA compliant)
#   gemini-embedding-001  — converts text to numbers for semantic search
#
# v1.0 CHANGES FROM v0.9:
#   [FIX 2] try/except — all Gemini and BigQuery API calls wrapped
#   [FIX 8] Embedding dimension comment corrected (768 → 3072)
#   [FIX 9] access_* fields removed from employee schema — unused by RBAC logic
#           RBAC is enforced entirely by ROLE_PERMISSIONS in main.py.
#           Storing these flags in BigQuery served no function and added confusion.
#
# RUN ORDER:
#   1. python processor.py   (loads data into BigQuery)
#   2. python main.py        (runs the agent)
# =============================================================================


# --- IMPORTS ---

import os
import json
import pandas as pd
from dotenv import load_dotenv
from google import genai
from google.cloud import bigquery


# =============================================================================
# CONFIGURATION
# All project settings in one place — change here, applies everywhere.
# =============================================================================

load_dotenv()

API_KEY     = os.getenv("GOOGLE_API_KEY")
# Reads your Gemini API key from the .env file.
# Never hardcode API keys directly in your code — always use .env.

PROJECT_ID  = "secure-rag-sg"
# Your Google Cloud project ID where BigQuery lives.

REGION      = "asia-southeast1"
# Singapore region — satisfies PDPA data residency requirement.
# All data is physically stored in Singapore Google data centres.

DATASET_ID  = "secure_rag"
# The BigQuery dataset name (like a folder that holds tables).

TABLE_ID    = "employee_data"
# The BigQuery table that stores raw employee records.

EMBED_TABLE = "employee_embeddings"
# The BigQuery table that stores Gemini embeddings for each record.

EMBED_MODEL = "gemini-embedding-001"
# The Gemini embedding model — converts text into 3072 numbers.
# [FIX 8] Corrected from 768 to 3072 — gemini-embedding-001 produces 3072 dimensions.
# IMPORTANT: Must match the model used in main.py — otherwise search breaks.


# =============================================================================
# SENSITIVE FIELDS — SECURITY CLASSIFICATION
# Fields listed here are restricted — only shown to permitted roles.
# This list must match the SENSITIVE_FIELDS in main.py.
# =============================================================================

SENSITIVE_FIELDS = {"nric", "ethnicity", "medical_info", "financial_info", "criminal_record"}
# A Python set of field names classified as sensitive under PDPA.
#
# Note on criminal_record: This field is stored in BigQuery but intentionally
# excluded from all role permission sets in ROLE_PERMISSIONS (main.py).
# No role currently has access to it. Formal access policy will be documented
# in the System Card (v1.4).


# =============================================================================
# STEP 1: INITIALISE CONNECTIONS
# =============================================================================

def init_connections():
    """
    Connects to Gemini (AI Studio) and BigQuery.
    Returns both client objects for use in other functions.
    [FIX 2] Wrapped in try/except — connection failures are caught cleanly.
    """

    print("[INIT] Connecting to Gemini and BigQuery...")

    try:
        gemini_client = genai.Client(api_key=API_KEY)
    except Exception as e:
        print(f"[INIT] FATAL — Could not connect to Gemini: {e}")
        raise SystemExit(1)

    try:
        bq_client = bigquery.Client(project=PROJECT_ID)
    except Exception as e:
        print(f"[INIT] FATAL — Could not connect to BigQuery: {e}")
        raise SystemExit(1)

    print(f"[INIT] Connected to Gemini model  : {EMBED_MODEL}")
    print(f"[INIT] Connected to BigQuery      : {PROJECT_ID}")
    print(f"[INIT] Data region                : {REGION} (Singapore - PDPA compliant)\n")

    return gemini_client, bq_client


# =============================================================================
# STEP 2: SET UP BIGQUERY DATASET AND TABLES
# =============================================================================

def setup_bigquery(bq_client):
    """
    Creates the BigQuery dataset and two tables if they don't already exist.
    Safe to run multiple times — won't overwrite existing structure.
    [FIX 9] access_* fields removed from employee schema — unused by RBAC logic.
    """

    print("[SETUP] Setting up BigQuery dataset and tables...")

    # --- CREATE DATASET ---
    try:
        dataset_ref          = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
        dataset_ref.location = REGION
        bq_client.create_dataset(dataset_ref, exists_ok=True)
        print(f"[SETUP] Dataset '{DATASET_ID}' ready in {REGION}.")
    except Exception as e:
        print(f"[SETUP] Warning — dataset creation issue: {e}")

    # --- EMPLOYEE DATA TABLE SCHEMA ---
    # [FIX 9] access_general, access_hr, access_finance, access_medical removed.
    # These flags were stored as strings ("true") but never read by the RBAC logic.
    # RBAC is enforced entirely by ROLE_PERMISSIONS in main.py — not by these flags.
    # Removing them avoids confusion and keeps the schema clean.

    employee_schema = [
        bigquery.SchemaField("nric",            "STRING", mode="REQUIRED"),
        # Unique identifier — cannot be empty (REQUIRED).

        bigquery.SchemaField("name",            "STRING", mode="NULLABLE"),
        bigquery.SchemaField("employment",      "STRING", mode="NULLABLE"),

        bigquery.SchemaField("ethnicity",       "STRING", mode="NULLABLE"),
        # Sensitive PII — HR_Admin only.

        bigquery.SchemaField("medical_info",    "STRING", mode="NULLABLE"),
        # Sensitive — Medical_Lead only.

        bigquery.SchemaField("financial_info",  "STRING", mode="NULLABLE"),
        # Sensitive — Finance_Lead only.

        bigquery.SchemaField("criminal_record", "STRING", mode="NULLABLE"),
        # Sensitive — no role currently permitted. See SENSITIVE_FIELDS note above.
    ]

    # --- EMBEDDINGS TABLE SCHEMA ---
    # Stores the Gemini-generated embedding for each employee record.

    embedding_schema = [
        bigquery.SchemaField("nric",      "STRING", mode="REQUIRED"),
        # Links this embedding to the employee record in the main table.

        bigquery.SchemaField("content",   "STRING", mode="NULLABLE"),
        # The original text that was embedded (name + employment only).
        # Sensitive fields are deliberately excluded from embeddings to prevent
        # information leakage through semantic search. See README for rationale.

        bigquery.SchemaField("embedding", "STRING", mode="NULLABLE"),
        # The embedding stored as a JSON string: "[0.123, -0.456, ...]"
        # [FIX 8] 3072 numbers representing the semantic meaning of the content.
    ]

    # --- CREATE BOTH TABLES ---
    for table_name, schema in [(TABLE_ID, employee_schema), (EMBED_TABLE, embedding_schema)]:
        try:
            table_ref = bigquery.Table(f"{PROJECT_ID}.{DATASET_ID}.{table_name}", schema=schema)
            bq_client.create_table(table_ref, exists_ok=True)
            print(f"[SETUP] Table '{table_name}' ready.")
        except Exception as e:
            print(f"[SETUP] Warning — table creation issue for '{table_name}': {e}")

    print("[SETUP] BigQuery setup complete.\n")


# =============================================================================
# STEP 3: GENERATE GEMINI EMBEDDING
# =============================================================================

def generate_embedding(gemini_client, text):
    """
    Converts a text string into a Gemini embedding vector.
    Returns a list of 3072 decimal numbers representing the text's meaning.
    [FIX 8] Corrected from 768 to 3072.
    [FIX 2] Wrapped in try/except — API failures are caught and re-raised clearly.
    """

    try:
        result = gemini_client.models.embed_content(
            model=EMBED_MODEL,
            contents=text
        )
        return result.embeddings[0].values

    except Exception as e:
        raise RuntimeError(f"Embedding generation failed for text '{text[:50]}...': {e}")


# =============================================================================
# STEP 4: MAIN INGESTION FUNCTION
# =============================================================================

def ingest_data(file_path):
    """
    Full ingestion pipeline:
    1. Connect to Gemini and BigQuery
    2. Set up BigQuery tables
    3. Read Excel data
    4. Generate Gemini embeddings per row
    5. Insert data and embeddings into BigQuery
    """

    # --- CONNECT ---
    gemini_client, bq_client = init_connections()

    # --- SET UP BIGQUERY ---
    setup_bigquery(bq_client)

    # --- LOAD EXCEL ---
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found at: {file_path}")

    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        raise RuntimeError(f"Could not read Excel file: {e}")

    print(f"[INGEST] Loaded {len(df)} rows from Excel.")
    print("[INGEST] Clearing existing BigQuery data...")

    # --- CLEAR EXISTING DATA ---
    for table_name in [TABLE_ID, EMBED_TABLE]:
        try:
            bq_client.query(
                f"DELETE FROM `{PROJECT_ID}.{DATASET_ID}.{table_name}` WHERE TRUE"
            ).result()
        except Exception as e:
            print(f"[INGEST] Warning — could not clear table '{table_name}': {e}")

    print("[INGEST] Tables cleared. Processing rows...\n")

    # --- PROCESS EACH ROW ---
    employee_rows  = []
    embedding_rows = []
    skipped        = 0
    embed_errors   = 0

    for _, row in df.iterrows():

        # Validate NRIC
        nric = str(row.get("NRIC", "")).strip()
        if not nric or nric.lower() == "nan":
            print(f"  [SKIP] Missing NRIC: {row.get('Name', 'Unknown')}")
            skipped += 1
            continue

        # Read all fields
        name            = str(row.get("Name",            "N/A")).strip()
        employment      = str(row.get("Employment",      "N/A")).strip()
        ethnicity       = str(row.get("Ethnicity",       "N/A")).strip()
        medical_info    = str(row.get("Medical_Info",    "N/A")).strip()
        financial_info  = str(row.get("Financial_Info",  "N/A")).strip()
        criminal_record = str(row.get("Criminal_Record", "N/A")).strip()

        # [FIX 9] access_* fields removed — no longer stored in BigQuery.
        employee_rows.append({
            "nric":             nric,
            "name":             name,
            "employment":       employment,
            "ethnicity":        ethnicity,
            "medical_info":     medical_info,
            "financial_info":   financial_info,
            "criminal_record":  criminal_record,
        })

        # Generate Gemini embedding for non-sensitive content only.
        # Sensitive fields are deliberately excluded — see README for rationale.
        content = f"Name: {name}, Employment: {employment}"

        try:
            embedding_vector = generate_embedding(gemini_client, content)
            embedding_rows.append({
                "nric":      nric,
                "content":   content,
                "embedding": json.dumps(embedding_vector),
            })
            print(f"  [OK] Processed: {name} ({nric})")

        except RuntimeError as e:
            # [FIX 2] Embedding failure for one row does not crash the whole ingestion.
            print(f"  [WARN] Embedding failed for {name} ({nric}): {e}")
            embed_errors += 1

    # --- BATCH INSERT INTO BIGQUERY ---
    print(f"\n[INGEST] Inserting {len(employee_rows)} records into BigQuery...")

    try:
        errors = bq_client.insert_rows_json(f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}", employee_rows)
        if errors:
            print(f"[ERROR] Employee table insert errors: {errors}")
        else:
            print(f"[OK] Employee data inserted.")
    except Exception as e:
        print(f"[ERROR] Employee table insert failed: {e}")

    try:
        errors = bq_client.insert_rows_json(f"{PROJECT_ID}.{DATASET_ID}.{EMBED_TABLE}", embedding_rows)
        if errors:
            print(f"[ERROR] Embeddings table insert errors: {errors}")
        else:
            print(f"[OK] Embeddings inserted.")
    except Exception as e:
        print(f"[ERROR] Embeddings table insert failed: {e}")

    # --- SUMMARY ---
    print(f"\n{'='*60}")
    print(f"  INGESTION COMPLETE")
    print(f"{'='*60}")
    print(f"  Records stored   : {len(employee_rows)}")
    print(f"  Embeddings stored: {len(embedding_rows)}")
    print(f"  Records skipped  : {skipped}")
    print(f"  Embed errors     : {embed_errors}")
    print(f"  Project          : {PROJECT_ID}")
    print(f"  Dataset          : {DATASET_ID}")
    print(f"  Region           : {REGION} (Singapore — PDPA compliant)")
    print(f"  Embedding model  : {EMBED_MODEL} (3072 dimensions)")
    print(f"{'='*60}\n")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    BASE_DIR  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    file_path = os.path.join(BASE_DIR, "data", "raw", "f_data.xlsx")

    print(f"{'='*60}")
    print(f"  AGENTIC ETL — PROCESSOR v1.0")
    print(f"  Gemini Embeddings + BigQuery Storage")
    print(f"{'='*60}")
    print(f"  Source: {file_path}\n")

    ingest_data(file_path)
