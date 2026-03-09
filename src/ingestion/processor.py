# =============================================================================
# processor.py  — FINAL VERSION
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
# RUN ORDER:
#   1. python processor.py   (loads data into BigQuery)
#   2. python main.py        (runs the agent)
# =============================================================================


# --- IMPORTS ---

import os
# os: File system access and reading environment variables.

import json
# json: Converts Python lists/dicts to JSON strings for BigQuery storage.

import pandas as pd
# pandas: Reads your Excel file into a table (DataFrame).

from dotenv import load_dotenv
# dotenv: Reads your .env file to load GOOGLE_API_KEY safely.

from google import genai
# genai: The new official Google Gemini library (google-genai package).
# This replaces the deprecated google.generativeai package.

from google.cloud import bigquery
# bigquery: Google Cloud library for creating tables and inserting data.


# =============================================================================
# CONFIGURATION
# All project settings in one place — change here, applies everywhere.
# =============================================================================

load_dotenv()
# Load environment variables from .env before anything else.

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
# The Gemini embedding model — converts text into 768 numbers.
# This is Google's latest and most capable embedding model.
# IMPORTANT: Must match the model used in main.py — otherwise search breaks.


# =============================================================================
# SENSITIVE FIELDS — SECURITY CLASSIFICATION
# Fields listed here are restricted — only shown to permitted roles.
# This list must match the SENSITIVE_FIELDS in main.py.
# =============================================================================

SENSITIVE_FIELDS = {"nric", "ethnicity", "medical_info", "financial_info", "criminal_record"}
# A Python set of field names classified as sensitive under PDPA.


# =============================================================================
# STEP 1: INITIALISE CONNECTIONS
# =============================================================================

def init_connections():
    """
    Connects to Gemini (AI Studio) and BigQuery.
    Returns both client objects for use in other functions.
    """

    print("[INIT] Connecting to Gemini and BigQuery...")

    # Connect to Gemini via AI Studio API key
    gemini_client = genai.Client(api_key=API_KEY)
    # genai.Client() creates a connection to Gemini using your API key.
    # This is the new way — replaces the old configure() + GenerativeModel() pattern.

    # Connect to BigQuery using Application Default Credentials (gcloud auth)
    bq_client = bigquery.Client(project=PROJECT_ID)
    # bigquery.Client() connects to BigQuery using your gcloud credentials.
    # No API key needed here — gcloud auth handles authentication automatically.

    print(f"[INIT] Connected to Gemini model  : {EMBED_MODEL}")
    print(f"[INIT] Connected to BigQuery      : {PROJECT_ID}")
    print(f"[INIT] Data region                : {REGION} (Singapore - PDPA compliant)\n")

    return gemini_client, bq_client
    # Return both clients so other functions can use them.


# =============================================================================
# STEP 2: SET UP BIGQUERY DATASET AND TABLES
# =============================================================================

def setup_bigquery(bq_client):
    """
    Creates the BigQuery dataset and two tables if they don't already exist.
    Safe to run multiple times — won't overwrite existing structure.
    """

    print("[SETUP] Setting up BigQuery dataset and tables...")

    # --- CREATE DATASET ---
    dataset_ref          = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
    # Reference to the dataset using format: project_id.dataset_id

    dataset_ref.location = REGION
    # Set physical location to Singapore for PDPA compliance.

    bq_client.create_dataset(dataset_ref, exists_ok=True)
    # Create the dataset. exists_ok=True = don't crash if already exists.

    print(f"[SETUP] Dataset '{DATASET_ID}' ready in {REGION}.")

    # --- EMPLOYEE DATA TABLE SCHEMA ---
    # Defines the columns of the employee_data table.
    # Each SchemaField = one column with a name, type, and mode.

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
        # Sensitive — restricted access.

        bigquery.SchemaField("access_general",  "STRING", mode="NULLABLE"),
        bigquery.SchemaField("access_hr",       "STRING", mode="NULLABLE"),
        bigquery.SchemaField("access_finance",  "STRING", mode="NULLABLE"),
        bigquery.SchemaField("access_medical",  "STRING", mode="NULLABLE"),
        # Access control flags used by the RBAC node in main.py.
    ]

    # --- EMBEDDINGS TABLE SCHEMA ---
    # Stores the Gemini-generated embedding for each employee record.

    embedding_schema = [
        bigquery.SchemaField("nric",      "STRING", mode="REQUIRED"),
        # Links this embedding to the employee record in the main table.

        bigquery.SchemaField("content",   "STRING", mode="NULLABLE"),
        # The original text that was embedded (name + employment).

        bigquery.SchemaField("embedding", "STRING", mode="NULLABLE"),
        # The embedding stored as a JSON string: "[0.123, -0.456, ...]"
        # 768 numbers representing the semantic meaning of the content.
    ]

    # --- CREATE BOTH TABLES ---
    for table_name, schema in [(TABLE_ID, employee_schema), (EMBED_TABLE, embedding_schema)]:
        # Loop through both table definitions and create each one.

        table_ref = bigquery.Table(f"{PROJECT_ID}.{DATASET_ID}.{table_name}", schema=schema)
        bq_client.create_table(table_ref, exists_ok=True)
        # Create the table — exists_ok=True prevents crash if already exists.

        print(f"[SETUP] Table '{table_name}' ready.")

    print("[SETUP] BigQuery setup complete.\n")


# =============================================================================
# STEP 3: GENERATE GEMINI EMBEDDING
# =============================================================================

def generate_embedding(gemini_client, text):
    """
    Converts a text string into a Gemini embedding vector.
    Returns a list of 768 decimal numbers representing the text's meaning.
    """

    result = gemini_client.models.embed_content(
        model=EMBED_MODEL,
        contents=text
        # Send the text to Gemini's embedding model.
        # "embed_content" is the new API method in the google-genai library.
    )

    return result.embeddings[0].values
    # result.embeddings = list of embedding objects (one per input text).
    # [0] = the first (and only) embedding result.
    # .values = the actual list of 768 numbers.


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

    df = pd.read_excel(file_path)
    print(f"[INGEST] Loaded {len(df)} rows from Excel.")
    print("[INGEST] Clearing existing BigQuery data...")

    # --- CLEAR EXISTING DATA ---
    # Wipe both tables before re-inserting to avoid duplicate records.
    for table_name in [TABLE_ID, EMBED_TABLE]:
        bq_client.query(
            f"DELETE FROM `{PROJECT_ID}.{DATASET_ID}.{table_name}` WHERE TRUE"
        ).result()
        # DELETE WHERE TRUE removes all rows.
        # .result() waits for the delete to complete before moving on.

    print("[INGEST] Tables cleared. Processing rows...\n")

    # --- PROCESS EACH ROW ---
    employee_rows  = []
    # Batch list for employee data rows.

    embedding_rows = []
    # Batch list for embedding rows.

    skipped = 0
    # Counter for skipped rows (missing NRIC).

    for _, row in df.iterrows():
        # Loop through every row in the DataFrame.

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

        # Build employee row matching the BigQuery schema
        employee_rows.append({
            "nric":             nric,
            "name":             name,
            "employment":       employment,
            "ethnicity":        ethnicity,
            "medical_info":     medical_info,
            "financial_info":   financial_info,
            "criminal_record":  criminal_record,
            "access_general":   "true",
            "access_hr":        "true",
            "access_finance":   "true",
            "access_medical":   "true",
        })

        # Generate Gemini embedding for non-sensitive content only
        content = f"Name: {name}, Employment: {employment}"
        # We only embed name and employment — sensitive fields stay in
        # the employee_data table and are filtered by RBAC in main.py.

        embedding_vector = generate_embedding(gemini_client, content)
        # Call Gemini to convert content text into 768 numbers.

        embedding_rows.append({
            "nric":      nric,
            "content":   content,
            "embedding": json.dumps(embedding_vector),
            # json.dumps() converts [0.1, 0.2, ...] to "[0.1, 0.2, ...]"
            # for storage as a string in BigQuery.
        })

        print(f"  [OK] Processed: {name} ({nric})")

    # --- BATCH INSERT INTO BIGQUERY ---
    print(f"\n[INGEST] Inserting {len(employee_rows)} records into BigQuery...")

    errors = bq_client.insert_rows_json(f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}", employee_rows)
    if errors:
        print(f"[ERROR] Employee table: {errors}")
    else:
        print(f"[OK] Employee data inserted.")

    errors = bq_client.insert_rows_json(f"{PROJECT_ID}.{DATASET_ID}.{EMBED_TABLE}", embedding_rows)
    if errors:
        print(f"[ERROR] Embeddings table: {errors}")
    else:
        print(f"[OK] Embeddings inserted.")

    # --- SUMMARY ---
    print(f"\n{'='*60}")
    print(f"  INGESTION COMPLETE")
    print(f"{'='*60}")
    print(f"  Records stored : {len(employee_rows)}")
    print(f"  Records skipped: {skipped}")
    print(f"  Project        : {PROJECT_ID}")
    print(f"  Dataset        : {DATASET_ID}")
    print(f"  Region         : {REGION} (Singapore — PDPA compliant)")
    print(f"  Embedding model: {EMBED_MODEL}")
    print(f"{'='*60}\n")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Navigate up from src/ingestion/ to project root, then into data/raw/
    BASE_DIR  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    file_path = os.path.join(BASE_DIR, "data", "raw", "f_data.xlsx")

    print(f"{'='*60}")
    print(f"  AGENTIC ETL — PROCESSOR")
    print(f"  Gemini Embeddings + BigQuery Storage")
    print(f"{'='*60}")
    print(f"  Source: {file_path}\n")

    ingest_data(file_path)
