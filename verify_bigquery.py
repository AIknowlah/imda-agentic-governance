# verify_bigquery.py
# Checks that data was successfully loaded into BigQuery.
# Run with: python verify_bigquery.py

from google.cloud import bigquery

bq = bigquery.Client(project="secure-rag-sg")

# Check employee data table
rows = list(bq.query("SELECT COUNT(*) as total FROM `secure-rag-sg.secure_rag.employee_data`").result())
print(f"Employee records in BigQuery : {rows[0].total}")

# Check embeddings table
rows = list(bq.query("SELECT COUNT(*) as total FROM `secure-rag-sg.secure_rag.employee_embeddings`").result())
print(f"Embeddings in BigQuery       : {rows[0].total}")

print("\nBigQuery verification complete!")
