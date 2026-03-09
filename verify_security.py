import chromadb

# 1. Access the database
client = chromadb.PersistentClient(path="./chroma_db")
collection = client.get_collection(name="sme_secure_data")

# 2. Check how many records were ingested
print(f"Total records in the vault: {collection.count()}")

# 3. Simulate a "Staff" role query (General Access)
# We filter where 'department' is 'general'
results = collection.query(
    query_texts=["employee"],
    where={"department": "general"},
    n_results=2
)

print(f"Results for 'general' staff: {results['documents']}")