import chromadb
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings

# 1. Connect to the vault
client = chromadb.PersistentClient(path="./chroma_db")
embedding_function = OpenAIEmbeddings()

# 2. Access the collection
db = Chroma(
    collection_name="sme_secure_data",
    persist_directory="./chroma_db",
    embedding_function=embedding_function
)

# 3. Fetch one sample document from the database
sample = db.get(limit=1)

print("--- Database Inspection ---")
print(f"Metadata: {sample['metadatas']}")
print(f"Document Text: {sample['documents']}")