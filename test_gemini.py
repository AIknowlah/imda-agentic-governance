# test_gemini.py
# Quick test to verify your Gemini API key is working correctly.
# Run this with: python test_gemini.py

import os
from dotenv import load_dotenv
from google import genai

# Load your API key from .env file
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

# Check the key was actually loaded
if not api_key:
    print("[ERROR] GOOGLE_API_KEY not found in your .env file.")
    print("        Make sure your .env file contains: GOOGLE_API_KEY=AIzaSy...")
else:
    print(f"[OK] API key loaded: {api_key[:10]}...")
    # Only shows first 10 characters for security

# Connect to Gemini
print("\n[TEST] Connecting to Gemini...")
client = genai.Client(api_key=api_key)

# Send a simple test message
print("[TEST] Sending test message...")
response = client.models.generate_content(
    model="gemini-2.0-flash",
    contents="Say hello in one sentence."
)

print("\n[RESULT] Gemini responded:")
print(response.text)
print("\n[SUCCESS] Gemini connection is working correctly!")
