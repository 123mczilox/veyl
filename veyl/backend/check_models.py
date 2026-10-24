import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("GEMINI_API_KEY is missing from .env")

client = genai.Client(api_key=api_key)

print("Checking available Gemma models...\n")

for model in client.models.list():
    if "gemma" in model.name.lower():
        print(model.name)