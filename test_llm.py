from dotenv import load_dotenv
import os
from huggingface_hub import InferenceClient

load_dotenv()

print("🧪 Testing LLM Connection...")

try:
    client = InferenceClient(
        provider="featherless-ai",
        api_key=os.getenv('HF_TOKEN')
    )
    
    result = client.text_generation(
        "What is a firewall?",
        model="fdtn-ai/Foundation-Sec-8B",
        max_new_tokens=50
    )
    
    print("✅ LLM Working!")
    print(f"Response: {result}")
    
except Exception as e:
    print(f"⚠️ LLM Error: {e}")
    print("Don't worry - app will use fallback responses")