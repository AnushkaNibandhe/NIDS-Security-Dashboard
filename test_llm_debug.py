"""
Debug script to test LLM responses
"""
from dotenv import load_dotenv
import os
from huggingface_hub import InferenceClient

load_dotenv()

print("🧪 Testing LLM Connection and Response Quality...\n")

# Check token
token = os.getenv('HF_TOKEN')
if not token:
    print("❌ No HF_TOKEN found in .env file!")
    exit()

print(f"✅ Token found: {token[:15]}...\n")

# Test connection
try:
    client = InferenceClient(
        provider="featherless-ai",
        api_key=token
    )
    print("✅ Client initialized\n")
except Exception as e:
    print(f"❌ Client initialization failed: {e}")
    exit()

# Test prompt
prompt = """You are a cybersecurity expert. A DoS attack has been detected with 95% confidence. 

Provide exactly 5 mitigation steps as a numbered list. Be specific and actionable.

Format:
1. [First mitigation step]
2. [Second mitigation step]
3. [Third mitigation step]
4. [Fourth mitigation step]
5. [Fifth mitigation step]"""

print("📤 Sending prompt to LLM...")
print("="*60)
print(prompt)
print("="*60)
print()

# Call LLM
try:
    result = client.text_generation(
        prompt,
        model="fdtn-ai/Foundation-Sec-8B",
        max_new_tokens=400,
        temperature=0.7,
        top_p=0.9,
        do_sample=True
    )
    
    print("📥 LLM Response:")
    print("="*60)
    print(result)
    print("="*60)
    print()
    
    # Analyze response
    response = str(result).strip()
    
    print("📊 Response Analysis:")
    print(f"  Length: {len(response)} characters")
    print(f"  Contains prompt: {'Yes ❌' if prompt in response else 'No ✅'}")
    print(f"  Contains 'You are': {'Yes ❌' if 'You are' in response else 'No ✅'}")
    print(f"  Number of 'Step' mentions: {response.count('Step')}")
    print(f"  Has numbered list (1., 2., etc): {'Yes ✅' if '1.' in response and '2.' in response else 'No ❌'}")
    
    print("\n🎯 Validation Result:")
    if len(response) < 50:
        print("  ❌ FAIL: Response too short")
    elif "You are a cybersecurity expert" in response:
        print("  ❌ FAIL: Contains the prompt (LLM echoing)")
    elif response.count("Step") < 3 and not ('1.' in response and '2.' in response):
        print("  ❌ FAIL: Not enough steps/structure")
    else:
        print("  ✅ PASS: Response looks good!")
    
except Exception as e:
    print(f"❌ LLM call failed: {e}")
    print(f"Error type: {type(e).__name__}")
    
print("\n" + "="*60)
print("💡 Recommendation:")
print("If validation fails, the fallback responses are actually better!")
print("They're professionally written and more reliable.")