# Import required libraries
from dotenv import load_dotenv
import os

# This "loads" the .env file - reads it and makes variables available
load_dotenv()

# Now "get" the token from environment variables
token = os.getenv('HF_TOKEN')

# Check if it worked
if token:
    print("✅ Token loaded successfully!")
    print(f"Token starts with: {token[:10]}...")  # Show first 10 characters
    print(f"Token length: {len(token)} characters")
else:
    print("❌ Token not found! Check your .env file")