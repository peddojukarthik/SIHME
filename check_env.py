"""
DIAGNOSE .ENV — run this FIRST: python3 check_env.py
It won't print your real key, just enough to spot the problem.
"""

import os
from dotenv import load_dotenv

load_dotenv()

url = os.environ.get("SUPABASE_URL", "")
key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

print("=" * 50)
print(f"SUPABASE_URL found:  {'YES' if url else 'NO - MISSING'}")
print(f"  value: {url}")
print()
print(f"SERVICE_ROLE_KEY found: {'YES' if key else 'NO - MISSING'}")
print(f"  length: {len(key)} characters (a real key is usually 200+ chars)")
print(f"  starts with: {key[:15]}...")
print(f"  ends with:   ...{key[-6:]}")
print(f"  has leading/trailing whitespace: {key != key.strip()}")
print(f"  has quote characters in it: {'\"' in key or chr(39) in key}")
print("=" * 50)

# Now actually try connecting, to see the real error directly
try:
    from supabase import create_client
    client = create_client(url, key)
    result = client.table("departments").select("department_id").limit(1).execute()
    print("SUCCESS — connected and queried departments table.")
    print(result.data)
except Exception as e:
    print("FAILED — this is the real error:")
    print(e)