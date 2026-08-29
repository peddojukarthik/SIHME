"""
DECODE THE KEY — shows what project/role your key actually claims to be,
without needing to log in anywhere. Run: python decode_key.py
"""

import os
import json
import base64
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

url = os.environ.get("SUPABASE_URL", "")
key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

# Extract the project ref from the URL, e.g. https://qevwwgummktradbenjpi.supabase.co
url_ref = url.replace("https://", "").replace("http://", "").split(".")[0]

# A JWT is three base64 parts separated by dots: header.payload.signature
# We only need the middle part (payload) to see what it claims.
parts = key.split(".")
if len(parts) != 3:
    print(f"This doesn't look like a valid JWT at all (expected 3 parts, got {len(parts)}).")
    print("Likely the key was cut off or corrupted during copy-paste.")
else:
    payload_b64 = parts[1]
    # base64 needs padding to a multiple of 4 - add back any missing '='
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

    print("=" * 50)
    print(f"URL says project ref:    {url_ref}")
    print(f"KEY says project ref:    {payload.get('ref', 'NOT FOUND')}")
    print(f"MATCH: {'YES' if payload.get('ref') == url_ref else 'NO <-- THIS IS LIKELY THE PROBLEM'}")
    print()
    print(f"KEY role:                {payload.get('role', 'NOT FOUND')}")
    print(f"  (should be 'service_role', not 'anon')")
    print()
    exp = payload.get("exp")
    if exp:
        exp_date = datetime.fromtimestamp(exp)
        print(f"KEY expires:             {exp_date}")
        print(f"  expired already: {'YES <-- PROBLEM' if exp_date < datetime.now() else 'NO, still valid'}")
    print("=" * 50)