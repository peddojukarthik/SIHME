"""
TEST GMAIL LOGIN ONLY — run: python test_gmail_login.py
No Supabase, no FastAPI, no frontend needed. Just checks if
GMAIL_ADDRESS + GMAIL_APP_PASSWORD actually work, in 2 seconds.
"""

import os
import smtplib
from dotenv import load_dotenv

load_dotenv()

GMAIL_ADDRESS = os.environ["GMAIL_ADDRESS"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]

print(f"Trying to log in as: {GMAIL_ADDRESS}")
print(f"App password length: {len(GMAIL_APP_PASSWORD)} characters (should be exactly 16)")
print()

try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
    print("SUCCESS — login worked. The problem is elsewhere, not the Gmail credentials.")
except smtplib.SMTPAuthenticationError as e:
    print("FAILED — Gmail rejected these exact credentials.")
    print(e)
    print()
    print("This means the fix hasn't actually taken effect yet. Double check:")
    print("1. Did you actually generate a NEW app password (not reuse the old one)?")
    print("2. Did you save the .env file after pasting the new one in?")
    print("3. Is there any OTHER .env file elsewhere that might be loading instead?")