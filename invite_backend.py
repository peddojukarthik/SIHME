"""
INVITE BACKEND — v3, adds real activation.

New in this version:
  GET  /activate-page?token=...  -> serves an HTML page with a password form
  POST /activate                  -> verifies the token, sets the password,
                                      moves account_status to 'activated'

The activation email now links to THIS server directly
(http://localhost:8000/activate-page?token=...) instead of a
placeholder URL, so clicking it actually does something.

Install:  pip install fastapi uvicorn supabase python-dotenv bcrypt
Run:      python3 invite_backend_v3.py
"""

import os
import secrets
import hashlib
import smtplib
import bcrypt
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

supabase = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SERVICE_ROLE_KEY"],
)

GMAIL_ADDRESS = os.environ["GMAIL_ADDRESS"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]

# This is what makes the emailed link actually work locally.
# When you eventually deploy for real, change this to your real domain.
BASE_URL = "http://localhost:8000"


# ------------------------------------------------------------------
# SEARCH (unchanged from v2)
# ------------------------------------------------------------------
@app.get("/employees/search")
def search_employees(q: str):
    if not q or len(q) < 2:
        return []
    registry_matches = (
        supabase.table("employee_registry")
        .select("employee_id, full_name, official_email, rank, department_id, departments(name)")
        .or_(f"full_name.ilike.%{q}%,employee_id.ilike.%{q}%")
        .execute()
    )
    if not registry_matches.data:
        return []
    candidate_ids = [row["employee_id"] for row in registry_matches.data]
    existing_users = supabase.table("users").select("employee_id").in_("employee_id", candidate_ids).execute()
    already_has_account = {row["employee_id"] for row in existing_users.data}
    return [row for row in registry_matches.data if row["employee_id"] not in already_has_account]


class InviteRequest(BaseModel):
    employee_id: str


@app.post("/invite")
def invite(req: InviteRequest):
    registry_result = (
        supabase.table("employee_registry")
        .select("employee_id, full_name, official_email")
        .eq("employee_id", req.employee_id)
        .execute()
    )
    if not registry_result.data:
        raise HTTPException(status_code=404, detail="No such employee found in the government registry.")

    employee = registry_result.data[0]

    existing = supabase.table("users").select("user_id").eq("employee_id", req.employee_id).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="This employee already has an account.")

    user_result = supabase.table("users").insert({
        "employee_id": req.employee_id,
        "account_status": "credentials_issued",   # = "application sent"
    }).execute()
    user_id = user_result.data[0]["user_id"]

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat()

    supabase.table("activation_tokens").insert({
        "user_id": user_id,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "status": "pending",
    }).execute()

    # This now points to a REAL page on this server, not a placeholder URL.
    activation_link = f"{BASE_URL}/activate-page?token={raw_token}"

    send_email(employee["official_email"], employee["full_name"], activation_link)

    return {"message": f"Invitation sent to {employee['full_name']}", "user_id": user_id}


# ------------------------------------------------------------------
# NEW — the page the person actually lands on when they click the link
# ------------------------------------------------------------------
@app.get("/activate-page", response_class=HTMLResponse)
def activate_page(token: str):
    return f"""
    <html><body style="font-family:sans-serif; max-width:400px; margin:60px auto;">
    <h2>Activate Your Account</h2>
    <p>Set a password to activate your account.</p>
    <form id="f">
        <input type="password" id="password" placeholder="New password" required
               style="width:100%; padding:10px; margin-top:10px;" />
        <button type="submit" style="margin-top:14px; padding:10px 16px; background:#2563eb; color:white; border:none; border-radius:6px;">
            Activate
        </button>
    </form>
    <p id="result" style="margin-top:16px;"></p>
    <script>
        document.getElementById('f').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const password = document.getElementById('password').value;
            const res = await fetch('/activate', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{ token: "{token}", password }}),
            }});
            const data = await res.json();
            document.getElementById('result').textContent =
                res.ok ? "Activated! Status is now: " + data.account_status : "Error: " + data.detail;
        }});
    </script>
    </body></html>
    """


class ActivateRequest(BaseModel):
    token: str
    password: str


@app.post("/activate")
def activate(req: ActivateRequest):
    token_hash = hashlib.sha256(req.token.encode()).hexdigest()

    token_result = (
        supabase.table("activation_tokens")
        .select("user_id, expires_at, status")
        .eq("token_hash", token_hash)
        .execute()
    )
    if not token_result.data:
        raise HTTPException(status_code=400, detail="Invalid activation link.")

    token_row = token_result.data[0]
    if token_row["status"] != "pending":
        raise HTTPException(status_code=400, detail="This link has already been used.")

    expires_at = datetime.fromisoformat(token_row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=400, detail="This link has expired.")

    password_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()

    supabase.table("users").update({
        "password_hash": password_hash,
        "account_status": "activated",   # <-- the status change you're testing for
    }).eq("user_id", token_row["user_id"]).execute()

    supabase.table("activation_tokens").update({"status": "used"}).eq("token_hash", token_hash).execute()

    return {"message": "Account activated", "account_status": "activated"}


def send_email(to_email: str, full_name: str, activation_link: str):
    body = f"""Hi {full_name},

Click the link below to activate your account (valid for 72 hours):

{activation_link}
"""
    msg = MIMEText(body)
    msg["Subject"] = "Activate your Secure DMS account"
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_ADDRESS, [to_email], msg.as_string())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)