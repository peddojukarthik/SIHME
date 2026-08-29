"""
INVITE BACKEND — v4: real authentication + department scoping.

WHAT CHANGED FROM v3:
  - New: POST /login — a head must authenticate before doing anything
  - /employees/search and /invite now REQUIRE a valid session token
    (sent as: Authorization: Bearer <token>)
  - Search/invite are scoped to the LOGGED-IN HEAD'S OWN DEPARTMENT ONLY
    - a Bengaluru account can no longer see/invite Hyderabad FSL staff
  - Every invited account now records invited_by = the head's user_id

Install:  pip install fastapi uvicorn supabase python-dotenv bcrypt
Run:      python3 invite_backend_v4.py
"""

import os
import secrets
import hashlib
import smtplib
import bcrypt
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Header
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

supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])
GMAIL_ADDRESS = os.environ["GMAIL_ADDRESS"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]
BASE_URL = "http://localhost:8000"

SESSION_LIFETIME_HOURS = 8


# ------------------------------------------------------------------
# AUTH HELPER — every protected endpoint calls this to identify
# who's making the request, and rejects the request if it can't.
# ------------------------------------------------------------------
def get_current_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not logged in. Include your session token.")

    raw_token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    session_result = (
        supabase.table("sessions")
        .select("user_id, expires_at")
        .eq("token_hash", token_hash)
        .execute()
    )
    if not session_result.data:
        raise HTTPException(status_code=401, detail="Invalid session. Please log in again.")

    session = session_result.data[0]
    if datetime.now(timezone.utc) > datetime.fromisoformat(session["expires_at"]):
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    # Get the user's own department, via employee_registry
    user_result = (
        supabase.table("users")
        .select("user_id, employee_id, account_status, employee_registry(full_name, department_id)")
        .eq("user_id", session["user_id"])
        .execute()
    )
    if not user_result.data:
        raise HTTPException(status_code=401, detail="User not found.")

    user = user_result.data[0]
    return {
        "user_id": user["user_id"],
        "full_name": user["employee_registry"]["full_name"],
        "department_id": user["employee_registry"]["department_id"],
    }


# ------------------------------------------------------------------
# LOGIN
# ------------------------------------------------------------------
class LoginRequest(BaseModel):
    employee_id: str
    password: str


@app.post("/login")
def login(req: LoginRequest):
    user_result = (
        supabase.table("users")
        .select("user_id, password_hash, account_status")
        .eq("employee_id", req.employee_id)
        .execute()
    )
    if not user_result.data:
        raise HTTPException(status_code=401, detail="Invalid employee ID or password.")

    user = user_result.data[0]

    if not user["password_hash"] or not bcrypt.checkpw(req.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid employee ID or password.")

    if user["account_status"] not in ("activated", "profile_pending", "active"):
        raise HTTPException(status_code=403, detail=f"Account not usable yet (status: {user['account_status']}).")

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_LIFETIME_HOURS)).isoformat()

    supabase.table("sessions").insert({
        "user_id": user["user_id"],
        "token_hash": token_hash,
        "expires_at": expires_at,
    }).execute()

    return {"token": raw_token, "expires_in_hours": SESSION_LIFETIME_HOURS}


# ------------------------------------------------------------------
# SEARCH — now requires login, scoped to the caller's OWN department
# ------------------------------------------------------------------
@app.get("/employees/search")
def search_employees(q: str, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    if not q or len(q) < 2:
        return []

    registry_matches = (
        supabase.table("employee_registry")
        .select("employee_id, full_name, official_email, rank, department_id, departments(name)")
        .eq("department_id", current_user["department_id"])   # <-- THE SCOPING FIX
        .or_(f"full_name.ilike.%{q}%,employee_id.ilike.%{q}%")
        .execute()
    )
    if not registry_matches.data:
        return []

    candidate_ids = [row["employee_id"] for row in registry_matches.data]
    existing_users = supabase.table("users").select("employee_id").in_("employee_id", candidate_ids).execute()
    already_has_account = {row["employee_id"] for row in existing_users.data}

    return [row for row in registry_matches.data if row["employee_id"] not in already_has_account]


# ------------------------------------------------------------------
# INVITE — now requires login, checks department match, records invited_by
# ------------------------------------------------------------------
class InviteRequest(BaseModel):
    employee_id: str


@app.post("/invite")
def invite(req: InviteRequest, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    registry_result = (
        supabase.table("employee_registry")
        .select("employee_id, full_name, official_email, department_id")
        .eq("employee_id", req.employee_id)
        .execute()
    )
    if not registry_result.data:
        raise HTTPException(status_code=404, detail="No such employee found in the government registry.")

    employee = registry_result.data[0]

    # THE SCOPING FIX — can't invite someone outside your own department
    if employee["department_id"] != current_user["department_id"]:
        raise HTTPException(
            status_code=403,
            detail=f"You can only invite employees in your own department. "
                   f"{employee['full_name']} belongs to a different department.",
        )

    existing = supabase.table("users").select("user_id").eq("employee_id", req.employee_id).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="This employee already has an account.")

    user_result = supabase.table("users").insert({
        "employee_id": req.employee_id,
        "account_status": "credentials_issued",
        "invited_by": current_user["user_id"],   # <-- THE AUDIT FIX
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

    # IMPORTANT: this must stay a real http:// link, not file:// — Gmail and
    # most webmail clients strip or block file:// links entirely, so an
    # emailed file:// link would arrive dead/unclickable. This route serves
    # your activate.html content over a real URL instead.
    activation_link = f"{BASE_URL}/activate-page?token={raw_token}"

    try:
        send_email(employee["official_email"], employee["full_name"], activation_link)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Account created, but email failed to send: {e}")

    return {
        "message": f"Invitation sent to {employee['full_name']} by {current_user['full_name']}",
        "user_id": user_id,
    }


# ------------------------------------------------------------------
# ACTIVATION (unchanged from v3)
# ------------------------------------------------------------------
@app.get("/activate-page", response_class=HTMLResponse)
def activate_page():
    # Serves your actual activate.html file over a real http:// URL, so it's
    # clickable from email AND stays visually consistent with your other
    # pages. The token is already in the query string (?token=...) - the
    # JS inside activate.html reads it directly from window.location, so
    # nothing needs to be injected here.
    with open("activate.html", "r", encoding="utf-8") as f:
        return f.read()


class ActivateRequest(BaseModel):
    token: str
    password: str


@app.post("/activate")
def activate(req: ActivateRequest):
    token_hash = hashlib.sha256(req.token.encode()).hexdigest()
    token_result = supabase.table("activation_tokens").select("user_id, expires_at, status").eq("token_hash", token_hash).execute()
    if not token_result.data:
        raise HTTPException(status_code=400, detail="Invalid activation link.")
    token_row = token_result.data[0]
    if token_row["status"] != "pending":
        raise HTTPException(status_code=400, detail="This link has already been used.")

    # Keep the tokens table accurate: an expired-but-still-"pending" token
    # gets explicitly marked 'expired' here, rather than silently rejected
    # while looking like it's still awaiting use.
    if datetime.now(timezone.utc) > datetime.fromisoformat(token_row["expires_at"]):
        supabase.table("activation_tokens").update({"status": "expired"}).eq("token_hash", token_hash).execute()
        raise HTTPException(status_code=400, detail="This link has expired. Ask your department head to resend it.")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    password_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    supabase.table("users").update({"password_hash": password_hash, "account_status": "activated"}).eq("user_id", token_row["user_id"]).execute()
    supabase.table("activation_tokens").update({"status": "used"}).eq("token_hash", token_hash).execute()

    return {"message": "Account activated", "account_status": "activated"}


def send_email(to_email: str, full_name: str, activation_link: str):
    body = f"Hi {full_name},\n\nClick to activate your account (valid 72 hours):\n{activation_link}\n"
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