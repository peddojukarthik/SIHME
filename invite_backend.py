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

"""
INVITE + CASE BACKEND — v8

NEW IN THIS VERSION:
  - /login now returns role info: is_admin, department_type, department_name
    -> this is what the frontend uses to decide WHICH homepage to render
  - /setup-2fa, /verify-2fa — TOTP step-up, required before /invite,
    /case/invite, or the hidden invite pages will do anything
  - /case/create — police-only, files a new case (the "digital FIR")
  - /case/my — lists cases the logged-in user belongs to (for homepage)
  - /case/members — lists a case's members + their document-type access
  - /case/invite — head grants a subordinate access to a specific case,
    with an explicit document-type checklist, requires 2FA elevation

Run:  python3 invite_backend_v8.py
Install: pip install fastapi uvicorn supabase python-dotenv bcrypt pyotp
"""

import os
import secrets
import hashlib
import smtplib
import bcrypt
import pyotp
import mimetypes
import uuid
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client

from document_crypto import (
    calculate_file_hash,
    generate_user_key_pair,
    save_private_key,
    sign_file_hash,
    verify_signature,
)

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
ELEVATION_LIFETIME_MINUTES = 15   # how long a 2FA step-up lasts before re-asking


# ------------------------------------------------------------------
# AUTH HELPER — identifies who's calling, their department/role,
# and whether they've completed the 2FA step-up recently.
# ------------------------------------------------------------------
def get_current_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not logged in. Include your session token.")

    raw_token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    session_result = (
        supabase.table("sessions")
        .select("session_id, user_id, expires_at, elevated_until")
        .eq("token_hash", token_hash)
        .execute()
    )
    if not session_result.data:
        raise HTTPException(status_code=401, detail="Invalid session. Please log in again.")

    session = session_result.data[0]
    if datetime.now(timezone.utc) > datetime.fromisoformat(session["expires_at"]):
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    user_result = (
        supabase.table("users")
        .select("user_id, employee_id, account_status, totp_secret, "
                "employee_registry!fk_users_employee(full_name, department_id, departments(type, name))")
        .eq("user_id", session["user_id"])
        .execute()
    )
    if not user_result.data:
        raise HTTPException(status_code=401, detail="User not found.")

    user = user_result.data[0]
    dept = user["employee_registry"]["departments"]

    admin_check = (
        supabase.table("department_admins")
        .select("can_invite_employees, can_delegate")
        .eq("user_id", user["user_id"])
        .eq("department_id", user["employee_registry"]["department_id"])
        .execute()
    )
    is_admin = bool(admin_check.data)

    is_elevated = False
    if session["elevated_until"]:
        is_elevated = datetime.now(timezone.utc) < datetime.fromisoformat(session["elevated_until"])

    return {
        "user_id": user["user_id"],
        "session_id": session["session_id"],
        "full_name": user["employee_registry"]["full_name"],
        "department_id": user["employee_registry"]["department_id"],
        "department_type": dept["type"],
        "department_name": dept["name"],
        "is_admin": is_admin,
        "has_2fa": bool(user["totp_secret"]),
        "is_elevated": is_elevated,
    }


def require_elevation(current_user):
    """Call this at the top of any sensitive admin action (invite, case grant)."""
    if not current_user["is_elevated"]:
        raise HTTPException(
            status_code=403,
            detail="This action requires 2FA verification. Call /verify-2fa first.",
        )


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
        .select("user_id, password_hash, account_status, totp_secret, "
                "employee_registry!fk_users_employee(full_name, department_id, departments(type, name))")
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

    dept_id = user["employee_registry"]["department_id"]
    admin_check = (
        supabase.table("department_admins")
        .select("admin_id")
        .eq("user_id", user["user_id"])
        .eq("department_id", dept_id)
        .execute()
    )

    # THIS IS WHAT THE FRONTEND USES TO PICK WHICH HOMEPAGE TO SHOW:
    # - account_status = 'activated' or 'profile_pending' -> profile form, not homepage
    # - is_admin + department_type='police' -> police HEAD homepage
    # - not is_admin + department_type='police' -> ordinary police officer homepage
    # - department_type != 'police' -> other-department officer homepage
    return {
        "token": raw_token,
        "expires_in_hours": SESSION_LIFETIME_HOURS,
        "account_status": user["account_status"],
        "full_name": user["employee_registry"]["full_name"],
        "department_type": user["employee_registry"]["departments"]["type"],
        "department_name": user["employee_registry"]["departments"]["name"],
        "is_admin": bool(admin_check.data),
        "has_2fa": bool(user["totp_secret"]),
    }


# ------------------------------------------------------------------
# 2FA SETUP — one-time enrollment. Returns a secret to add to an
# authenticator app (Google Authenticator, Authy, etc).
# ------------------------------------------------------------------
@app.post("/setup-2fa")
def setup_2fa(authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    if current_user["has_2fa"]:
        raise HTTPException(status_code=400, detail="2FA is already set up for this account.")

    secret = pyotp.random_base32()
    supabase.table("users").update({"totp_secret": secret}).eq("user_id", current_user["user_id"]).execute()

    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user["full_name"], issuer_name="Secure DMS"
    )
    return {"secret": secret, "otpauth_url": otpauth_url}


# ------------------------------------------------------------------
# 2FA VERIFY — the actual step-up check. On success, elevates the
# CURRENT SESSION for ELEVATION_LIFETIME_MINUTES, after which
# sensitive actions will ask for a fresh code again.
# ------------------------------------------------------------------
class Verify2FARequest(BaseModel):
    code: str


@app.post("/verify-2fa")
def verify_2fa(req: Verify2FARequest, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    user_result = supabase.table("users").select("totp_secret").eq("user_id", current_user["user_id"]).execute()
    totp_secret = user_result.data[0]["totp_secret"]
    if not totp_secret:
        raise HTTPException(status_code=400, detail="2FA is not set up yet. Call /setup-2fa first.")

    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(req.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid or expired code.")

    elevated_until = (datetime.now(timezone.utc) + timedelta(minutes=ELEVATION_LIFETIME_MINUTES)).isoformat()
    supabase.table("sessions").update({"elevated_until": elevated_until}).eq("session_id", current_user["session_id"]).execute()

    return {"message": "Verified", "elevated_for_minutes": ELEVATION_LIFETIME_MINUTES}


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
    require_elevation(current_user)   # <-- 2FA STEP-UP REQUIRED

    registry_result = (
        supabase.table("employee_registry")
        .select("employee_id, full_name, official_email, department_id")
        .eq("employee_id", req.employee_id)
        .execute()
    )
    if not registry_result.data:
        raise HTTPException(status_code=404, detail="No such employee found in the government registry.")

    employee = registry_result.data[0]

    # THE PERMISSION FIX — check department_admins, not just department match.
    # Anyone in a department could invite before; now only actual admins can.
    admin_check = (
        supabase.table("department_admins")
        .select("can_invite_employees")
        .eq("user_id", current_user["user_id"])
        .eq("department_id", employee["department_id"])
        .execute()
    )
    if not admin_check.data or not admin_check.data[0]["can_invite_employees"]:
        raise HTTPException(
            status_code=403,
            detail="You don't have invite permissions for this department.",
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
# CASE: CREATE — the "digital FIR". Police only, enforced server-side.
# ------------------------------------------------------------------
def generate_fir_number(department_type: str) -> str:
    """Auto-generated, not typed by the officer: PREFIX-YYYYMMDD-XXXX"""
    prefix = {"police": "FIR"}.get(department_type, "CASE")
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_part = secrets.token_hex(2).upper()  # 4 hex chars
    return f"{prefix}-{date_part}-{random_part}"


class CreateCaseRequest(BaseModel):
    complainant_name: str
    incident_type: str
    incident_date: str
    location: str
    description: str


@app.post("/case/create")
def create_case(req: CreateCaseRequest, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    if current_user["department_type"] != "police":
        raise HTTPException(status_code=403, detail="Only police department members can file an FIR.")

    fir_id = generate_fir_number(current_user["department_type"])

    case_result = supabase.table("cases").insert({
        "fir_id": fir_id,
        "status": "open",
        "created_by": current_user["user_id"],
    }).execute()
    case_id = case_result.data[0]["case_id"]

    supabase.table("case_membership").insert({
        "user_id": current_user["user_id"],
        "case_id": case_id,
        "permission_level": "grant",
        "granted_by": current_user["user_id"],
        "allowed_document_types": ["fir", "evidence", "witness_statement", "charge_sheet"],
    }).execute()

    # Render the submitted form into an actual file, then push it through
    # the SAME hash+sign+store pipeline as any other upload — the FIR
    # form becomes a real, signed document, not just database rows.
    form_text = (
        f"FIRST INFORMATION REPORT\n"
        f"FIR Number: {fir_id}\n"
        f"Filed by: {current_user['full_name']} ({current_user['department_name']})\n"
        f"Filed at: {datetime.now(timezone.utc).isoformat()}\n"
        f"{'-'*50}\n"
        f"Complainant Name: {req.complainant_name}\n"
        f"Incident Type: {req.incident_type}\n"
        f"Incident Date: {req.incident_date}\n"
        f"Location: {req.location}\n"
        f"{'-'*50}\n"
        f"Description:\n{req.description}\n"
    )
    file_bytes = form_text.encode("utf-8")
    file_hash = calculate_file_hash(file_bytes)
    user_key = ensure_user_key(current_user["user_id"])
    signature = sign_file_hash(current_user["user_id"], file_hash)

    document_result = supabase.table("documents").insert({
        "case_id": case_id, "document_type": "fir",
        "file_type": "text", "uploader_id": current_user["user_id"],
    }).execute()
    document_id = document_result.data[0]["document_id"]

    version_id = str(uuid.uuid4())
    storage_path = f"{case_id}/{document_id}/{version_id}/fir_{fir_id}.txt"

    try:
        supabase.storage.from_(DOCUMENT_BUCKET).upload(
            storage_path, file_bytes, {"content-type": "text/plain", "upsert": False}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"FIR document storage failed: {str(e)}")

    supabase.table("document_versions").insert({
        "version_id": version_id, "document_id": document_id, "storage_path": storage_path,
        "file_hash": file_hash, "previous_version_hash": None, "signature": signature,
        "co_signature": None, "uploader_id": current_user["user_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }).execute()
    supabase.table("documents").update({"current_version_id": version_id}).eq("document_id", document_id).execute()

    return {"message": "FIR filed", "case_id": case_id, "fir_id": fir_id, "document_id": document_id}


# ------------------------------------------------------------------
# CASE: MY CASES — homepage "My Cases" list
# ------------------------------------------------------------------
@app.get("/case/my")
def my_cases(authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    result = (
        supabase.table("case_membership")
        .select("case_id, permission_level, allowed_document_types, cases(fir_id, status, created_at)")
        .eq("user_id", current_user["user_id"])
        .execute()
    )
    return result.data


@app.get("/case/documents")
def case_documents(case_id: str, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    membership = (
        supabase.table("case_membership")
        .select("permission_level, allowed_document_types")
        .eq("case_id", case_id).eq("user_id", current_user["user_id"]).execute()
    )
    if not membership.data:
        raise HTTPException(status_code=403, detail="You are not a member of this case.")

    my_allowed = set(membership.data[0]["allowed_document_types"] or [])

    docs = (
        supabase.table("documents")
        .select("document_id, document_type, file_type, uploader_id, current_version_id, "
                "document_versions!fk_documents_current_version(storage_path, file_hash, signature, timestamp)")
        .eq("case_id", case_id)
        .execute()
    )

    # THE VISIBILITY FILTER — only show document types this viewer is
    # actually cleared for, even though they can see the case at all.
    visible = [d for d in docs.data if d["document_type"] in my_allowed]

    return {
        "my_permission_level": membership.data[0]["permission_level"],
        "my_allowed_document_types": sorted(my_allowed),
        "documents": visible,
    }


# ------------------------------------------------------------------
# CASE: MEMBERS — who's currently on a case (used by the case-invite
# screen to show existing members, and for transparency per our
# earlier discussion on visible delegation)
# ------------------------------------------------------------------
@app.get("/case/members")
def case_members(case_id: str, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    my_membership = (
        supabase.table("case_membership")
        .select("permission_level, allowed_document_types")
        .eq("case_id", case_id)
        .eq("user_id", current_user["user_id"])
        .execute()
    )
    if not my_membership.data:
        raise HTTPException(status_code=403, detail="You are not a member of this case.")

    members = (
        supabase.table("case_membership")
        .select("user_id, permission_level, allowed_document_types, granted_by, delegated_by, "
                "users(employee_id, employee_registry!fk_users_employee(full_name, departments(name)))")
        .eq("case_id", case_id)
        .execute()
    )
    return {"my_access": my_membership.data[0], "members": members.data}


# ------------------------------------------------------------------
# CASE: INVITE — grant a specific person access to a specific case,
# with an explicit document-type checklist. Requires 2FA elevation.
#
# DELEGATION RULE (per our earlier discussion): if the inviter is
# NOT the case's original owner, they can only grant document types
# they THEMSELVES already have - never more. This is enforced here,
# not just suggested in the UI.
# ------------------------------------------------------------------
class CaseInviteRequest(BaseModel):
    case_id: str
    employee_id: str
    permission_level: str          # 'read', 'upload', 'sign', or 'grant'
    allowed_document_types: list[str]


@app.post("/case/invite")
def case_invite(req: CaseInviteRequest, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)
    require_elevation(current_user)   # <-- 2FA STEP-UP REQUIRED

    # Does the inviter actually have grant rights on this case?
    inviter_membership = (
        supabase.table("case_membership")
        .select("permission_level, allowed_document_types")
        .eq("case_id", req.case_id)
        .eq("user_id", current_user["user_id"])
        .execute()
    )
    if not inviter_membership.data or inviter_membership.data[0]["permission_level"] != "grant":
        raise HTTPException(status_code=403, detail="You don't have grant permission on this case.")

    inviter_allowed = set(inviter_membership.data[0]["allowed_document_types"] or [])

    # THE DELEGATION CAP — can never hand out more than you yourself have
    requested = set(req.allowed_document_types)
    if not requested.issubset(inviter_allowed):
        excess = requested - inviter_allowed
        raise HTTPException(
            status_code=403,
            detail=f"You can't grant document types you don't have access to yourself: {sorted(excess)}",
        )

    target_user = supabase.table("users").select("user_id").eq("employee_id", req.employee_id).execute()
    if not target_user.data:
        raise HTTPException(status_code=404, detail="That employee doesn't have an app account yet — invite them to the app first.")
    target_user_id = target_user.data[0]["user_id"]

    existing = (
        supabase.table("case_membership")
        .select("membership_id")
        .eq("case_id", req.case_id)
        .eq("user_id", target_user_id)
        .execute()
    )
    if existing.data:
        raise HTTPException(status_code=400, detail="This person already has access to this case.")

    supabase.table("case_membership").insert({
        "user_id": target_user_id,
        "case_id": req.case_id,
        "permission_level": req.permission_level,
        "granted_by": current_user["user_id"],
        "delegated_by": current_user["user_id"],
        "allowed_document_types": list(requested),
    }).execute()

    return {"message": f"{req.employee_id} added to case {req.case_id}"}


# ------------------------------------------------------------------
# PROFILE COMPLETION — closes the first-login gate. Only self-declared
# personal fields here; professional facts stay locked, set by the head.
# ------------------------------------------------------------------
class ProfileRequest(BaseModel):
    dob: str
    personal_address: str
    personal_phone: str
    emergency_contact_name: str
    emergency_contact_phone: str


@app.post("/profile/complete")
def complete_profile(req: ProfileRequest, authorization: str | None = Header(default=None)):
    current_user = get_current_user(authorization)

    supabase.table("user_profile").upsert({
        "user_id": current_user["user_id"],
        "dob": req.dob,
        "personal_address": req.personal_address,
        "personal_phone": req.personal_phone,
        "emergency_contact_name": req.emergency_contact_name,
        "emergency_contact_phone": req.emergency_contact_phone,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

    supabase.table("users").update({"account_status": "active"}).eq("user_id", current_user["user_id"]).execute()

    return {"message": "Profile completed", "account_status": "active"}


# ------------------------------------------------------------------
# DOCUMENT UPLOAD — merged in from the separately-drafted version,
# with two fixes:
#   1. Document types now match your actual schema (lowercase,
#      specific categories) instead of a different invented set —
#      otherwise the case-invite checklist would never match anything
#      an uploader actually stores.
#   2. Upload now checks BOTH permission_level AND allowed_document_types
#      — previously only permission_level was checked, meaning someone
#      granted access to only 'evidence' could still upload a
#      'witness_statement' if their permission level allowed uploading
#      at all. That gap is closed here.
# ------------------------------------------------------------------

DOCUMENT_BUCKET = os.getenv("DOCUMENT_BUCKET", "documents")
MAX_FILE_SIZE = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".doc", ".docx", ".ppt", ".pptx", ".txt"}

# Matches documents.document_type values used throughout your schema
# and the case-invite checklist — NOT the separately-invented uppercase set.
ALLOWED_DOCUMENT_TYPES = {
    "fir", "evidence", "forensic_report", "postmortem_report",
    "witness_statement", "charge_sheet", "court_order", "judgment",
}


def determine_file_type(extension: str) -> str:
    extension = extension.lower()
    if extension in {".jpg", ".jpeg", ".png"}:
        return "image"
    if extension in {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".txt"}:
        return "text"
    raise HTTPException(status_code=400, detail="Unsupported file type.")


def ensure_user_key(user_id: str):
    """Reuses an existing active key pair, or generates a new one.
    NOTE: private key is stored encrypted-on-disk (Fernet), not in a
    real KMS — a deliberate prototype simplification, flagged earlier."""
    existing = (
        supabase.table("user_keys")
        .select("key_id, public_key, kms_key_reference, algorithm")
        .eq("user_id", user_id).eq("key_status", "active").limit(1).execute()
    )
    if existing.data:
        return existing.data[0]

    private_key, public_key = generate_user_key_pair()
    save_private_key(user_id, private_key)
    kms_reference = f"local-encrypted-key:{user_id}"

    result = supabase.table("user_keys").insert({
        "user_id": user_id, "public_key": public_key,
        "kms_key_reference": kms_reference, "algorithm": "ECDSA-P256", "key_status": "active",
    }).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Could not create user key.")
    return result.data[0]


def check_case_upload_permission(user_id: str, case_id: str, document_type: str):
    membership = (
        supabase.table("case_membership")
        .select("permission_level, expires_at, allowed_document_types")
        .eq("user_id", user_id).eq("case_id", case_id).limit(1).execute()
    )
    if not membership.data:
        raise HTTPException(status_code=403, detail="You are not a member of this case.")

    row = membership.data[0]

    if row.get("expires_at"):
        if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
            raise HTTPException(status_code=403, detail="Your case access has expired.")

    if row["permission_level"] not in {"upload", "sign", "grant"}:
        raise HTTPException(status_code=403, detail="You don't have upload permission for this case.")

    # THE FIX — checklist enforcement, not just permission_level
    allowed_types = set(row.get("allowed_document_types") or [])
    if document_type not in allowed_types:
        raise HTTPException(
            status_code=403,
            detail=f"You're not authorized to upload '{document_type}' documents on this case. "
                   f"Your access covers: {sorted(allowed_types) or 'nothing yet'}.",
        )


@app.post("/documents/upload")
async def upload_document(
    case_id: str = Form(...),
    document_type: str = Form(...),
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
):
    current_user = get_current_user(authorization)
    user_id = current_user["user_id"]

    document_type = document_type.strip().lower()
    if document_type not in ALLOWED_DOCUMENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid document type. Allowed: {sorted(ALLOWED_DOCUMENT_TYPES)}")

    check_case_upload_permission(user_id, case_id, document_type)

    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing.")
    original_filename = os.path.basename(file.filename)
    extension = os.path.splitext(original_filename)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported file type. Allowed: PDF, PNG, JPG, DOC, DOCX, PPT, PPTX, TXT.")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Empty file.")
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File is larger than 50 MB.")

    file_type = determine_file_type(extension)
    file_hash = calculate_file_hash(file_bytes)
    user_key = ensure_user_key(user_id)

    document_result = supabase.table("documents").insert({
        "case_id": case_id, "document_type": document_type,
        "file_type": file_type, "uploader_id": user_id,
    }).execute()
    if not document_result.data:
        raise HTTPException(status_code=500, detail="Could not create document.")
    document_id = document_result.data[0]["document_id"]

    version_id = str(uuid.uuid4())
    signature = sign_file_hash(user_id, file_hash)
    safe_filename = original_filename.replace("/", "_").replace("\\", "_")
    storage_path = f"{case_id}/{document_id}/{version_id}/{safe_filename}"
    content_type = file.content_type or mimetypes.guess_type(original_filename)[0] or "application/octet-stream"

    try:
        supabase.storage.from_(DOCUMENT_BUCKET).upload(
            storage_path, file_bytes, {"content-type": content_type, "upsert": False}
        )
    except Exception as e:
        try:
            supabase.table("documents").delete().eq("document_id", document_id).execute()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"File storage failed: {str(e)}")

    version_result = supabase.table("document_versions").insert({
        "version_id": version_id, "document_id": document_id, "storage_path": storage_path,
        "file_hash": file_hash, "previous_version_hash": None, "signature": signature,
        "co_signature": None, "uploader_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }).execute()
    if not version_result.data:
        try:
            supabase.storage.from_(DOCUMENT_BUCKET).remove([storage_path])
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Could not create document version.")

    supabase.table("documents").update({"current_version_id": version_id}).eq("document_id", document_id).execute()

    return {
        "success": True, "message": "Document uploaded and digitally signed.",
        "document_id": document_id, "version_id": version_id, "case_id": case_id,
        "filename": original_filename, "file_type": file_type, "file_size": len(file_bytes),
        "file_hash": file_hash, "hash_algorithm": "SHA-256", "signature": signature,
        "signature_algorithm": "ECDSA-P256", "public_key": user_key["public_key"],
        "storage_path": storage_path,
    }


@app.get("/documents/verify/{version_id}")
def verify_document(version_id: str):
    version_result = supabase.table("document_versions").select("*").eq("version_id", version_id).limit(1).execute()
    if not version_result.data:
        raise HTTPException(status_code=404, detail="Document version not found.")
    version = version_result.data[0]

    key_result = (
        supabase.table("user_keys").select("public_key")
        .eq("user_id", version["uploader_id"]).eq("key_status", "active").limit(1).execute()
    )
    if not key_result.data:
        raise HTTPException(status_code=404, detail="Uploader public key not found.")

    valid = verify_signature(key_result.data[0]["public_key"], version["file_hash"], version["signature"])
    return {
        "valid": valid, "version_id": version_id, "file_hash": version["file_hash"],
        "signature": version["signature"], "algorithm": "ECDSA-P256",
        "uploader_id": version["uploader_id"],
        "message": "Signature is valid." if valid else "Signature is INVALID.",
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