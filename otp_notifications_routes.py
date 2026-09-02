
# ADD THIS TO invite_backend.py after get_current_user(), supabase and
# GMAIL_* variables have been initialized.
#
# It deliberately uses a separate email OTP from the existing authenticator
# TOTP. TOTP remains the second factor for privileged invite/case delegation;
# email OTP is the step-up gate requested by the project UI.

import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from fastapi import Header
from pydantic import BaseModel

class EmailOTPRequest(BaseModel):
    purpose: str
    case_id: str | None = None

class EmailOTPVerifyRequest(BaseModel):
    purpose: str
    case_id: str | None = None
    code: str

def register_otp_notification_routes(app, supabase, get_current_user,
                                      gmail_address, gmail_app_password):

    def send_code(to_email, name, code):
        msg = MIMEText(
            f"Hello {name},\n\n"
            f"Your Secure DMS verification code is: {code}\n"
            f"This code expires in 5 minutes.\n\n"
            "If you did not request this, ignore this email."
        )
        msg["Subject"] = "Secure DMS verification code"
        msg["From"] = gmail_address
        msg["To"] = to_email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(gmail_address, gmail_app_password)
            server.sendmail(gmail_address, [to_email], msg.as_string())

    @app.post("/security/request-otp")
    def request_otp(req: EmailOTPRequest,
                    authorization: str | None = Header(default=None)):
        u = get_current_user(authorization)

        allowed = {"CASE_VIEW", "CASE_UPLOAD", "CASE_MEMBERS", "APP_INVITE"}
        if req.purpose not in allowed:
            raise HTTPException(400, "Invalid OTP purpose.")

        q = (supabase.table("employee_registry")
             .select("full_name,official_email")
             .eq("employee_id", u["employee_id"])
             .limit(1).execute())
        if not q.data or not q.data[0].get("official_email"):
            raise HTTPException(400, "Official email is not configured.")

        code = f"{secrets.randbelow(1000000):06d}"
        h = hashlib.sha256(code.encode()).hexdigest()
        exp = datetime.now(timezone.utc) + timedelta(minutes=5)

        supabase.table("email_otps").update({
            "used_at": datetime.now(timezone.utc).isoformat()
        }).eq("user_id", u["user_id"]).eq("purpose", req.purpose).is_("used_at","null").execute()

        supabase.table("email_otps").insert({
            "user_id": u["user_id"],
            "purpose": req.purpose,
            "case_id": req.case_id,
            "otp_hash": h,
            "expires_at": exp.isoformat()
        }).execute()

        try:
            send_code(q.data[0]["official_email"], q.data[0]["full_name"], code)
        except Exception as e:
            raise HTTPException(502, f"Could not send OTP email: {e}")

        return {"message": "Verification code sent to your official email.", "expires_in": 300}

    @app.post("/security/verify-otp")
    def verify_otp(req: EmailOTPVerifyRequest,
                   authorization: str | None = Header(default=None)):
        u = get_current_user(authorization)
        if not req.code.isdigit() or len(req.code) != 6:
            raise HTTPException(400, "OTP must be exactly 6 digits.")

        h = hashlib.sha256(req.code.encode()).hexdigest()
        q = (supabase.table("email_otps")
             .select("otp_id,expires_at,attempts")
             .eq("user_id",u["user_id"])
             .eq("purpose",req.purpose)
             .eq("otp_hash",h)
             .is_("used_at","null")
             .order("created_at",desc=True).limit(1).execute())

        if not q.data:
            raise HTTPException(401, "Invalid verification code.")

        row=q.data[0]
        if row["attempts"] >= 5:
            raise HTTPException(401, "Too many attempts. Request a new code.")

        if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
            raise HTTPException(401, "Verification code expired.")

        supabase.table("email_otps").update({
            "used_at": datetime.now(timezone.utc).isoformat()
        }).eq("otp_id",row["otp_id"]).execute()

        return {"verified": True}

    @app.get("/notifications")
    def notifications(authorization: str | None = Header(default=None)):
        u=get_current_user(authorization)
        r=(supabase.table("notifications").select("*")
           .eq("user_id",u["user_id"]).order("created_at",desc=True)
           .limit(100).execute())
        return r.data or []

    @app.get("/notifications/unread-count")
    def unread_count(authorization: str | None = Header(default=None)):
        u=get_current_user(authorization)
        r=(supabase.table("notifications").select("notification_id",count="exact")
           .eq("user_id",u["user_id"]).is_("read_at","null").execute())
        return {"count": r.count or 0}

    @app.post("/notifications/read")
    def mark_notifications_read(authorization: str | None = Header(default=None)):
        u=get_current_user(authorization)
        supabase.table("notifications").update({
            "read_at": datetime.now(timezone.utc).isoformat()
        }).eq("user_id",u["user_id"]).is_("read_at","null").execute()
        return {"success":True}

# After defining the function:
#
# register_otp_notification_routes(
#     app, supabase, get_current_user, GMAIL_ADDRESS, GMAIL_APP_PASSWORD
# )
