"""
FULL RESET + BOOTSTRAP — wipes every table, reseeds departments and
employee_registry with test data, and bootstraps ONE working head
account per department so you can immediately log in and test /invite.

This is the one script allowed to create a `users` row directly,
bypassing the normal invite flow entirely -- because normally NOTHING
can happen until at least one admin already exists. Real deployments
would do this step manually, once, per institution, out-of-band.

EDIT THE CONFIG SECTION BELOW before running -- swap in your real
test emails (reusing the same email for multiple entries is fine,
official_email has no uniqueness requirement).

Run:  python bootstrap_reset.py
"""

import os
import bcrypt
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])

# ============================================================
# CONFIG -- edit this section with your real test emails
# ============================================================
DEMO_PASSWORD = "Demo@1234"   # every bootstrapped head gets this password to start

DEPARTMENTS = [
    {"name": "Hyderabad City Police - Begumpet Station", "type": "police", "jurisdiction": "Begumpet, Hyderabad", "official_email_domain": "example.com"},
    {"name": "Telangana State Forensic Science Laboratory", "type": "fsl", "jurisdiction": "Hyderabad", "official_email_domain": "example.com"},
    {"name": "Gandhi Hospital - Forensic Medicine Department", "type": "hospital_forensic_medicine", "jurisdiction": "Musheerabad, Hyderabad", "official_email_domain": "example.com"},
    {"name": "City Civil Court, Hyderabad", "type": "court", "jurisdiction": "Hyderabad", "official_email_domain": "example.com"},
    {"name": "Directorate of Prosecution, Telangana", "type": "prosecution", "jurisdiction": "Hyderabad", "official_email_domain": "example.com"},
    {"name": "Bengaluru City Police - Cubbon Park Station", "type": "police", "jurisdiction": "Cubbon Park, Bengaluru", "official_email_domain": "example.com"},
]

# One HEAD per department -- these get bootstrapped directly with a
# working login AND department_admins rights. PUT_EMAIL_HERE placeholders
# are what you should replace -- reusing the same real email across all
# 6 is completely fine for testing.
HEADS = [
    {"employee_id": "HYD-PS4-DEMO1", "full_name": "Karthik Dola",       "rank": "Sub-Inspector",           "email": "karthikpeddoju1006@gmail.com", "dept_name": "Hyderabad City Police - Begumpet Station"},
    {"employee_id": "TSFSL-0001",    "full_name": "Demo FSL Head",      "rank": "Senior Scientific Officer","email": "karthikpeddoju1006@gmail.com", "dept_name": "Telangana State Forensic Science Laboratory"},
    {"employee_id": "GH-FMD-0001",   "full_name": "Demo Hospital Head", "rank": "Assistant Professor",     "email": "karthikpeddoju1006@gmail.com", "dept_name": "Gandhi Hospital - Forensic Medicine Department"},
    {"employee_id": "CCC-HYD-0001",  "full_name": "Demo Court Head",    "rank": "Additional District Judge","email": "karthikpeddoju1006@gmail.com", "dept_name": "City Civil Court, Hyderabad"},
    {"employee_id": "DOP-TG-0001",   "full_name": "Demo Prosecutor Head","rank": "Public Prosecutor",      "email": "karthikpeddoju1006@gmail.com", "dept_name": "Directorate of Prosecution, Telangana"},
    {"employee_id": "HYD-PS4-DEMO2", "full_name": "Karthik Peddoju",    "rank": "Constable",                "email": "karthikpeddoju1006@gmail.com", "dept_name": "Hyderabad City Police - Begumpet Station"},
]
# ============================================================


import psycopg2

def reset_all_tables():
    print("Wiping all tables (TRUNCATE CASCADE)...")
    conn = psycopg2.connect(os.environ["SUPABASE_DB_URL"])
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("""
        TRUNCATE TABLE
            departments, employee_registry, users, activation_tokens,
            user_profile, correction_requests, login_audit, user_keys,
            cases, case_membership, documents, document_versions,
            visibility_policy, access_requests, access_events,
            sessions, department_admins
        CASCADE;
    """)

    # VERIFY the wipe actually happened before doing anything else.
    # If this fails, STOP HERE instead of hitting a confusing duplicate
    # key error three steps later.
    cur.execute("SELECT count(*) FROM employee_registry;")
    remaining = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM departments;")
    remaining_depts = cur.fetchone()[0]
    cur.close()
    conn.close()

    print(f"  employee_registry rows after truncate: {remaining} (should be 0)")
    print(f"  departments rows after truncate:       {remaining_depts} (should be 0)")

    if remaining != 0 or remaining_depts != 0:
        raise RuntimeError(
            "TRUNCATE did not actually empty the tables! This usually means "
            "SUPABASE_DB_URL is pointing at a different database than you "
            "expect, or a permissions issue. STOPPING before seeding to "
            "avoid duplicate-key errors. Check SUPABASE_DB_URL carefully."
        )

    print("Confirmed: all tables genuinely empty.\n")


def seed_departments():
    print("Seeding departments...")
    result = supabase.table("departments").insert(DEPARTMENTS).execute()
    name_to_id = {row["name"]: row["department_id"] for row in result.data}
    print(f"  Created {len(result.data)} departments.\n")
    return name_to_id


def seed_registry_and_bootstrap_heads(name_to_id):
    print("Seeding employee_registry + bootstrapping head accounts...")
    for head in HEADS:
        dept_id = name_to_id[head["dept_name"]]

        supabase.table("employee_registry").insert({
            "employee_id": head["employee_id"],
            "full_name": head["full_name"],
            "department_id": dept_id,
            "rank": head["rank"],
            "official_email": head["email"],
            "registry_status": "verified",
        }).execute()

        password_hash = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt()).decode()
        user_result = supabase.table("users").insert({
            "employee_id": head["employee_id"],
            "password_hash": password_hash,
            "account_status": "active",   # bootstrapped directly to fully active
            "invited_by": None,           # null = bootstrapped, not invited by anyone
        }).execute()
        user_id = user_result.data[0]["user_id"]

        supabase.table("department_admins").insert({
            "user_id": user_id,
            "department_id": dept_id,
            "can_invite_employees": True,
            "can_delegate": True,
            "granted_by": None,
        }).execute()

        print(f"  {head['full_name']} ({head['employee_id']}) - login ready, password: {DEMO_PASSWORD}")
    print()


if __name__ == "__main__":
    reset_all_tables()
    name_to_id = seed_departments()
    seed_registry_and_bootstrap_heads(name_to_id)
    print("=" * 60)
    print(f"Done. Every listed head can now log in with password: {DEMO_PASSWORD}")
    print("Use their employee_id + this password on the login screen.")
    print("=" * 60)