import os
import mimetypes
import uuid

from datetime import datetime, timezone

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Header,
    HTTPException,
    Form
)

from fastapi.middleware.cors import CORSMiddleware

from dotenv import load_dotenv

from supabase import create_client

from document_crypto import (
    calculate_file_hash,
    generate_user_key_pair,
    save_private_key,
    sign_file_hash,
    verify_signature
)


# ============================================================
# CONFIG
# ============================================================

load_dotenv()

SUPABASE_URL = os.environ[
    "SUPABASE_URL"
]

SUPABASE_SERVICE_ROLE_KEY = os.environ[
    "SUPABASE_SERVICE_ROLE_KEY"
]

DOCUMENT_BUCKET = os.getenv(
    "DOCUMENT_BUCKET",
    "documents"
)


supabase = create_client(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
)


app = FastAPI(
    title="Secure Document Service"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# SETTINGS
# ============================================================

MAX_FILE_SIZE = 50 * 1024 * 1024


ALLOWED_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".doc",
    ".docx",
    ".ppt",
    ".pptx",
    ".txt"
}


ALLOWED_DOCUMENT_TYPES = {
    "FIR",
    "CASE_DOCUMENT",
    "EVIDENCE",
    "REPORT",
    "STATEMENT",
    "OTHER"
}


# ============================================================
# AUTHENTICATION
# ============================================================

def get_current_user(
    authorization: str | None
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Not logged in."
        )


    if not authorization.startswith(
        "Bearer "
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header."
        )


    raw_token = (
        authorization
        .removeprefix("Bearer ")
        .strip()
    )


    if not raw_token:

        raise HTTPException(
            status_code=401,
            detail="Missing session token."
        )


    # --------------------------------------------------------
    # Same token hashing mechanism as your existing backend
    # --------------------------------------------------------

    import hashlib

    token_hash = hashlib.sha256(
        raw_token.encode()
    ).hexdigest()


    session_result = (
        supabase
        .table("sessions")
        .select(
            "user_id, expires_at"
        )
        .eq(
            "token_hash",
            token_hash
        )
        .execute()
    )


    if not session_result.data:

        raise HTTPException(
            status_code=401,
            detail="Invalid session."
        )


    session = session_result.data[0]


    expires_at = datetime.fromisoformat(
        session["expires_at"]
    )


    if datetime.now(
        timezone.utc
    ) > expires_at:

        raise HTTPException(
            status_code=401,
            detail="Session expired."
        )


    user_id = session[
        "user_id"
    ]


    user_result = (
        supabase
        .table("users")
        .select(
            "user_id, employee_id, account_status"
        )
        .eq(
            "user_id",
            user_id
        )
        .execute()
    )


    if not user_result.data:

        raise HTTPException(
            status_code=401,
            detail="User not found."
        )


    user = user_result.data[0]


    return user


# ============================================================
# USER KEY MANAGEMENT
# ============================================================

def ensure_user_key(
    user_id: str
):

    existing = (
        supabase
        .table("user_keys")
        .select(
            "key_id, public_key, kms_key_reference, algorithm"
        )
        .eq(
            "user_id",
            user_id
        )
        .eq(
            "key_status",
            "active"
        )
        .limit(1)
        .execute()
    )


    if existing.data:

        return existing.data[0]


    # --------------------------------------------------------
    # Generate ECDSA P-256 pair
    # --------------------------------------------------------

    private_key, public_key = (
        generate_user_key_pair()
    )


    # --------------------------------------------------------
    # Store encrypted private key OUTSIDE database
    # --------------------------------------------------------

    save_private_key(
        user_id,
        private_key
    )


    # --------------------------------------------------------
    # Prototype KMS reference
    #
    # Later replace this with:
    # AWS KMS ARN / Azure Key Vault ID / HSM reference
    # --------------------------------------------------------

    kms_reference = (
        f"local-encrypted-key:{user_id}"
    )


    result = (
        supabase
        .table("user_keys")
        .insert({
            "user_id": user_id,
            "public_key": public_key,
            "kms_key_reference": kms_reference,
            "algorithm": "ECDSA-P256",
            "key_status": "active"
        })
        .execute()
    )


    if not result.data:

        raise HTTPException(
            status_code=500,
            detail="Could not create user key."
        )


    return result.data[0]


# ============================================================
# CASE ACCESS
# ============================================================

def check_case_upload_permission(
    user_id: str,
    case_id: str
):

    membership = (
        supabase
        .table("case_membership")
        .select(
            "permission_level, expires_at"
        )
        .eq(
            "user_id",
            user_id
        )
        .eq(
            "case_id",
            case_id
        )
        .limit(1)
        .execute()
    )


    if not membership.data:

        raise HTTPException(
            status_code=403,
            detail="You are not a member of this case."
        )


    membership_row = membership.data[0]


    # --------------------------------------------------------
    # Check expiry
    # --------------------------------------------------------

    if membership_row.get(
        "expires_at"
    ):

        expires = datetime.fromisoformat(
            membership_row[
                "expires_at"
            ]
        )

        if datetime.now(
            timezone.utc
        ) > expires:

            raise HTTPException(
                status_code=403,
                detail="Your case access has expired."
            )


    permission = membership_row[
        "permission_level"
    ]


    # Your schema defines:
    #
    # read
    # upload
    # sign
    # grant
    #
    # For upload, upload/sign/grant are accepted.

    if permission not in {
        "upload",
        "sign",
        "grant"
    }:

        raise HTTPException(
            status_code=403,
            detail="You don't have upload permission for this case."
        )


    return True


# ============================================================
# FILE TYPE
# ============================================================

def determine_file_type(
    extension: str
):

    extension = extension.lower()


    if extension in {
        ".jpg",
        ".jpeg",
        ".png"
    }:

        return "image"


    if extension in {
        ".pdf",
        ".doc",
        ".docx",
        ".ppt",
        ".pptx",
        ".txt"
    }:

        return "text"


    raise HTTPException(
        status_code=400,
        detail="Unsupported file type."
    )


# ============================================================
# UPLOAD
# ============================================================

@app.post(
    "/documents/upload"
)
async def upload_document(

    case_id: str = Form(...),

    document_type: str = Form(...),

    file: UploadFile = File(...),

    authorization: str | None = Header(
        default=None
    )
):

    # --------------------------------------------------------
    # Authenticate
    # --------------------------------------------------------

    user = get_current_user(
        authorization
    )


    user_id = user[
        "user_id"
    ]


    # --------------------------------------------------------
    # Validate case ID
    # --------------------------------------------------------

    try:

        uuid.UUID(case_id)

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail="Invalid case_id."
        )


    # --------------------------------------------------------
    # Validate document type
    # --------------------------------------------------------

    document_type = (
        document_type
        .strip()
        .upper()
    )


    if document_type not in (
        ALLOWED_DOCUMENT_TYPES
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid document type."
        )


    # --------------------------------------------------------
    # Check case permission
    # --------------------------------------------------------

    check_case_upload_permission(
        user_id,
        case_id
    )


    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="Filename missing."
        )


    original_filename = (
        os.path.basename(
            file.filename
        )
    )


    extension = os.path.splitext(
        original_filename
    )[1].lower()


    if extension not in (
        ALLOWED_EXTENSIONS
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                "Allowed: PDF, PNG, JPG, DOC, "
                "DOCX, PPT, PPTX, TXT."
            )
        )


    # --------------------------------------------------------
    # Read file
    # --------------------------------------------------------

    file_bytes = await file.read()


    if not file_bytes:

        raise HTTPException(
            status_code=400,
            detail="Empty file."
        )


    if len(file_bytes) > MAX_FILE_SIZE:

        raise HTTPException(
            status_code=413,
            detail="File is larger than 50 MB."
        )


    # --------------------------------------------------------
    # Determine file type
    # --------------------------------------------------------

    file_type = determine_file_type(
        extension
    )


    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    file_hash = calculate_file_hash(
        file_bytes
    )


    # --------------------------------------------------------
    # Generate / retrieve user's key
    # --------------------------------------------------------

    user_key = ensure_user_key(
        user_id
    )


    # --------------------------------------------------------
    # Create document
    # --------------------------------------------------------

    document_result = (
        supabase
        .table("documents")
        .insert({
            "case_id": case_id,
            "document_type": document_type,
            "file_type": file_type,
            "uploader_id": user_id
        })
        .execute()
    )


    if not document_result.data:

        raise HTTPException(
            status_code=500,
            detail="Could not create document."
        )


    document = (
        document_result.data[0]
    )


    document_id = document[
        "document_id"
    ]


    # --------------------------------------------------------
    # Version ID
    # --------------------------------------------------------

    version_id = str(
        uuid.uuid4()
    )


    # --------------------------------------------------------
    # Check previous version
    #
    # For a brand-new document there won't be one.
    # This will be used when we add replacement/version upload.
    # --------------------------------------------------------

    previous_version_hash = None


    # --------------------------------------------------------
    # Digital signature
    # --------------------------------------------------------

    signature = sign_file_hash(
        user_id,
        file_hash
    )


    # --------------------------------------------------------
    # Storage path
    # --------------------------------------------------------

    safe_filename = (
        original_filename
        .replace("/", "_")
        .replace("\\", "_")
    )


    storage_path = (
        f"{case_id}/"
        f"{document_id}/"
        f"{version_id}/"
        f"{safe_filename}"
    )


    # --------------------------------------------------------
    # Upload original file
    # --------------------------------------------------------

    content_type = (
        file.content_type
        or mimetypes.guess_type(
            original_filename
        )[0]
        or "application/octet-stream"
    )


    try:

        supabase.storage \
            .from_(DOCUMENT_BUCKET) \
            .upload(
                storage_path,
                file_bytes,
                {
                    "content-type":
                        content_type,
                    "upsert":
                        False
                }
            )

    except Exception as e:

        # If storage fails, remove document row
        try:

            (
                supabase
                .table("documents")
                .delete()
                .eq(
                    "document_id",
                    document_id
                )
                .execute()
            )

        except Exception:
            pass


        raise HTTPException(
            status_code=500,
            detail=f"File storage failed: {str(e)}"
        )


    # --------------------------------------------------------
    # Create document version
    # --------------------------------------------------------

    version_result = (
        supabase
        .table("document_versions")
        .insert({

            "version_id":
                version_id,

            "document_id":
                document_id,

            "storage_path":
                storage_path,

            "file_hash":
                file_hash,

            "previous_version_hash":
                previous_version_hash,

            "signature":
                signature,

            "co_signature":
                None,

            "uploader_id":
                user_id,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat()
        })
        .execute()
    )


    if not version_result.data:

        # Storage cleanup if DB insert failed

        try:

            (
                supabase.storage
                .from_(DOCUMENT_BUCKET)
                .remove([
                    storage_path
                ])
            )

        except Exception:
            pass


        raise HTTPException(
            status_code=500,
            detail="Could not create document version."
        )


    # --------------------------------------------------------
    # Update current version
    # --------------------------------------------------------

    (
        supabase
        .table("documents")
        .update({
            "current_version_id":
                version_id
        })
        .eq(
            "document_id",
            document_id
        )
        .execute()
    )


    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {

        "success":
            True,

        "message":
            "Document uploaded and digitally signed.",

        "document_id":
            document_id,

        "version_id":
            version_id,

        "case_id":
            case_id,

        "filename":
            original_filename,

        "file_type":
            file_type,

        "file_size":
            len(file_bytes),

        "file_hash":
            file_hash,

        "hash_algorithm":
            "SHA-256",

        "signature":
            signature,

        "signature_algorithm":
            "ECDSA-P256",

        "public_key":
            user_key[
                "public_key"
            ],

        "storage_path":
            storage_path
    }


# ============================================================
# VERIFY DOCUMENT
# ============================================================

@app.get(
    "/documents/verify/{version_id}"
)
def verify_document(
    version_id: str
):

    # --------------------------------------------------------
    # Get version
    # --------------------------------------------------------

    version_result = (
        supabase
        .table("document_versions")
        .select("*")
        .eq(
            "version_id",
            version_id
        )
        .limit(1)
        .execute()
    )


    if not version_result.data:

        raise HTTPException(
            status_code=404,
            detail="Document version not found."
        )


    version = version_result.data[0]


    uploader_id = version[
        "uploader_id"
    ]


    # --------------------------------------------------------
    # Get public key
    # --------------------------------------------------------

    key_result = (
        supabase
        .table("user_keys")
        .select(
            "public_key, algorithm, key_status"
        )
        .eq(
            "user_id",
            uploader_id
        )
        .eq(
            "key_status",
            "active"
        )
        .limit(1)
        .execute()
    )


    if not key_result.data:

        raise HTTPException(
            status_code=404,
            detail="Uploader public key not found."
        )


    public_key = key_result.data[0][
        "public_key"
    ]


    # --------------------------------------------------------
    # Verify signature
    # --------------------------------------------------------

    valid_signature = verify_signature(
        public_key,
        version["file_hash"],
        version["signature"]
    )


    return {

        "valid":
            valid_signature,

        "version_id":
            version_id,

        "file_hash":
            version["file_hash"],

        "signature":
            version["signature"],

        "algorithm":
            "ECDSA-P256",

        "uploader_id":
            uploader_id,

        "message":
            (
                "Signature is valid."
                if valid_signature
                else
                "Signature is INVALID."
            )
    }