import os
import base64
import hashlib
from pathlib import Path

from dotenv import load_dotenv
from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


load_dotenv()


# ============================================================
# CONFIG
# ============================================================

KEY_ENCRYPTION_KEY = os.environ["KEY_ENCRYPTION_KEY"]

fernet = Fernet(
    KEY_ENCRYPTION_KEY.encode()
)


KEY_DIRECTORY = Path(
    os.getenv(
        "PRIVATE_KEY_DIRECTORY",
        "./private_keys"
    )
)

KEY_DIRECTORY.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# SHA-256
# ============================================================

def calculate_file_hash(
    file_bytes: bytes
) -> str:

    return hashlib.sha256(
        file_bytes
    ).hexdigest()


# ============================================================
# KEY GENERATION
# ============================================================

def generate_user_key_pair():

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()


    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    return (
        private_bytes.decode(),
        public_bytes.decode()
    )


# ============================================================
# PRIVATE KEY ENCRYPTION
# ============================================================

def encrypt_private_key(
    private_key: str
) -> bytes:

    return fernet.encrypt(
        private_key.encode()
    )


def decrypt_private_key(
    encrypted_private_key: bytes
) -> str:

    return fernet.decrypt(
        encrypted_private_key
    ).decode()


# ============================================================
# LOCAL ENCRYPTED PRIVATE KEY STORAGE
# ============================================================

def private_key_path(
    user_id: str
) -> Path:

    return (
        KEY_DIRECTORY /
        f"{user_id}.key"
    )


def save_private_key(
    user_id: str,
    private_key: str
):

    encrypted = encrypt_private_key(
        private_key
    )

    path = private_key_path(
        user_id
    )

    path.write_bytes(
        encrypted
    )

    # Owner-readable only where supported
    try:
        os.chmod(
            path,
            0o600
        )
    except Exception:
        pass


def load_private_key(
    user_id: str
) -> str:

    path = private_key_path(
        user_id
    )

    if not path.exists():

        raise FileNotFoundError(
            "Private key not found for user."
        )

    encrypted = path.read_bytes()

    return decrypt_private_key(
        encrypted
    )


# ============================================================
# SIGN FILE HASH
# ============================================================

def sign_file_hash(
    user_id: str,
    file_hash: str
) -> str:

    private_pem = load_private_key(
        user_id
    )

    private_key = (
        serialization
        .load_pem_private_key(
            private_pem.encode(),
            password=None
        )
    )


    signature = private_key.sign(
        file_hash.encode(),
        ec.ECDSA(
            hashes.SHA256()
        )
    )


    return base64.b64encode(
        signature
    ).decode()


# ============================================================
# VERIFY
# ============================================================

def verify_signature(
    public_key_pem: str,
    file_hash: str,
    signature: str
) -> bool:

    try:

        public_key = (
            serialization
            .load_pem_public_key(
                public_key_pem.encode()
            )
        )


        signature_bytes = (
            base64.b64decode(
                signature
            )
        )


        public_key.verify(
            signature_bytes,
            file_hash.encode(),
            ec.ECDSA(
                hashes.SHA256()
            )
        )

        return True

    except Exception:

        return False