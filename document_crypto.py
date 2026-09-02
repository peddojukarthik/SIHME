"""
document_crypto.py
Stateless document signing for SIH.

- User RSA-3072 private keys are encrypted with AES-256-GCM.
- The encrypted private key is stored in Supabase (user_keys.encrypted_private_key).
- No private_keys/ local directory is required.
- SHA-256 is used for document fingerprints.
- RSA-PSS/SHA-256 is used for digital signatures.

Required environment variable:
    KEY_ENCRYPTION_KEY=<base64-url-safe 32-byte key>

Generate one with:
    python -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
"""

import os
import base64
import hashlib

from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()


def _master_key() -> bytes:
    value = os.getenv("KEY_ENCRYPTION_KEY")
    if not value:
        raise RuntimeError(
            "KEY_ENCRYPTION_KEY is missing from .env / server environment."
        )

    try:
        key = base64.urlsafe_b64decode(value.encode())
    except Exception as exc:
        raise RuntimeError(
            "KEY_ENCRYPTION_KEY is not valid base64."
        ) from exc

    if len(key) != 32:
        raise RuntimeError(
            "KEY_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256)."
        )

    return key


def calculate_file_hash(data: bytes) -> str:
    """Return SHA-256 hex digest of the exact bytes stored in Storage."""
    return hashlib.sha256(data).hexdigest()


def generate_user_key_pair():
    """Generate an RSA-3072 private/public key pair as PEM bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def encrypt_private_key(private_key_pem: bytes) -> str:
    """Encrypt a user's private key using AES-256-GCM."""
    aes = AESGCM(_master_key())
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        private_key_pem,
        None,
    )

    # Stored value = nonce + ciphertext/tag, base64 encoded.
    return base64.urlsafe_b64encode(
        nonce + ciphertext
    ).decode("ascii")


def decrypt_private_key(encrypted_value: str) -> bytes:
    """Decrypt a private key retrieved from Supabase."""
    raw = base64.urlsafe_b64decode(
        encrypted_value.encode("ascii")
    )

    if len(raw) < 13:
        raise ValueError("Encrypted private key is invalid.")

    nonce = raw[:12]
    ciphertext = raw[12:]

    aes = AESGCM(_master_key())

    return aes.decrypt(
        nonce,
        ciphertext,
        None,
    )


def sign_file_hash(user_id: str, file_hash: str, supabase=None) -> str:
    """
    Sign a SHA-256 document hash using the user's private key stored
    encrypted in Supabase.

    supabase must be the service-role Supabase client.
    """
    if supabase is None:
        raise RuntimeError(
            "sign_file_hash requires the Supabase client."
        )

    result = (
        supabase.table("user_keys")
        .select("encrypted_private_key, key_status, algorithm")
        .eq("user_id", user_id)
        .eq("key_status", "active")
        .limit(1)
        .execute()
    )

    if not result.data:
        raise RuntimeError(
            "No active signing key exists for this user."
        )

    row = result.data[0]
    encrypted_private_key = row.get("encrypted_private_key")

    if not encrypted_private_key:
        raise RuntimeError(
            "The user's private key is not stored in user_keys.encrypted_private_key."
        )

    private_pem = decrypt_private_key(encrypted_private_key)

    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
    )

    signature = private_key.sign(
        file_hash.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    public_key_pem: str,
    file_hash: str,
    signature_b64: str,
) -> bool:
    """Verify a signature against the stored public key and SHA-256 hash."""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )

        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            file_hash.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except Exception:
        return False
