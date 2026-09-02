import base64, hashlib, os
from pathlib import Path
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

load_dotenv()
KEY_ENCRYPTION_KEY=os.getenv('KEY_ENCRYPTION_KEY')
if not KEY_ENCRYPTION_KEY: raise RuntimeError('KEY_ENCRYPTION_KEY is missing from .env')
fernet=Fernet(KEY_ENCRYPTION_KEY.encode())
PRIVATE_KEY_DIR=Path(os.getenv('PRIVATE_KEY_DIR','./private_keys'))
PRIVATE_KEY_DIR.mkdir(parents=True,exist_ok=True)

def calculate_file_hash(file_bytes:bytes)->str: return hashlib.sha256(file_bytes).hexdigest()
def generate_user_key_pair():
    private=ec.generate_private_key(ec.SECP256R1()); public=private.public_key()
    priv=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    pub=public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv,pub

def _path(uid): return PRIVATE_KEY_DIR/f'{uid}.key'
def save_private_key(uid,pem):
    p=_path(uid); p.write_bytes(fernet.encrypt(pem.encode()))
    try: os.chmod(p,0o600)
    except OSError: pass

def load_private_key(uid): return fernet.decrypt(_path(uid).read_bytes()).decode()
def sign_file_hash(uid,file_hash):
    key=serialization.load_pem_private_key(load_private_key(uid).encode(),password=None)
    sig=key.sign(file_hash.encode(),ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()

def verify_signature(public_key_pem,file_hash,signature):
    try:
        key=serialization.load_pem_public_key(public_key_pem.encode())
        key.verify(base64.b64decode(signature,validate=True),file_hash.encode(),ec.ECDSA(hashes.SHA256()))
        return True
    except Exception: return False
