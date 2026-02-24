# crypto_utils.py

import os
import base64

from cryptography.hazmat.primitives import hashes, padding, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# =========================
# ECDH key exchange helpers
# =========================

def generate_ec_keypair():
    """Generate an EC private/public key pair (P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1(), backend)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize public key to PEM (for display / sending if needed)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(pem_bytes):
    """Load public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes, backend=backend)


def derive_shared_key(private_key, peer_public_key):
    """
    Derive a 32-byte symmetric key from ECDH shared secret using HKDF-SHA256.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ics344-ecdhe-aes-cbc",
        backend=backend
    )
    key = hkdf.derive(shared_secret)
    return key

# =========================
# AES-CBC + PKCS#7 helpers
# =========================

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_aes_cbc_pkcs7(key: bytes, plaintext: bytes):
    """
    AES-CBC encryption with PKCS#7 padding.
    Returns (iv, ciphertext).
    """
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def decrypt_aes_cbc_pkcs7(key: bytes, iv: bytes, ciphertext: bytes):
    """
    AES-CBC decryption with PKCS#7 unpadding.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext

# =========================
# HMAC for integrity & auth
# =========================

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256(key, data).
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    h.update(data)
    return h.finalize()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> None:
    """
    Verify HMAC; raises InvalidSignature on failure.
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    h.update(data)
    h.verify(tag)

# =========================
# Password-based key (for Dictionary Attack demo)
# =========================

COMMON_PASSWORDS = [
    "123456",
    "password",
    "123456789",
    "qwerty",
    "abc123",
    "letmein",
    "111111",
    "admin",
    "welcome",
    "iloveyou",
    "ics344",
    "secret",
    "password123"
]


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA256.
    (Low iterations on purpose, so dictionary attack is fast for demo.)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=50_000,  # demo value; in real life this should be much higher
        backend=backend,
    )
    return kdf.derive(password.encode("utf-8"))


def dictionary_attack(ciphertext: bytes, iv: bytes, salt: bytes):
    """
    Try to recover the plaintext using a small dictionary of common passwords.
    Returns (success, tried, recovered_plaintext or None, found_password or None).
    """
    from cryptography.exceptions import InvalidKey, InvalidSignature

    for pwd in COMMON_PASSWORDS:
        try:
            key = derive_key_from_password(pwd, salt)
            pt = decrypt_aes_cbc_pkcs7(key, iv, ciphertext)
            # If decryption didn't raise, we *assume* success for the demo.
            return True, pwd, pt, pwd
        except Exception:
            # decryption failed; try next password
            continue

    return False, None, None, None


# =========================
# Helper for base64 encoding/decoding
# =========================

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))
