"""
Utilitaires simples de chiffrement et signature avec PyNaCl.
Clés attendues via variables d'environnement :
  - SCANNER_SECRET_KEY (base64) pour SecretBox (32 bytes)
  - SCANNER_SIGNING_KEY (base64) pour SigningKey (64 bytes)

Fonctions renvoient bytes encodés en base64 pour stockage plus simple.
"""
import os
import base64
import logging
from typing import Tuple

try:
    from nacl.secret import SecretBox
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignatureError
except Exception:
    SecretBox = None  # type: ignore

logger = logging.getLogger(__name__)


def _b64decode_env(name: str) -> bytes:
    v = os.environ.get(name)
    if not v:
        raise ValueError(f"Variable d'environnement {name} non définie")
    return base64.b64decode(v)


def encrypt_bytes(secret_key_b64: bytes, data: bytes) -> bytes:
    """Chiffre `data` avec SecretBox. `secret_key_b64` doit être la clé brute (32 bytes).
    Retourne le ciphertext en base64 (bytes).
    """
    if SecretBox is None:
        raise RuntimeError("PyNaCl non installé")
    # secret_key_b64 peut être clé binaire; si fournie en base64, on assume déjà décodée
    key = secret_key_b64
    box = SecretBox(key)
    ct = box.encrypt(data)
    return base64.b64encode(ct)


def decrypt_bytes(secret_key_b64: bytes, ciphertext_b64: bytes) -> bytes:
    if SecretBox is None:
        raise RuntimeError("PyNaCl non installé")
    key = secret_key_b64
    box = SecretBox(key)
    ct = base64.b64decode(ciphertext_b64)
    return box.decrypt(ct)


def sign_bytes(signing_key_b64: bytes, data: bytes) -> bytes:
    if SigningKey is None:
        raise RuntimeError("PyNaCl non installé")
    sk = SigningKey(signing_key_b64)
    signed = sk.sign(data)
    return base64.b64encode(signed.signature)


def verify_signature(verify_key_b64: bytes, data: bytes, signature_b64: bytes) -> bool:
    try:
        vk = VerifyKey(verify_key_b64)
        sig = base64.b64decode(signature_b64)
        vk.verify(data, sig)
        return True
    except Exception:
        return False
