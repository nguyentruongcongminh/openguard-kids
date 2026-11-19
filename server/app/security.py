"""OGK-Server — bảo mật v2 theo mục F5 của đề.

- Mật khẩu phụ huynh: Argon2id (passlib), tối thiểu 10 ký tự (kiểm ở tầng API).
- Trường nhạy cảm (TOTP secret, khóa HMAC của thiết bị): AES-GCM, khóa chủ lấy
  từ biến môi trường OGK_MASTER_KEY (base64, 32 byte) — không hardcode.
- Token thiết bị/phụ huynh: chỉ lưu hash SHA-256 phía server.
"""
import base64
import hashlib
import os
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from passlib.hash import argon2

_DEV = os.getenv("OGK_ENV", "lab") != "production"


def hash_password(pw: str) -> str:
    return argon2.hash(pw)


def verify_password(pw: str, stored: str) -> bool:
    try:
        return argon2.verify(pw, stored)
    except Exception:
        return False


def _master_key() -> bytes:
    raw = os.getenv("OGK_MASTER_KEY", "")
    if raw:
        key = base64.b64decode(raw)
        if len(key) != 32:
            raise RuntimeError("OGK_MASTER_KEY must decode to 32 bytes")
        return key
    if not _DEV:
        raise RuntimeError("OGK_MASTER_KEY is required in production")
    # Chế độ lab/dev: khóa tạm theo tiến trình (dữ liệu mã hóa sẽ không đọc lại
    # được sau khi server khởi động lại — chấp nhận được cho bản demo/phòng lab).
    global _EPHEMERAL
    try:
        return _EPHEMERAL
    except NameError:
        _EPHEMERAL = AESGCM.generate_key(bit_length=256)
        print("WARNING: OGK_MASTER_KEY not set — using an ephemeral key (lab mode).",
              file=sys.stderr)
        return _EPHEMERAL


def encrypt_field(plaintext: str) -> str:
    aes = AESGCM(_master_key())
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_field(token: str) -> str:
    raw = base64.b64decode(token)
    aes = AESGCM(_master_key())
    return aes.decrypt(raw[:12], raw[12:], None).decode("utf-8")


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()
