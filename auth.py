"""
🔐 نظام مصادقة JWT مبني بمكتبات Python القياسية
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, Optional

from fastapi import Header, HTTPException

from db import get_user_by_email, get_user_by_id

JWT_SECRET = os.getenv("SECUREAI_JWT_SECRET", "secureai-dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXPIRE_SECONDS = int(os.getenv("SECUREAI_JWT_EXPIRE_SECONDS", "43200"))  # 12 hours


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()



def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)



def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
    return f"pbkdf2_sha256${_b64url_encode(salt)}${_b64url_encode(derived)}"



def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, salt_b64, hash_b64 = stored_hash.split("$", 2)
        if scheme != "pbkdf2_sha256":
            return False
        salt = _b64url_decode(salt_b64)
        expected = _b64url_decode(hash_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False



def create_token(user: Dict, expires_in: int = JWT_EXPIRE_SECONDS) -> str:
    header = {"alg": JWT_ALG, "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "username": user["username"],
        "iat": now,
        "exp": now + expires_in,
    }
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"



def decode_token(token: str) -> Dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        provided_sig = _b64url_decode(signature_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            raise HTTPException(status_code=401, detail="رمز الوصول غير صالح")

        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise HTTPException(status_code=401, detail="انتهت صلاحية الجلسة")
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="تعذر التحقق من رمز الوصول")



def authenticate_user(email: str, password: str) -> Optional[Dict]:
    user = get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user.get("password_hash", "")):
        return None
    return user



def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="يلزم تسجيل الدخول أولاً")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token)
    user = get_user_by_id(int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=401, detail="المستخدم غير موجود")
    return user
