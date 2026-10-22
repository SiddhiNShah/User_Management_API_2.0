from datetime import datetime, timedelta, timezone

from jose import jwt
from passlib.context import CryptContext

from app.config import settings

# Argon2 via passlib — plan §14 allows Argon2 or bcrypt; Argon2 avoids
# bcrypt's 72-byte password cap and is the modern default.
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(user_id: int, token_version: int) -> str:
    # JWT carries subject (user id), token version, and expiry — all checked on each request.
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": str(user_id), "tv": token_version, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def normalize_email(email: str) -> str:
    # Plan: emails are trimmed + lowercased before storage and lookup.
    return email.strip().lower()
