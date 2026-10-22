from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import RoleEnum, User

# Simple Bearer scheme — Swagger's Authorize dialog will show one "Value" field
# where you paste the token returned by /auth/login.
bearer_scheme = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials
    # Decode + validate the JWT; a bad/expired token is 401.
    creds_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id = int(payload.get("sub"))
        token_version = int(payload.get("tv"))
    except (JWTError, TypeError, ValueError):
        raise creds_error

    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise creds_error

    # Status checked on every protected request, not just at login.
    if user.is_deleted:
        raise creds_error
    if user.is_deactivated:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is deactivated")

    # token_version mismatch means the token was revoked (password change, deactivation, etc.).
    if user.token_version != token_version:
        raise creds_error

    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != RoleEnum.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    return current_user
