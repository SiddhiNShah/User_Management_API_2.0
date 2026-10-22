from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import RoleEnum, User
from app.schemas import Token, UserLogin, UserOut, UserRegister
from app.security import create_access_token, hash_password, normalize_email, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


def _authenticate(db: Session, email: str, password: str) -> User:
    user = (
        db.query(User)
        .filter(User.email == normalize_email(email), User.is_deleted.is_(False))
        .first()
    )
    # Same error for unknown email vs wrong password — don't leak which was wrong.
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    if user.is_deactivated:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is deactivated")
    return user


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    email = normalize_email(payload.email)

    # Uniqueness is enforced only against active (non-deleted) accounts;
    # a soft-deleted email may be reused as a brand-new user_id.
    existing = (
        db.query(User)
        .filter(User.email == email, User.is_deleted.is_(False))
        .first()
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        name=payload.name,
        birthdate=payload.birthdate,
        gender=payload.gender,
        department=settings.default_department,  # Default dept; admin can change later.
        role=RoleEnum.user,                      # Public registration never grants admin.
        is_deleted=False,
        is_deactivated=False,
        token_version=0,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # JSON login: { "email": "...", "password": "..." }
    user = _authenticate(db, payload.email, payload.password)
    token = create_access_token(user.user_id, user.token_version)
    return Token(access_token=token)
