"""Create the initial admin account from ADMIN_EMAIL / ADMIN_PASSWORD env vars.

Idempotent: if an admin already exists, do nothing — never overwrite an existing password.
Run with:  python -m scripts.seed_admin
"""
from __future__ import annotations

import sys

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import RoleEnum, User
from app.security import hash_password, normalize_email


def main() -> int:
    if not settings.admin_email or not settings.admin_password:
        print("ADMIN_EMAIL and ADMIN_PASSWORD must be set in the environment.", file=sys.stderr)
        return 1

    # Ensure tables exist before the first run.
    Base.metadata.create_all(bind=engine)

    email = normalize_email(settings.admin_email)
    db = SessionLocal()
    try:
        # Any existing admin aborts the script — never silently reset credentials.
        existing_admin = db.query(User).filter(User.role == RoleEnum.admin).first()
        if existing_admin:
            print(f"Admin already exists (user_id={existing_admin.user_id}); nothing to do.")
            return 0

        admin = User(
            email=email,
            password_hash=hash_password(settings.admin_password),
            name="Administrator",
            department="admin",
            role=RoleEnum.admin,
            is_deleted=False,
            is_deactivated=False,
            token_version=0,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        # Never log the plain-text password.
        print(f"Admin created: user_id={admin.user_id}, email={admin.email}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
