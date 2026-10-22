from sqlalchemy.orm import Session

from app.models import RoleEnum, User


def active_admin_count(db: Session) -> int:
    # Admins who can actually log in and perform admin actions.
    return (
        db.query(User)
        .filter(
            User.role == RoleEnum.admin,
            User.is_deleted.is_(False),
            User.is_deactivated.is_(False),
        )
        .count()
    )


def is_last_active_admin(db: Session, target: User) -> bool:
    # True if removing/demoting/deactivating `target` would leave zero active admins.
    if target.role != RoleEnum.admin:
        return False
    if target.is_deleted or target.is_deactivated:
        return False
    return active_admin_count(db) <= 1
