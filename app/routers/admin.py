from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import AuditAction, RoleEnum, User
from app.schemas import UserListPage, UserOut, UserUpdateAdmin
from app.services import audit
from app.services.admin_guard import is_last_active_admin

router = APIRouter(prefix="/admin/users", tags=["admin"])


def _get_target_for_read(db: Session, user_id: int) -> User:
    # Read-only guard: any non-deleted user (incl. self and other admins) is visible.
    target = db.query(User).filter(User.user_id == user_id).first()
    if not target or target.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return target


def _get_target_for_mutation(db: Session, user_id: int, admin: User) -> User:
    """Mutation guard: target must exist, not be deleted, and not be the acting admin.
    Other admins are now valid targets — admins manage everyone except themselves."""
    target = db.query(User).filter(User.user_id == user_id).first()
    if not target or target.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target.user_id == admin.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot manage your own account here")
    return target


@router.get("", response_model=UserListPage)
def list_users(
    department: str | None = Query(default=None),
    is_deactivated: bool | None = Query(default=None),
    role: RoleEnum | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    # Includes admins so admins can see each other; still excludes soft-deleted.
    query = db.query(User).filter(User.is_deleted.is_(False))
    if department is not None:
        query = query.filter(User.department == department)
    if is_deactivated is not None:
        query = query.filter(User.is_deactivated.is_(is_deactivated))
    if role is not None:
        query = query.filter(User.role == role)

    total = query.count()
    items = query.order_by(User.user_id).offset(offset).limit(limit).all()
    return UserListPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return _get_target_for_read(db, user_id)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateAdmin,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_target_for_mutation(db, user_id, admin)
    data = payload.model_dump(exclude_unset=True)

    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "No fields to update")

    # Role change can go either direction (user ↔ admin). Demoting the sole
    # active admin would strand the system → 409.
    new_role = data.get("role")
    role_changed = new_role is not None and new_role != target.role
    if role_changed and new_role != RoleEnum.admin and is_last_active_admin(db, target):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Cannot demote the last active admin"
        )

    before = {k: getattr(target, k) for k in data.keys()}
    for field, value in data.items():
        setattr(target, field, value)
    if role_changed:
        target.token_version += 1  # Permissions changed → old tokens die.

    audit.record(
        db,
        actor=admin,
        action=AuditAction.user_role_change if role_changed else AuditAction.user_update,
        target=target,
        details={"before": before, "after": data},
    )
    db.commit()
    db.refresh(target)
    return target


def _atomic_set_flag(
    db: Session,
    user_id: int,
    *,
    where_flag: str,
    where_value: bool,
    set_values: dict,
) -> int:
    """Conditional UPDATE: applies only if `where_flag` currently equals
    `where_value`. Returns rows updated (0 = someone else won the race)."""
    column = getattr(User, where_flag)
    return (
        db.query(User)
        .filter(
            User.user_id == user_id,
            User.is_deleted.is_(False),
            column.is_(where_value),
        )
        .update(set_values, synchronize_session=False)
    )


@router.post("/{user_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_target_for_mutation(db, user_id, admin)

    # Cannot deactivate the last active admin — would lock everyone out.
    if is_last_active_admin(db, target):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Cannot deactivate the last active admin"
        )

    rows = _atomic_set_flag(
        db,
        target.user_id,
        where_flag="is_deactivated",
        where_value=False,
        set_values={
            User.is_deactivated: True,
            User.token_version: User.token_version + 1,
        },
    )
    if rows == 0:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "User is already deactivated")

    audit.record(db, actor=admin, action=AuditAction.user_deactivate, target=target)
    db.commit()


@router.post("/{user_id}/reactivate", status_code=status.HTTP_204_NO_CONTENT)
def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_target_for_mutation(db, user_id, admin)

    rows = _atomic_set_flag(
        db,
        target.user_id,
        where_flag="is_deactivated",
        where_value=True,
        set_values={User.is_deactivated: False},  # token_version intentionally NOT reset.
    )
    if rows == 0:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "User is already active")

    audit.record(db, actor=admin, action=AuditAction.user_reactivate, target=target)
    db.commit()


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_target_for_mutation(db, user_id, admin)

    if is_last_active_admin(db, target):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Cannot delete the last active admin"
        )

    rows = _atomic_set_flag(
        db,
        target.user_id,
        where_flag="is_deleted",
        where_value=False,
        set_values={
            User.is_deleted: True,
            User.deleted_at: datetime.utcnow(),
            User.token_version: User.token_version + 1,
        },
    )
    if rows == 0:
        db.rollback()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    audit.record(db, actor=admin, action=AuditAction.user_delete, target=target)
    db.commit()
