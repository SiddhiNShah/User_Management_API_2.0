import enum
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Enum, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class RoleEnum(str, enum.Enum):
    user = "user"
    admin = "admin"


class GenderEnum(str, enum.Enum):
    male = "male"
    female = "female"
    other = "other"
    prefer_not_to_say = "prefer_not_to_say"


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Email is stored trimmed + lowercased; uniqueness is enforced only among non-deleted rows
    # (see partial index below) so soft-deleted emails may be reused.
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # Birthdate and gender are optional per the plan.
    birthdate: Mapped[date | None] = mapped_column(Date, nullable=True)
    gender: Mapped[GenderEnum | None] = mapped_column(Enum(GenderEnum), nullable=True)
    department: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[RoleEnum] = mapped_column(Enum(RoleEnum), nullable=False, default=RoleEnum.user)

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_deactivated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Bumped on password change, deactivation, deletion, or role change to invalidate old JWTs.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        # Case-insensitive uniqueness only for active (non-deleted) accounts.
        Index(
            "ux_users_email_active",
            text("lower(email)"),
            unique=True,
            sqlite_where=text("is_deleted = 0"),
            postgresql_where=text("is_deleted = false"),
        ),
    )


class AuditAction(str, enum.Enum):
    # Admin-triggered account changes. Extend as new admin actions are added.
    user_update = "user.update"
    user_role_change = "user.role_change"
    user_deactivate = "user.deactivate"
    user_reactivate = "user.reactivate"
    user_delete = "user.delete"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # The admin performing the action. Nullable + SET NULL so audit history survives
    # if the actor's row is ever removed.
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True
    )
    # The user being acted on. Nullable for the same reason.
    target_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True
    )

    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False, index=True)
    # Free-form JSON string with action-specific context (e.g., changed fields).
    # NEVER store passwords, hashes, or tokens.
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, index=True
    )
