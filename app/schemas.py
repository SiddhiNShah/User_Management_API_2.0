import re
from datetime import date

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models import GenderEnum, RoleEnum

# Password policy: 8-30 printable-ASCII chars, >=1 upper, >=1 lower,
# >=1 digit, >=1 non-alphanumeric (any special, e.g. !@#$%^&*()_+-=.,?/).
# [\x21-\x7e] = printable ASCII minus space, so emoji/whitespace are rejected.
_PASSWORD_RE = re.compile(
    r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])[\x21-\x7e]{8,30}$"
)


def _validate_password(v: str) -> str:
    if not _PASSWORD_RE.match(v):
        raise ValueError(
            "Password must be 8-30 printable ASCII chars with at least one "
            "uppercase, lowercase, digit, and special character"
        )
    return v


class UserRegister(BaseModel):
    # Only fields the public may set at registration.
    model_config = ConfigDict(extra="forbid")  # Reject unknown fields.

    email: EmailStr
    password: str = Field(min_length=8, max_length=30)
    name: str = Field(min_length=1, max_length=120)
    birthdate: date | None = None
    gender: GenderEnum | None = None

    @field_validator("password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("birthdate")
    @classmethod
    def _birthdate_not_future(cls, v: date | None) -> date | None:
        if v is not None and v > date.today():
            raise ValueError("birthdate cannot be in the future")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    # Public user shape — never includes password_hash or token_version.
    model_config = ConfigDict(from_attributes=True)

    user_id: int
    email: EmailStr
    name: str
    birthdate: date | None
    gender: GenderEnum | None
    department: str
    role: RoleEnum
    is_deactivated: bool


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---- Self-service (users/me) ----
# Note: PATCH /users/me and POST /users/me/deactivate were removed —
# only admins can change user details or deactivate accounts.

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _check_new_password(cls, v: str) -> str:
        return _validate_password(v)


# ---- Admin updates ----

class UserUpdateAdmin(BaseModel):
    # Admins can edit name/birthdate/gender/department and promote user → admin.
    # Demotion (admin → user) is blocked at the handler level.
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    birthdate: date | None = None
    gender: GenderEnum | None = None
    department: str | None = Field(default=None, min_length=1, max_length=120)
    role: RoleEnum | None = None

    @field_validator("name", mode="before")
    @classmethod
    def _reject_null_name(cls, v):
        if v is None:
            raise ValueError("name cannot be null")
        return v

    @field_validator("department", mode="before")
    @classmethod
    def _reject_null_department(cls, v):
        if v is None:
            raise ValueError("department cannot be null")
        return v

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("birthdate")
    @classmethod
    def _birthdate_not_future(cls, v: date | None) -> date | None:
        if v is not None and v > date.today():
            raise ValueError("birthdate cannot be in the future")
        return v


class UserListPage(BaseModel):
    # Paginated response for GET /admin/users.
    items: list[UserOut]
    total: int
    limit: int
    offset: int
