"""Shared pytest fixtures.

Each test gets its own in-memory SQLite DB so tests are independent and fast.
`StaticPool` + a shared engine ensure every session sees the same in-memory DB.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import RoleEnum, User
from app.security import hash_password

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Admin$1234"
USER_EMAIL = "jane@example.com"
USER_PASSWORD = "Jane$1234"


@pytest.fixture
def engine():
    # In-memory SQLite shared across sessions via StaticPool.
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)
    eng.dispose()


@pytest.fixture
def TestingSessionLocal(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def db(TestingSessionLocal):
    # Session for direct DB manipulation in tests (seeding, assertions).
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(TestingSessionLocal):
    # Override FastAPI's get_db to use the test engine.
    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---- Account fixtures ----

@pytest.fixture
def admin(db) -> User:
    u = User(
        email=ADMIN_EMAIL,
        password_hash=hash_password(ADMIN_PASSWORD),
        name="Admin",
        department="admin",
        role=RoleEnum.admin,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _login(client: TestClient, email: str, password: str) -> str:
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def admin_headers(client, admin):
    return {"Authorization": f"Bearer {_login(client, ADMIN_EMAIL, ADMIN_PASSWORD)}"}


@pytest.fixture
def registered_user(client):
    r = client.post(
        "/auth/register",
        json={"email": USER_EMAIL, "password": USER_PASSWORD, "name": "Jane"},
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def user_headers(client, registered_user):
    return {"Authorization": f"Bearer {_login(client, USER_EMAIL, USER_PASSWORD)}"}
