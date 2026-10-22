"""Register + login flows."""
from tests.conftest import USER_EMAIL, USER_PASSWORD


def test_register_success(client):
    r = client.post(
        "/auth/register",
        json={"email": USER_EMAIL, "password": USER_PASSWORD, "name": "Jane"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == USER_EMAIL
    assert body["role"] == "user"
    # Sensitive fields never surface in the response.
    assert "password" not in body
    assert "password_hash" not in body
    assert "token_version" not in body


def test_register_normalizes_email(client):
    r = client.post(
        "/auth/register",
        json={"email": "  Jane@Example.COM ", "password": USER_PASSWORD, "name": "Jane"},
    )
    assert r.status_code == 201
    assert r.json()["email"] == "jane@example.com"


def test_register_duplicate_email(client, registered_user):
    r = client.post(
        "/auth/register",
        json={"email": USER_EMAIL, "password": USER_PASSWORD, "name": "Jane2"},
    )
    assert r.status_code == 409


def test_register_rejects_weak_password(client):
    r = client.post(
        "/auth/register",
        json={"email": USER_EMAIL, "password": "weakpass", "name": "Jane"},
    )
    assert r.status_code == 422


def test_register_rejects_extra_fields(client):
    r = client.post(
        "/auth/register",
        json={
            "email": USER_EMAIL,
            "password": USER_PASSWORD,
            "name": "Jane",
            "role": "admin",  # Not allowed via public registration.
        },
    )
    assert r.status_code == 422


def test_register_defaults_role_and_department(client, registered_user):
    assert registered_user["role"] == "user"
    assert registered_user["department"]  # some default string present


def test_login_success(client, registered_user):
    r = client.post("/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD})
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"
    assert r.json()["access_token"]


def test_login_wrong_password(client, registered_user):
    r = client.post("/auth/login", json={"email": USER_EMAIL, "password": "WrongPass$1"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password"


def test_login_unknown_email_same_error(client):
    r = client.post("/auth/login", json={"email": "nobody@example.com", "password": USER_PASSWORD})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password"


def test_login_deactivated_blocked(client, registered_user, admin_headers):
    r = client.post(
        f"/admin/users/{registered_user['user_id']}/deactivate",
        headers=admin_headers,
    )
    assert r.status_code == 204
    r = client.post("/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD})
    assert r.status_code == 403


def test_soft_deleted_email_can_be_reused(client, registered_user, admin_headers):
    r = client.delete(
        f"/admin/users/{registered_user['user_id']}", headers=admin_headers
    )
    assert r.status_code == 204
    r = client.post(
        "/auth/register",
        json={"email": USER_EMAIL, "password": USER_PASSWORD, "name": "Jane New"},
    )
    assert r.status_code == 201
    assert r.json()["user_id"] != registered_user["user_id"]
