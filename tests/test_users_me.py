"""Self-service /users/me endpoints.

Policy: users can view themselves and change their password, but can no
longer edit profile details or deactivate themselves — only admins do that.
"""
from tests.conftest import USER_EMAIL, USER_PASSWORD


def test_read_me(client, user_headers):
    r = client.get("/users/me", headers=user_headers)
    assert r.status_code == 200
    assert r.json()["email"] == USER_EMAIL
    assert "password_hash" not in r.json()


def test_read_me_requires_auth(client):
    r = client.get("/users/me")
    assert r.status_code in (401, 403)


def test_patch_me_is_gone(client, user_headers):
    r = client.patch("/users/me", headers=user_headers, json={"name": "Jane Doe"})
    assert r.status_code in (404, 405)  # Route removed → 405 for /me, 404 for /me/deactivate.


def test_self_deactivate_is_gone(client, user_headers):
    r = client.post("/users/me/deactivate", headers=user_headers)
    assert r.status_code in (404, 405)


def test_change_password_invalidates_old_token(client, user_headers):
    r = client.post(
        "/users/me/change-password",
        headers=user_headers,
        json={"current_password": USER_PASSWORD, "new_password": "NewPass$1234"},
    )
    assert r.status_code == 204

    # Old token invalid.
    r = client.get("/users/me", headers=user_headers)
    assert r.status_code == 401

    # Old password rejected.
    r = client.post("/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD})
    assert r.status_code == 401

    # New password works.
    r = client.post("/auth/login", json={"email": USER_EMAIL, "password": "NewPass$1234"})
    assert r.status_code == 200


def test_change_password_wrong_current(client, user_headers):
    r = client.post(
        "/users/me/change-password",
        headers=user_headers,
        json={"current_password": "WrongPass$1", "new_password": "NewPass$1234"},
    )
    assert r.status_code == 401
