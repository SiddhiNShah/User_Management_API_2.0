"""/admin/users endpoints.

Policy: admins manage everyone except themselves. Role changes go both
directions (promote/demote). The last-active-admin guard is defensive —
in normal flows the self-guard fires first because the only way the TARGET
could be the sole active admin while the ACTOR is also an active admin is a
contradiction (two active admins exist). We cover it with a unit test on
the guard function itself.
"""
from app.models import RoleEnum, User
from app.security import hash_password
from app.services.admin_guard import active_admin_count, is_last_active_admin
from tests.conftest import USER_EMAIL, USER_PASSWORD


def _make_second_admin(db) -> User:
    u = User(
        email="admin2@example.com",
        password_hash=hash_password("Admin$5678"),
        name="Admin Two",
        department="admin",
        role=RoleEnum.admin,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


# ---- Authorization ----

def test_admin_endpoints_require_admin(client, user_headers):
    r = client.get("/admin/users", headers=user_headers)
    assert r.status_code == 403


# ---- Listing ----

def test_list_includes_admins_excludes_deleted(client, admin_headers, registered_user):
    r = client.get("/admin/users", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    assert {u["email"] for u in body["items"]} == {"admin@example.com", USER_EMAIL}


def test_list_filter_by_role(client, admin_headers, registered_user):
    assert client.get("/admin/users?role=user", headers=admin_headers).json()["total"] == 1
    assert client.get("/admin/users?role=admin", headers=admin_headers).json()["total"] == 1


def test_list_filter_by_deactivation(client, admin_headers, registered_user):
    client.post(f"/admin/users/{registered_user['user_id']}/deactivate", headers=admin_headers)
    assert client.get("/admin/users?is_deactivated=true", headers=admin_headers).json()["total"] == 1
    assert client.get("/admin/users?is_deactivated=false", headers=admin_headers).json()["total"] == 1


# ---- GET /{id} ----

def test_admin_can_view_self(client, admin, admin_headers):
    r = client.get(f"/admin/users/{admin.user_id}", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_get_deleted_user_404(client, admin_headers, registered_user):
    client.delete(f"/admin/users/{registered_user['user_id']}", headers=admin_headers)
    r = client.get(f"/admin/users/{registered_user['user_id']}", headers=admin_headers)
    assert r.status_code == 404


# ---- PATCH ----

def test_update_user_name(client, admin_headers, registered_user):
    r = client.patch(
        f"/admin/users/{registered_user['user_id']}",
        headers=admin_headers,
        json={"name": "Updated"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "Updated"


def test_update_other_admin_name(client, admin_headers, db):
    other = _make_second_admin(db)
    r = client.patch(
        f"/admin/users/{other.user_id}",
        headers=admin_headers,
        json={"name": "Renamed Admin"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "Renamed Admin"


def test_update_user_empty_body_rejected(client, admin_headers, registered_user):
    r = client.patch(
        f"/admin/users/{registered_user['user_id']}", headers=admin_headers, json={}
    )
    assert r.status_code == 422


def test_update_user_null_department_rejected(client, admin_headers, registered_user):
    r = client.patch(
        f"/admin/users/{registered_user['user_id']}",
        headers=admin_headers,
        json={"department": None},
    )
    assert r.status_code == 422


# ---- Role changes ----

def test_promote_user_to_admin(client, admin_headers, registered_user):
    uid = registered_user["user_id"]
    r = client.patch(f"/admin/users/{uid}", headers=admin_headers, json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"

    # Original admin can still mutate the newly-promoted admin.
    r = client.patch(f"/admin/users/{uid}", headers=admin_headers, json={"name": "Promoted"})
    assert r.status_code == 200

    # Old user token invalidated — new login required.
    r = client.post("/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD})
    assert r.status_code == 200
    new_token = r.json()["access_token"]
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {new_token}"})
    assert r.status_code == 200


def test_demote_other_admin(client, admin_headers, db):
    other = _make_second_admin(db)
    r = client.patch(
        f"/admin/users/{other.user_id}", headers=admin_headers, json={"role": "user"}
    )
    assert r.status_code == 200
    assert r.json()["role"] == "user"


# ---- Deactivate / reactivate ----

def test_deactivate_then_double_deactivate(client, admin_headers, registered_user):
    uid = registered_user["user_id"]
    assert client.post(f"/admin/users/{uid}/deactivate", headers=admin_headers).status_code == 204
    assert client.post(f"/admin/users/{uid}/deactivate", headers=admin_headers).status_code == 409


def test_deactivate_other_admin(client, admin_headers, db):
    other = _make_second_admin(db)
    r = client.post(f"/admin/users/{other.user_id}/deactivate", headers=admin_headers)
    assert r.status_code == 204


def test_reactivate_flow(client, admin_headers, registered_user):
    uid = registered_user["user_id"]
    client.post(f"/admin/users/{uid}/deactivate", headers=admin_headers)
    assert client.post(f"/admin/users/{uid}/reactivate", headers=admin_headers).status_code == 204
    assert client.post(f"/admin/users/{uid}/reactivate", headers=admin_headers).status_code == 409
    r = client.post("/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD})
    assert r.status_code == 200


# ---- Delete ----

def test_delete_then_delete_again_404(client, admin_headers, registered_user):
    uid = registered_user["user_id"]
    assert client.delete(f"/admin/users/{uid}", headers=admin_headers).status_code == 204
    assert client.delete(f"/admin/users/{uid}", headers=admin_headers).status_code == 404


def test_delete_other_admin(client, admin_headers, db):
    other = _make_second_admin(db)
    r = client.delete(f"/admin/users/{other.user_id}", headers=admin_headers)
    assert r.status_code == 204


# ---- Self-protection ----

def test_admin_cannot_mutate_self(client, admin, admin_headers):
    uid = admin.user_id
    assert client.patch(f"/admin/users/{uid}", headers=admin_headers, json={"name": "X"}).status_code == 403
    assert client.post(f"/admin/users/{uid}/deactivate", headers=admin_headers).status_code == 403
    assert client.post(f"/admin/users/{uid}/reactivate", headers=admin_headers).status_code == 403
    assert client.delete(f"/admin/users/{uid}", headers=admin_headers).status_code == 403


# ---- Last-active-admin guard (unit tests on the service) ----

def test_last_active_admin_guard_true_when_sole_active(db, admin):
    assert active_admin_count(db) == 1
    assert is_last_active_admin(db, admin) is True


def test_last_active_admin_guard_false_with_two_admins(db, admin):
    other = _make_second_admin(db)
    assert active_admin_count(db) == 2
    assert is_last_active_admin(db, admin) is False
    assert is_last_active_admin(db, other) is False


def test_last_active_admin_guard_false_for_deactivated_target(db, admin):
    admin.is_deactivated = True
    db.commit()
    assert is_last_active_admin(db, admin) is False
