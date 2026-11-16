from conftest import _auth


def test_pages(client):
    for path in ("/login", "/register", "/privacy", "/about"):
        assert client.get(path).status_code == 200
    # unauthenticated console redirects to login
    r = client.get("/")
    assert r.status_code == 302


def test_register_login_flow(client, user):
    tok = user["token"]
    r = client.get("/api/auth/me", headers=_auth(tok))
    assert r.status_code == 200
    assert r.get_json()["email"] == user["email"]
    # wrong password
    r = client.post("/api/auth/login", json={
        "email": user["email"], "password": "wrongwrong1"})
    assert r.status_code == 401
    # tampered token
    r = client.get("/api/auth/me", headers=_auth(tok + "x"))
    assert r.status_code == 401
    # no token
    assert client.get("/api/auth/me").status_code == 401


def test_weak_password_and_bad_email(client):
    assert client.post("/api/auth/register", json={
        "email": "a@b.com", "password": "short"}).status_code == 400
    assert client.post("/api/auth/register", json={
        "email": "not-an-email", "password": "longenough1"}).status_code == 400


def test_duplicate_email(client):
    client.post("/api/auth/register", json={
        "email": "dup@example.com", "password": "hunter2hunter2"})
    r = client.post("/api/auth/register", json={
        "email": "dup@example.com", "password": "hunter2hunter2"})
    assert r.status_code == 409


def test_export_and_delete(client, user):
    tok = user["token"]
    r = client.get("/api/auth/export", headers=_auth(tok))
    assert r.status_code == 200
    assert set(r.get_json()) >= {"user", "policy", "actions", "audit"}
    r = client.delete("/api/auth/me", headers=_auth(tok))
    assert r.status_code == 200
    # old token is dead after deletion (token_version bumped row is gone)
    r = client.get("/api/auth/me", headers=_auth(tok))
    assert r.status_code == 401
