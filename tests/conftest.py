import os
import tempfile

import pytest

os.environ.setdefault("GATE_CONSOLE_SECRET_KEY", "test-secret-key-not-production")

import accounts
from app import app as flask_app


@pytest.fixture()
def tmp_store(tmp_path, monkeypatch):
    """A GateStore on a fresh temp database for every test."""
    path = str(tmp_path / "gate.db")
    monkeypatch.setattr(accounts, "DB_PATH", path)
    store = accounts.GateStore(path)
    monkeypatch.setattr(accounts, "_SIGNER",
                        accounts.URLSafeTimedSerializer("test-secret-key",
                                                        salt="gate-console-auth-v1"))
    return store


@pytest.fixture()
def app(tmp_store, monkeypatch):
    monkeypatch.setattr("app.store", tmp_store)
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user(client):
    c = client
    r = c.post("/api/auth/register", json={
        "email": "reviewer@example.com", "password": "hunter2hunter2"})
    assert r.status_code == 200
    tok = r.get_json()["token"]
    return {"email": "reviewer@example.com", "token": tok}


def _auth(tok):
    return {"Authorization": f"Bearer {tok}",
            "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    accounts._RATE.clear()
    yield
    accounts._RATE.clear()
