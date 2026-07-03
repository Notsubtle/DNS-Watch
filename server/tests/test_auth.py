"""Optional HTTP Basic auth middleware."""

from __future__ import annotations

import base64


def test_open_when_no_password(client):
    # Default fixtures set no password -> everything open.
    assert client.get("/api/summary?range=all").status_code == 200


def test_enforced_when_password_set(client, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "AUTH_PASSWORD", "s3cret")
    monkeypatch.setattr(main, "AUTH_USERNAME", "admin")

    assert client.get("/api/summary?range=all").status_code == 401
    assert "www-authenticate" in {k.lower() for k in client.get("/api/summary?range=all").headers}

    ok = base64.b64encode(b"admin:s3cret").decode()
    assert client.get("/api/summary?range=all", headers={"Authorization": f"Basic {ok}"}).status_code == 200

    for creds in (b"admin:wrong", b"root:s3cret"):
        bad = base64.b64encode(creds).decode()
        assert client.get("/api/summary?range=all", headers={"Authorization": f"Basic {bad}"}).status_code == 401

    assert client.get("/api/summary?range=all", headers={"Authorization": "Basic !!notb64"}).status_code == 401


def test_health_exempt_from_auth(client, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "AUTH_PASSWORD", "s3cret")
    assert client.get("/api/health").status_code == 200
