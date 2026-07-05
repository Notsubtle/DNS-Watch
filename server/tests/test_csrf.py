"""CSRF protection on state-changing routes.

HTTP Basic auth has no built-in CSRF defense on its own — a browser attaches
cached credentials to any request sent to this origin, including ones
triggered by a page the victim merely visits. See server/app/main.py's
csrf_guard docstring for the reasoning behind the Origin/Referer check.
"""

from __future__ import annotations


def test_cross_origin_post_rejected(client):
    r = client.post(
        "/api/alert-rules",
        json={"name": "x", "type": "new_device", "params": {}},
        headers={"Origin": "http://evil.example"},
    )
    assert r.status_code == 403


def test_same_origin_post_allowed(client):
    r = client.post(
        "/api/alert-rules",
        json={"name": "x", "type": "new_device", "params": {}},
        headers={"Origin": "http://testserver"},
    )
    assert r.status_code == 200


def test_post_without_origin_or_referer_allowed(client):
    # Non-browser clients (curl, server-to-server calls) send neither header —
    # the guard only blocks requests that identify a mismatched origin.
    r = client.post(
        "/api/alert-rules",
        json={"name": "x", "type": "new_device", "params": {}},
    )
    assert r.status_code == 200


def test_cross_origin_referer_rejected(client):
    r = client.delete(
        "/api/alert-rules/1",
        headers={"Referer": "http://evil.example/attack.html"},
    )
    assert r.status_code == 403


def test_same_origin_referer_allowed(client):
    r = client.patch(
        "/api/settings",
        json={"webhook_enabled": False},
        headers={"Referer": "http://testserver/settings"},
    )
    assert r.status_code == 200


def test_get_requests_not_subject_to_csrf_guard(client):
    r = client.get("/api/summary?range=1h", headers={"Origin": "http://evil.example"})
    assert r.status_code == 200
