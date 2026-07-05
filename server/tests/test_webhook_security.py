"""Fixes for findings from the security review of server/app/alerts.py.

Two things covered here:
1. SSRF hardening for the user-supplied webhook URL. DNS Watch's webhook feature
   intentionally targets LAN services (Home Assistant, self-hosted ntfy), so
   private (RFC1918) and loopback addresses must stay reachable — only
   link-local/metadata, multicast, unspecified, and reserved ranges, plus
   non-http(s) schemes, are blocked. Also verifies redirects aren't auto-followed.
2. The webhook auth secret is never returned in plaintext by GET /api/settings —
   only whether one is set — since it's a bearer credential for an external
   service and the API has no auth by default.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


@pytest.mark.parametrize("url,expect_substr", [
    ("file:///etc/passwd", "scheme"),
    ("ftp://example.com/x", "scheme"),
    ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),  # cloud metadata
    ("http://[fe80::1]/x", "fe80::1"),                                # IPv6 link-local
    ("http://224.0.0.1/x", "224.0.0.1"),                              # multicast
    ("http://0.0.0.0/x", "0.0.0.0"),                                  # unspecified
])
def test_validator_blocks_unsafe_targets(url, expect_substr):
    from app.alerts import _validate_webhook_url
    ip, err = _validate_webhook_url(url)
    assert ip is None
    assert err is not None
    assert expect_substr in err


@pytest.mark.parametrize("url", [
    "http://192.168.1.50/x",   # RFC1918 private LAN — the documented use case
    "http://10.0.0.5:8123/x",  # e.g. Home Assistant on a LAN
    "http://127.0.0.1:9999/x",  # IPv4 loopback — used by our own test mock server
    "http://[::1]:9999/x",      # IPv6 loopback — same policy as IPv4 loopback
    "https://8.8.8.8/x",
])
def test_validator_allows_lan_and_loopback_targets(url):
    from app.alerts import _validate_webhook_url
    ip, err = _validate_webhook_url(url)
    assert err is None
    assert ip is not None


def test_validator_returns_the_pinned_ip_on_success():
    from app.alerts import _validate_webhook_url
    ip, err = _validate_webhook_url("http://127.0.0.1:9999/x")
    assert err is None
    assert ip == "127.0.0.1"


def test_deliver_webhook_rejects_before_any_network_call():
    # A literal IP needs no DNS lookup, so this stays fast and deterministic
    # regardless of the test environment's network access.
    from app.alerts import deliver_webhook
    ok, err = deliver_webhook("http://169.254.169.254/latest/meta-data/", {"x": 1})
    assert ok is False
    assert "169.254.169.254" in err


def test_api_test_webhook_rejects_metadata_target(client):
    r = client.post("/api/settings/test-webhook", json={"url": "http://169.254.169.254/x"}).json()
    assert r["ok"] is False
    assert "169.254.169.254" in r["error"]


def test_api_test_webhook_rejects_bad_scheme(client):
    r = client.post("/api/settings/test-webhook", json={"url": "file:///etc/passwd"}).json()
    assert r["ok"] is False
    assert "scheme" in r["error"]


@pytest.fixture
def redirecting_webhook():
    """A server that always responds 302, pointing at a second (also-loopback)
    server. If redirects were auto-followed, the second server would receive
    the POST; this proves it never does."""
    followed = []

    class Target(BaseHTTPRequestHandler):
        def do_POST(self):
            followed.append(True)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    target = HTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    target_url = f"http://127.0.0.1:{target.server_address[1]}/landed"

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", target_url)
            self.end_headers()

        def log_message(self, *a):
            pass

    redirector = HTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=redirector.serve_forever, daemon=True).start()

    yield f"http://127.0.0.1:{redirector.server_address[1]}/hook", followed
    redirector.shutdown()
    target.shutdown()


def test_deliver_webhook_does_not_follow_redirects(redirecting_webhook):
    # Declining the redirect makes urllib raise HTTPError for the 3xx status
    # (rather than returning it as a normal response) — caught by deliver_webhook's
    # except clause. Either way, ok=False and the redirect target is never hit,
    # which is the property that actually matters here.
    from app.alerts import deliver_webhook
    url, followed = redirecting_webhook
    ok, err = deliver_webhook(url, {"x": 1})
    assert ok is False
    assert "302" in err
    assert followed == []  # the redirect target never received the request


# --------------------------------------------------------------------------
# DNS-rebinding TOCTOU: the connection must use the IP validation already
# checked, not re-resolve the hostname when it actually opens.
# --------------------------------------------------------------------------

def test_deliver_webhook_connects_to_the_pinned_ip_not_a_re_resolved_host(webhook, monkeypatch):
    """Regression for the DNS-rebinding gap: the old implementation validated
    the resolved IP once, then handed the ORIGINAL URL to urllib, which
    re-resolved the hostname independently when it opened the connection — a
    rebinding attacker (short-TTL DNS record) could swap in an unsafe address
    between the two lookups. The fix pins the validated IP for the actual
    connection, so the hostname itself must be resolved exactly once, and any
    later resolution (e.g. inside socket.create_connection when the TCP
    connection opens) must operate on that already-validated literal IP —
    never ask the resolver about the original hostname a second time.
    """
    import socket as socket_mod

    from app import alerts

    url, received = webhook
    fake_host = "totally-fake-webhook-host.invalid"
    fake_url = url.replace("127.0.0.1", fake_host)

    real_getaddrinfo = socket_mod.getaddrinfo
    resolved_hosts = []

    def fake_getaddrinfo(host, *args, **kwargs):
        resolved_hosts.append(host)
        if host == fake_host:
            return real_getaddrinfo("127.0.0.1", *args, **kwargs)
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket_mod, "getaddrinfo", fake_getaddrinfo)
    ok, err = alerts.deliver_webhook(fake_url, {"probe": 1})

    assert ok is True, err
    assert len(received) == 1
    assert resolved_hosts[0] == fake_host  # validation resolves it once
    assert fake_host not in resolved_hosts[1:]  # never asked again downstream


# --------------------------------------------------------------------------
# Webhook secret is never returned in plaintext
# --------------------------------------------------------------------------

def test_get_settings_never_returns_raw_secret(client):
    client.patch("/api/settings", json={"webhook_secret": "tok_super_secret"})
    body = client.get("/api/settings").json()
    assert "webhook_secret" not in body
    assert body["webhook_secret_set"] is True
    assert "tok_super_secret" not in json.dumps(body)


def test_get_settings_secret_set_false_when_absent(client):
    assert client.get("/api/settings").json()["webhook_secret_set"] is False


def test_patch_response_also_omits_raw_secret(client):
    body = client.patch("/api/settings", json={"webhook_secret": "another_tok"}).json()
    assert "webhook_secret" not in body
    assert body["webhook_secret_set"] is True


def test_omitting_secret_on_patch_preserves_existing_value(client):
    from app.alerts import _get_raw_settings
    client.patch("/api/settings", json={"webhook_secret": "keep_me"})
    # A later PATCH that doesn't mention webhook_secret at all must not touch it.
    client.patch("/api/settings", json={"webhook_url": "http://192.168.1.5/hook"})
    assert _get_raw_settings()["webhook_secret"] == "keep_me"
    assert client.get("/api/settings").json()["webhook_secret_set"] is True


def test_empty_string_secret_clears_it(client):
    from app.alerts import _get_raw_settings
    client.patch("/api/settings", json={"webhook_secret": "temp"})
    client.patch("/api/settings", json={"webhook_secret": ""})
    assert _get_raw_settings()["webhook_secret"] == ""
    assert client.get("/api/settings").json()["webhook_secret_set"] is False


def test_fire_still_delivers_with_secret_after_masking_fix(client, webhook):
    # End-to-end: the masking fix must not break actual delivery, which needs the
    # real secret internally even though the API never exposes it.
    import time
    url, received = webhook
    client.patch("/api/settings", json={
        "webhook_enabled": True, "webhook_url": url, "webhook_secret": "real_tok"})
    client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600}})
    before = len(received)
    assert client.get("/api/alerts").json()["new"] > 0
    deadline = time.time() + 5
    while len(received) <= before and time.time() < deadline:
        time.sleep(0.03)
    assert len(received) > before
    assert received[-1]["auth"] == "Bearer real_tok"
