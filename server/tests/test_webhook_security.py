"""SSRF hardening for user-supplied webhook URLs (server/app/alerts.py).

DNS Watch's webhook feature intentionally targets LAN services (Home Assistant,
self-hosted ntfy), so private (RFC1918) and loopback addresses must stay
reachable — only link-local/metadata, multicast, unspecified, and reserved
ranges, plus non-http(s) schemes, are blocked. These tests pin that boundary
directly against the validator (no live network calls, so they're fast and
hermetic) plus one end-to-end check that redirects aren't auto-followed.
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
    err = _validate_webhook_url(url)
    assert err is not None
    assert expect_substr in err


@pytest.mark.parametrize("url", [
    "http://192.168.1.50/x",   # RFC1918 private LAN — the documented use case
    "http://10.0.0.5:8123/x",  # e.g. Home Assistant on a LAN
    "http://127.0.0.1:9999/x",  # loopback — used by our own test mock server
    "https://8.8.8.8/x",
])
def test_validator_allows_lan_and_loopback_targets(url):
    from app.alerts import _validate_webhook_url
    assert _validate_webhook_url(url) is None


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
