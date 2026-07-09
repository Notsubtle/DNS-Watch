"""Alert engine: rule CRUD, evaluation, cooldown, settings, webhook delivery."""

from __future__ import annotations

import time

# `webhook` fixture lives in conftest.py (shared with test_webhook_security.py).


def _wait(received, before, timeout=5):
    deadline = time.time() + timeout
    while len(received) <= before and time.time() < deadline:
        time.sleep(0.03)


def test_rule_crud(client):
    assert client.get("/api/alert-rules").json() == []
    r = client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600},
    })
    assert r.status_code == 200
    rid = r.json()["id"]
    assert client.patch(f"/api/alert-rules/{rid}", json={"enabled": False}).json()["enabled"] is False
    assert client.patch("/api/alert-rules/9999", json={"enabled": False}).status_code == 404
    assert client.delete(f"/api/alert-rules/{rid}").json() == {"deleted": rid}
    assert client.delete("/api/alert-rules/9999").status_code == 404


def test_invalid_rule_type_rejected(client):
    assert client.post("/api/alert-rules", json={"name": "x", "type": "bogus", "params": {}}).status_code == 400


def test_evaluation_and_cooldown(client):
    client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600}})
    client.post("/api/alert-rules", json={
        "name": "KW", "type": "domain_keyword",
        "params": {"keyword": "ads", "window_minutes": 600, "min_count": 1}})
    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})

    a = client.get("/api/alerts").json()
    assert a["new"] > 0
    types = {e["type"] for e in a["events"]}
    assert {"volume_threshold", "domain_keyword", "new_device"} <= types

    # Immediate re-eval fires nothing new (cooldown), event count stable.
    a2 = client.get("/api/alerts").json()
    assert a2["new"] == 0
    assert len(a2["events"]) == len(a["events"])


def test_volume_threshold_rule_scoped_to_tag(client):
    """#31: volume_threshold's overall ("any") scope can be narrowed to a tag
    instead of one client or the whole network. A threshold met by the tag's
    combined traffic but not by either client alone proves the scoping
    actually sums the group rather than silently falling back to "any"."""
    tag = client.post("/api/tags", json={"name": "Laptops"}).json()
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.10"})
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.11"})

    solo_10 = client.get("/api/summary", params={"client": "192.168.1.10", "range": "all"}).json()
    solo_11 = client.get("/api/summary", params={"client": "192.168.1.11", "range": "all"}).json()
    combined = solo_10["total_queries"] + solo_11["total_queries"]
    threshold = max(solo_10["total_queries"], solo_11["total_queries"]) + 1
    assert threshold <= combined, "fixture didn't produce enough traffic for this test to be meaningful"

    client.post("/api/alert-rules", json={
        "name": "TagVol", "type": "volume_threshold",
        "params": {"scope": "any", "tag": "Laptops", "threshold": threshold, "window_minutes": 600000}})
    events = client.get("/api/alerts").json()["events"]
    tag_events = [e for e in events if e["type"] == "volume_threshold"]
    assert tag_events and any('tag "Laptops"' in e["message"] for e in tag_events)


def test_domain_keyword_rule_scoped_to_tag_excludes_other_clients(client):
    """#31: an untagged client's matching queries must not count toward a
    tag-scoped domain_keyword rule."""
    tag = client.post("/api/tags", json={"name": "JustLaptop"}).json()
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.10"})

    global_count = client.get(
        "/api/queries", params={"domain": "ads", "range": "all", "limit": 1}
    ).json()["total"]
    tagged_count = client.get(
        "/api/queries", params={"domain": "ads", "tag": "JustLaptop", "range": "all", "limit": 1}
    ).json()["total"]
    assert tagged_count <= global_count

    client.post("/api/alert-rules", json={
        "name": "TagKW", "type": "domain_keyword",
        "params": {"keyword": "ads", "tag": "JustLaptop", "min_count": max(tagged_count, 1),
                   "window_minutes": 600000}})
    events = client.get("/api/alerts").json()["events"]
    kw_events = [e for e in events if e["type"] == "domain_keyword"]
    assert (len(kw_events) > 0) == (tagged_count > 0)
    if tagged_count > 0:
        assert any("JustLaptop" in e["message"] for e in kw_events)


def test_device_quiet_rule(client, ftl):
    import sqlite3
    from conftest import CLIENTS
    # Add a client that was busy ~90 min ago but silent since -> should trip a
    # device_quiet rule with a 60m window.
    now = int(__import__("time").time())
    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        conn.execute("INSERT INTO client VALUES (98,'192.168.1.98','oldtv')")
        for _ in range(30):
            conn.execute("INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,98)",
                         (now - 90 * 60, 1, 2, "a.example.com"))
    elif ftl["schema"] == "real":
        conn.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (98,'de:ad:be:ef:00:62','TestVendor')")
        conn.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                     "VALUES (98,'192.168.1.98',?,'oldtv',?)", (now, now))
        for _ in range(30):
            conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,'192.168.1.98')",
                         (float(now - 90 * 60), 1, 2, "a.example.com"))
    elif ftl["schema"] == "idstore":
        from conftest import _idstore_client_id, _idstore_domain_id
        cid = _idstore_client_id(conn.cursor(), "192.168.1.98", "oldtv")
        did = _idstore_domain_id(conn.cursor(), "a.example.com")
        for _ in range(30):
            conn.execute("INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                         (now - 90 * 60, 1, 2, did, cid))
    else:
        conn.execute("INSERT INTO network VALUES (98,'oldtv')")
        conn.execute("INSERT INTO network_addresses VALUES ('192.168.1.98',98)")
        for _ in range(30):
            conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,'192.168.1.98')",
                         (now - 90 * 60, 1, 2, "a.example.com"))
    conn.commit()
    conn.close()

    client.post("/api/alert-rules", json={
        "name": "Quiet", "type": "device_quiet",
        "params": {"window_minutes": 60, "min_prior": 20}})
    events = client.get("/api/alerts").json()["events"]
    quiet = [e for e in events if e["type"] == "device_quiet"]
    assert quiet and any("oldtv" in e["message"] for e in quiet)

    # #6/#7: the same presence qualifier detect_anomalies()'s "silent" case
    # would attach for this client, so Alerts/Anomalies never disagree.
    from app import db
    msg = next(e["message"] for e in quiet if "oldtv" in e["message"])
    if ftl["schema"] in ("real", "idstore"):
        assert db.PRESENCE_MAC_KNOWN_NOTE in msg
    else:
        assert db.PRESENCE_MAC_UNKNOWN_NOTE in msg


def test_new_vendor_rule(client, ftl):
    """#12: complementary to new_device, but keyed on vendor rather than raw
    IP/first-seen. Only "real"/"idstore" schemas carry vendor data at all
    (see #4) -- db.vendor_alert_candidates() is a guaranteed no-op elsewhere,
    covered by test_new_vendor_rule_noop_without_vendor_data below."""
    if ftl["schema"] not in ("real", "idstore"):
        return
    import sqlite3
    from conftest import _idstore_client_id, _idstore_domain_id

    now = int(time.time())
    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "real":
        # A brand-new device from a vendor never seen on this network before.
        conn.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (99,'aa:bb:cc:dd:ee:99','NewCo')")
        conn.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                     "VALUES (99,'192.168.1.99',?,NULL,?)", (now, now))
        conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (float(now), 1, 2, "a.example.com", "192.168.1.99"))
        # A brand-new device with a real MAC that matches no vendor at all.
        conn.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (100,'10:20:30:99:99:99','')")
        conn.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                     "VALUES (100,'192.168.1.100',?,NULL,?)", (now, now))
        conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (float(now), 1, 2, "b.example.com", "192.168.1.100"))
    else:
        cur = conn.cursor()
        cid_new_vendor = _idstore_client_id(cur, "192.168.1.99", None)
        conn.execute(
            "UPDATE network SET hwaddr='aa:bb:cc:dd:ee:99', macVendor='NewCo' WHERE id = "
            "(SELECT network_id FROM network_addresses WHERE ip='192.168.1.99')"
        )
        did = _idstore_domain_id(cur, "a.example.com")
        conn.execute("INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (now, 1, 2, did, cid_new_vendor))

        cid_unlisted = _idstore_client_id(cur, "192.168.1.100", None)
        conn.execute(
            "UPDATE network SET hwaddr='10:20:30:99:99:99', macVendor='' WHERE id = "
            "(SELECT network_id FROM network_addresses WHERE ip='192.168.1.100')"
        )
        did2 = _idstore_domain_id(cur, "b.example.com")
        conn.execute("INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (now, 1, 2, did2, cid_unlisted))
    conn.commit()
    conn.close()

    client.post("/api/alert-rules", json={
        "name": "Vendor", "type": "new_vendor", "params": {"window_minutes": 60}})
    events = client.get("/api/alerts").json()["events"]
    vendor_events = [e for e in events if e["type"] == "new_vendor"]

    assert any("NewCo" in e["message"] and "192.168.1.99" in e["message"] for e in vendor_events)
    assert any(
        "unrecognized" in e["message"].lower() and "192.168.1.100" in e["message"]
        for e in vendor_events
    )
    # Whether the 4 standard CLIENTS (all sharing macVendor "TestVendor") also
    # count as "new" here depends on build_ftl's random first-seen offsets --
    # not deterministic enough to assert on directly in this fixture. The
    # "an already-established vendor doesn't re-fire" invariant is instead
    # covered precisely in test_db.py, with an exact, controlled after_ts.


def test_new_vendor_rule_noop_without_vendor_data(client, ftl):
    """#12: schemas with no vendor table at all must never fire this rule --
    every device would otherwise look "unrecognized" from a data gap, not an
    actual finding (see db.vendor_alert_candidates)."""
    if ftl["schema"] in ("real", "idstore"):
        return
    client.post("/api/alert-rules", json={
        "name": "Vendor", "type": "new_vendor", "params": {"window_minutes": 6000}})
    events = client.get("/api/alerts").json()["events"]
    assert not any(e["type"] == "new_vendor" for e in events)


def test_doh_provider_rule_fires_for_known_provider_domain(client, ftl):
    """#33 (scope-corrected): flags a client querying a well-known DoH/DoT
    provider's OWN domain (e.g. dns.google) -- a proxy "may be setting up or
    falling back to a resolver that bypasses Pi-hole" signal, honestly worded
    as exactly that, never as "bypass detected" (see db.DOH_PROVIDER_DOMAINS'
    module note for why that stronger claim would be false)."""
    import sqlite3
    from conftest import CLIENTS, _idstore_client_id, _idstore_domain_id

    now = int(time.time())
    conn = sqlite3.connect(ftl["path"])
    ip, name = CLIENTS[0]
    if ftl["schema"] == "new":
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,1)",
            (now, 1, 2, "dns.google"),
        )
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        cid = _idstore_client_id(cur, ip, name)
        did = _idstore_domain_id(cur, "dns.google")
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (now, 1, 2, did, cid),
        )
    else:  # "old" / "real"
        ts = float(now) if ftl["schema"] == "real" else now
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (ts, 1, 2, "dns.google", ip),
        )
    conn.commit()
    conn.close()

    client.post("/api/alert-rules", json={
        "name": "DoH", "type": "doh_provider", "params": {"window_minutes": 60}})
    events = client.get("/api/alerts").json()["events"]
    doh_events = [e for e in events if e["type"] == "doh_provider"]

    assert doh_events, "expected a doh_provider event to fire"
    msg = doh_events[0]["message"].lower()
    assert "dns.google" in msg
    assert ip in doh_events[0]["message"]
    # Honesty check: must read as a proxy signal, never a confirmed finding.
    assert "bypass" not in msg or "not" in msg or "may" in msg
    assert "detected" not in msg


def test_doh_provider_rule_quiet_when_no_provider_queries(client, ftl):
    """A client that never queries a known DoH/DoT provider domain must not
    trip this rule -- ordinary traffic (build_ftl's fixture domains) isn't a
    known provider domain, so this should stay silent by default."""
    client.post("/api/alert-rules", json={
        "name": "DoH", "type": "doh_provider", "params": {"window_minutes": 6000}})
    events = client.get("/api/alerts").json()["events"]
    assert not any(e["type"] == "doh_provider" for e in events)


def test_digest_rule_fires_once_per_period_then_on_rollover(ftl, store, monkeypatch):
    """#30: digest firing is gated on a UTC calendar period, not elapsed-time
    cooldown -- verify it fires once, stays silent on a repeat eval within the
    same period, then fires again once the (mocked) clock crosses into the
    next UTC day. Controls `now` directly (via alerts.time.time) rather than
    fudging the persisted schedule row, since the period string itself is
    derived from wall-clock time -- mutating only the stored row wouldn't
    actually change what period the next eval computes."""
    from app import alerts

    alerts.create_rule("Digest", "digest", {"period": "daily"})
    base = int(time.time())
    monkeypatch.setattr(alerts.time, "time", lambda: base)

    fired1 = alerts.evaluate()
    assert any(e["type"] == "digest" for e in fired1)

    # Same period, evaluated again -> no new digest event.
    fired2 = alerts.evaluate()
    assert not any(e["type"] == "digest" for e in fired2)

    # Cross a UTC day boundary -> a new period, so the digest fires again.
    monkeypatch.setattr(alerts.time, "time", lambda: base + 86400 + 5)
    fired3 = alerts.evaluate()
    assert any(e["type"] == "digest" for e in fired3)

    # And immediately re-evaluating the new period is quiet again.
    fired4 = alerts.evaluate()
    assert not any(e["type"] == "digest" for e in fired4)


def test_digest_message_mentions_period_and_summarizes_activity(client, store):
    """Digest content should be honest about what it's summarizing (events +
    new devices since the last digest), not a generic placeholder."""
    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})
    client.post("/api/alert-rules", json={
        "name": "Digest", "type": "digest", "params": {"period": "weekly"}})

    result = client.get("/api/alerts").json()
    digest_events = [e for e in result["events"] if e["type"] == "digest"]
    assert digest_events, "digest rule should have fired"
    msg = digest_events[0]["message"].lower()
    assert "weekly digest" in msg
    assert "device" in msg or "alert" in msg


def test_settings_roundtrip_and_format_validation(client):
    assert client.get("/api/settings").json()["webhook_enabled"] is False
    updated = client.patch("/api/settings", json={
        "webhook_enabled": True, "webhook_url": "http://x.invalid", "webhook_format": "discord"}).json()
    assert updated["webhook_format"] == "discord" and updated["webhook_enabled"] is True
    assert client.patch("/api/settings", json={"webhook_format": "telegram"}).status_code == 400


def test_test_webhook_success_and_failure(client, webhook):
    url, received = webhook
    r = client.post("/api/settings/test-webhook", json={"url": url, "secret": "tok", "format": "slack"}).json()
    assert r["ok"] is True
    assert received[-1]["body"].keys() == {"text"}          # slack shape
    assert received[-1]["auth"] == "Bearer tok"             # secret -> bearer

    dead = client.post("/api/settings/test-webhook", json={"url": "http://127.0.0.1:1/x"}).json()
    assert dead["ok"] is False and dead["error"]


def test_fire_delivers_webhook_in_format(client, webhook):
    url, received = webhook
    client.patch("/api/settings", json={
        "webhook_enabled": True, "webhook_url": url, "webhook_secret": "s3", "webhook_format": "discord"})
    client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600}})
    before = len(received)
    assert client.get("/api/alerts").json()["new"] > 0
    _wait(received, before)
    assert len(received) > before
    assert received[-1]["body"].keys() == {"content"}       # discord shape
    assert 0 < len(received[-1]["body"]["content"]) <= 2000
    assert received[-1]["auth"] == "Bearer s3"
