"""Alert engine: rule CRUD, evaluation, cooldown, settings, webhook delivery."""

from __future__ import annotations

import time

from conftest import add_client_with_hourly_pattern

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


def test_first_seen_domain_rule(client, ftl):
    """#32: domain-keyed sibling of new_device/new_vendor -- fires when a
    domain is queried that NO client has ever queried before, network-wide.
    Backed by rollups.new_domains(), so the rollup must be backfilled first
    (mirroring how a real deployment's scheduler tick would have already run
    at least once) before the new domain is inserted and picked up by a
    second refresh."""
    from app import rollups
    import sqlite3

    rollups.refresh_rollups()  # backfill everything build_ftl already seeded

    now = int(time.time())
    brand_new_domain = "totally-new-domain.example"
    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,1)",
            (now, 1, 2, brand_new_domain),
        )
    elif ftl["schema"] == "idstore":
        from conftest import _idstore_client_id, _idstore_domain_id
        cur = conn.cursor()
        cid = _idstore_client_id(cur, "192.168.1.10", "laptop")
        did = _idstore_domain_id(cur, brand_new_domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (now, 1, 2, did, cid),
        )
    else:  # "old" / "real"
        ts = float(now) if ftl["schema"] == "real" else now
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (ts, 1, 2, brand_new_domain, "192.168.1.10"),
        )
    conn.commit()
    conn.close()

    rollups.refresh_rollups()  # pick up the new domain into seen_domains

    client.post("/api/alert-rules", json={
        "name": "NewDomain", "type": "first_seen_domain", "params": {"window_minutes": 60}})
    events = client.get("/api/alerts").json()["events"]
    dom_events = [e for e in events if e["type"] == "first_seen_domain"]

    assert dom_events and any(brand_new_domain in e["message"] for e in dom_events)
    # Whether build_ftl's own fixture domains also count as "new" here depends
    # on its random first-seen offsets landing inside this same 60m window --
    # not deterministic enough to assert on in this fixture (same caveat as
    # test_new_vendor_rule's analogous note). The precise "an already-seen
    # domain outside the window doesn't re-fire" invariant is covered exactly,
    # with a controlled cutoff, by test_new_domains_matches_ground_truth in
    # test_rollup_reads.py.


def test_first_seen_domain_rule_noop_before_rollup_backfilled(client, ftl):
    """Before the rollup has ever been backfilled, rollups.new_domains()
    returns None (not []) -- the rule must treat that as "no signal yet",
    not misfire on every domain in build_ftl's fixture looking spuriously
    "new" from an empty seen_domains table."""
    client.post("/api/alert-rules", json={
        "name": "NewDomain", "type": "first_seen_domain", "params": {"window_minutes": 600000}})
    events = client.get("/api/alerts").json()["events"]
    assert not any(e["type"] == "first_seen_domain" for e in events)


def test_client_first_seen_domain_rule(client, ftl):
    """#1: per-client sibling of first_seen_domain -- fires when a SPECIFIC
    client queries a domain it has never queried before, even reusing a
    domain that already exists in build_ftl's fixture data (unlike
    first_seen_domain, this must NOT require the domain to be network-wide
    new). Backed by rollups.client_new_domains()."""
    from app import rollups
    import sqlite3

    rollups.refresh_rollups()  # backfill everything build_ftl already seeded

    now = int(time.time())
    reused_domain = "reused-for-this-client.example"
    target_ip = "192.168.1.10"
    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,1)",
            (now, 1, 2, reused_domain),
        )
    elif ftl["schema"] == "idstore":
        from conftest import _idstore_client_id, _idstore_domain_id
        cur = conn.cursor()
        cid = _idstore_client_id(cur, target_ip, "laptop")
        did = _idstore_domain_id(cur, reused_domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (now, 1, 2, did, cid),
        )
    else:  # "old" / "real"
        ts = float(now) if ftl["schema"] == "real" else now
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (ts, 1, 2, reused_domain, target_ip),
        )
    conn.commit()
    conn.close()

    rollups.refresh_rollups()  # pick up the new (client, domain) pair

    client.post("/api/alert-rules", json={
        "name": "ClientNewDomain", "type": "client_first_seen_domain",
        "params": {"window_minutes": 60}})
    events = client.get("/api/alerts").json()["events"]
    dom_events = [e for e in events if e["type"] == "client_first_seen_domain"]

    assert dom_events and any(reused_domain in e["message"] for e in dom_events)


def test_client_first_seen_domain_rule_noop_before_rollup_backfilled(client, ftl):
    """Same None-vs-[] contract as first_seen_domain: before the rollup has
    ever been backfilled, rollups.client_new_domains() returns None, and the
    rule must treat that as "no signal yet"."""
    client.post("/api/alert-rules", json={
        "name": "ClientNewDomain", "type": "client_first_seen_domain",
        "params": {"window_minutes": 600000}})
    events = client.get("/api/alerts").json()["events"]
    assert not any(e["type"] == "client_first_seen_domain" for e in events)


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


def test_digest_message_mentions_current_anomalies(ftl, store, monkeypatch):
    from app import alerts

    now = int(time.time())
    pattern = [15] * 27 + [0, 0, 0]
    add_client_with_hourly_pattern(
        ftl["path"], ftl["schema"], "10.0.0.57", "digest_silent", pattern, now
    )
    monkeypatch.setattr(alerts.time, "time", lambda: now)

    alerts.create_rule("Digest", "digest", {"period": "daily"})
    digest = next(e for e in alerts.evaluate() if e["type"] == "digest")

    msg = digest["message"].lower()
    assert "daily digest" in msg
    assert "1 anomaly(ies)" in msg
    assert "1 silent" in msg


def test_digest_message_omits_anomaly_clause_when_none(ftl, store, monkeypatch):
    from app import alerts

    now = int(time.time())
    monkeypatch.setattr(alerts.time, "time", lambda: now)

    alerts.create_rule("Digest", "digest", {"period": "daily"})
    digest = next(e for e in alerts.evaluate() if e["type"] == "digest")

    assert "anomal" not in digest["message"].lower()


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


def test_events_carry_structured_client_ip_and_domain(client):
    """#43: fired events must expose a structured target (client_ip/domain),
    not just a free-text message, so the frontend can deep-link into the
    dashboard/heatmap without parsing dedup_key strings."""
    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})
    events = client.get("/api/alerts").json()["events"]
    new_dev = next(e for e in events if e["type"] == "new_device")
    assert new_dev["client_ip"] is not None
    assert new_dev["domain"] is None
    assert new_dev["dedup_key"].startswith("new:")


def test_snooze_suppresses_only_that_recurrence(client):
    """#42: snoozing one client's fired new_device event must stop THAT
    client's alert from re-firing, without affecting a different client's
    otherwise-identical alert under the very same rule -- proves this is
    keyed on dedup_key (per-entity), not the rule as a whole."""
    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})
    events = client.get("/api/alerts").json()["events"]
    new_devs = [e for e in events if e["type"] == "new_device"]
    assert len(new_devs) >= 2, "fixture needs at least 2 new devices for this test"
    snoozed_event, other_event = new_devs[0], new_devs[1]

    until = int(time.time()) + 3600
    r = client.post(f"/api/alert-events/{snoozed_event['id']}/snooze", json={"until": until})
    assert r.status_code == 200
    assert r.json()["dedup_key"] == snoozed_event["dedup_key"]

    # Force both events past their normal cooldown so they'd otherwise both
    # re-fire -- isolating the snooze's effect from the ordinary cooldown gate.
    from app import alerts
    with alerts._connect() as conn:
        conn.execute("UPDATE alert_events SET created_at = 0")
        conn.commit()

    refired = client.get("/api/alerts").json()["events"]
    refired_keys = {e["dedup_key"] for e in refired}
    assert other_event["dedup_key"] in refired_keys, "the un-snoozed device's alert should still re-fire"
    # The snoozed one may still appear from its ORIGINAL insert (list_events
    # just reads history), so check it didn't get a NEWER created_at instead.
    resnoozed_rows = [e for e in refired if e["dedup_key"] == snoozed_event["dedup_key"]]
    assert all(e["created_at"] == 0 for e in resnoozed_rows), "snoozed recurrence must not re-fire"


def test_snooze_expires(client, monkeypatch):
    """A snooze must stop blocking re-fires once `until` has passed."""
    from app import alerts

    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})
    events = client.get("/api/alerts").json()["events"]
    ev = next(e for e in events if e["type"] == "new_device")

    base = int(time.time())
    monkeypatch.setattr(alerts.time, "time", lambda: base)
    until = base + 100
    client.post(f"/api/alert-events/{ev['id']}/snooze", json={"until": until})

    with alerts._connect() as conn:
        conn.execute("UPDATE alert_events SET created_at = 0 WHERE dedup_key = ?", (ev["dedup_key"],))
        conn.commit()

    # Still within the snooze window -> no re-fire.
    monkeypatch.setattr(alerts.time, "time", lambda: base + 50)
    still_snoozed = client.get("/api/alerts").json()["events"]
    assert all(e["created_at"] == 0 for e in still_snoozed if e["dedup_key"] == ev["dedup_key"])

    # Past `until` -> free to re-fire again.
    monkeypatch.setattr(alerts.time, "time", lambda: base + 200)
    after_expiry = client.get("/api/alerts").json()["events"]
    refired = [e for e in after_expiry if e["dedup_key"] == ev["dedup_key"]]
    assert any(e["created_at"] == base + 200 for e in refired)


def test_snooze_unknown_event_404s(client):
    assert client.post("/api/alert-events/9999/snooze", json={"until": 0}).status_code == 404


def test_unsnooze(client):
    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})
    ev = next(e for e in client.get("/api/alerts").json()["events"] if e["type"] == "new_device")
    until = int(time.time()) + 3600
    client.post(f"/api/alert-events/{ev['id']}/snooze", json={"until": until})

    r = client.delete(f"/api/alert-snoozes/{ev['dedup_key']}")
    assert r.status_code == 200

    # A second unsnooze of the same (now-removed) key 404s.
    assert client.delete(f"/api/alert-snoozes/{ev['dedup_key']}").status_code == 404


def _insert_new_client_query(ftl, ip: str, name: str, domain: str, ts: float) -> None:
    """A single query from a client NOT in the standard CLIENTS fixture,
    registering just enough per-schema identity plumbing for
    db.new_clients()/db.domain_queriers() to recognize it as genuinely new."""
    import sqlite3
    from conftest import _idstore_client_id, _idstore_domain_id

    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        next_id = conn.execute("SELECT COALESCE(MAX(id),0)+1 FROM client").fetchone()[0]
        conn.execute("INSERT INTO client (id, ip, name) VALUES (?,?,?)", (next_id, ip, name))
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, domain, next_id),
        )
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        cid = _idstore_client_id(cur, ip, name)
        did = _idstore_domain_id(cur, domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, did, cid),
        )
    else:  # "old" / "real"
        next_id = conn.execute("SELECT COALESCE(MAX(id),0)+1 FROM network").fetchone()[0]
        if ftl["schema"] == "real":
            conn.execute(
                "INSERT INTO network (id, hwaddr, macVendor) VALUES (?,?,NULL)",
                (next_id, f"aa:bb:cc:dd:ee:{next_id:02x}"),
            )
            conn.execute(
                "INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                "VALUES (?,?,?,?,?)",
                (next_id, ip, int(ts), name, int(ts)),
            )
        else:
            conn.execute("INSERT INTO network VALUES (?,?)", (next_id, name))
            conn.execute("INSERT INTO network_addresses VALUES (?,?)", (ip, next_id))
        stored_ts = float(ts) if ftl["schema"] == "real" else int(ts)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (stored_ts, 1, 2, domain, ip),
        )
    conn.commit()
    conn.close()


def _insert_existing_client_query(ftl, ip: str, domain: str, ts: float) -> None:
    """A query from an ALREADY-KNOWN CLIENTS ip -- reuses its existing
    identity rather than creating a new one, so this client's global
    first-seen is unaffected (or pulled further back if `ts` is older)."""
    import sqlite3
    from conftest import CLIENTS, _idstore_client_id, _idstore_domain_id

    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        cid = next(i for i, (cip, _) in enumerate(CLIENTS, 1) if cip == ip)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, domain, cid),
        )
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        name = next(n for cip, n in CLIENTS if cip == ip)
        cid = _idstore_client_id(cur, ip, name)
        did = _idstore_domain_id(cur, domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, did, cid),
        )
    else:
        stored_ts = float(ts) if ftl["schema"] == "real" else int(ts)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (stored_ts, 1, 2, domain, ip),
        )
    conn.commit()
    conn.close()


def test_correlated_new_device_domain_fires_for_matched_pair(client, ftl):
    """#46: a brand-new device querying a domain no client has ever queried
    before, within the same short window, is a much stronger signal than
    either half alone -- must fire, and the event must carry the structured
    client_ip/domain target (#43's deep-linking depends on this)."""
    from app import rollups

    rollups.refresh_rollups()  # backfill everything build_ftl already seeded

    now = int(time.time())
    new_ip, new_domain = "192.168.1.99", "iot-callback.example.test"
    _insert_new_client_query(ftl, new_ip, "gadget", new_domain, now)

    rollups.refresh_rollups()  # pick up the new domain into seen_domains

    client.post("/api/alert-rules", json={
        "name": "Corr", "type": "correlated_new_device_domain",
        "params": {"window_minutes": 60}})
    events = client.get("/api/alerts").json()["events"]
    corr = [e for e in events if e["type"] == "correlated_new_device_domain"]

    assert any(e["client_ip"] == new_ip and e["domain"] == new_domain for e in corr)
    hit = next(e for e in corr if e["client_ip"] == new_ip and e["domain"] == new_domain)
    assert hit["dedup_key"] == f"corr:{hit['rule_id']}:{new_ip}:{new_domain}"


def test_correlated_new_device_domain_requires_new_client_not_just_new_domain(client, ftl):
    """A first-seen domain queried ONLY by an ALREADY-established client must
    NOT fire this rule -- proves it's genuinely about the (new client, new
    domain) PAIR, not "a new domain exists somewhere and a new client exists
    somewhere else" (which first_seen_domain and new_device would each
    already cover on their own)."""
    from app import rollups
    from conftest import CLIENTS

    established_ip = CLIENTS[0][0]
    now = int(time.time())
    # Anchor this client's first-seen firmly in the past, regardless of
    # build_ftl's own randomized fixture timestamps for it.
    _insert_existing_client_query(ftl, established_ip, "old-anchor.example.test", now - 10 * 86400)
    rollups.refresh_rollups()

    new_domain = "not-actually-correlated.example.test"
    _insert_existing_client_query(ftl, established_ip, new_domain, now)
    rollups.refresh_rollups()

    client.post("/api/alert-rules", json={
        "name": "Corr", "type": "correlated_new_device_domain",
        "params": {"window_minutes": 60}})
    events = client.get("/api/alerts").json()["events"]
    corr = [e for e in events if e["type"] == "correlated_new_device_domain"]
    assert not any(e["domain"] == new_domain for e in corr)


def test_correlated_new_device_domain_noop_before_rollup_backfilled(client, ftl):
    """Before the rollup has ever been backfilled, rollups.new_domains()
    returns None -- must be treated as "no signal yet", same guard
    first_seen_domain already relies on."""
    client.post("/api/alert-rules", json={
        "name": "Corr", "type": "correlated_new_device_domain",
        "params": {"window_minutes": 600000}})
    events = client.get("/api/alerts").json()["events"]
    assert not any(e["type"] == "correlated_new_device_domain" for e in events)


def _insert_at(ftl, ip: str, domain: str, ts: float) -> None:
    """A single query from an EXISTING CLIENTS ip at an exact timestamp --
    for #54 backtest tests, which need controlled historical data rather
    than build_ftl's own randomized-within-the-last-hour fixture rows."""
    import sqlite3
    from conftest import CLIENTS, _idstore_client_id, _idstore_domain_id

    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        cid = next(i for i, (cip, _) in enumerate(CLIENTS, 1) if cip == ip)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, domain, cid),
        )
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        name = next(n for cip, n in CLIENTS if cip == ip)
        cid = _idstore_client_id(cur, ip, name)
        did = _idstore_domain_id(cur, domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, did, cid),
        )
    else:
        stored_ts = float(ts) if ftl["schema"] == "real" else int(ts)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (stored_ts, 1, 2, domain, ip),
        )
    conn.commit()
    conn.close()


def _insert_typed(ftl, ip: str, domain: str, type_code: int, ts: float) -> None:
    """A query from an EXISTING CLIENTS ip with a controllable FTL query
    TYPE code (1=A, 7=TXT, 3=ANY -- see db.TYPE_NAMES), for #55's
    query-type-composition tests."""
    import sqlite3
    from conftest import CLIENTS, _idstore_client_id, _idstore_domain_id

    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        cid = next(i for i, (cip, _) in enumerate(CLIENTS, 1) if cip == ip)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (int(ts), type_code, 2, domain, cid),
        )
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        name = next(n for cip, n in CLIENTS if cip == ip)
        cid = _idstore_client_id(cur, ip, name)
        did = _idstore_domain_id(cur, domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (int(ts), type_code, 2, did, cid),
        )
    else:
        stored_ts = float(ts) if ftl["schema"] == "real" else int(ts)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (stored_ts, type_code, 2, domain, ip),
        )
    conn.commit()
    conn.close()


def test_backtest_unsupported_type_rejected(client):
    r = client.post("/api/alert-rules/backtest", json={
        "type": "new_device", "params": {"window_minutes": 60}, "days": 1})
    assert r.status_code == 400


def test_backtest_too_many_buckets_rejected(client):
    r = client.post("/api/alert-rules/backtest", json={
        "type": "volume_threshold",
        "params": {"scope": "any", "threshold": 10, "window_minutes": 1},
        "days": 30,
    })
    assert r.status_code == 400


def test_backtest_volume_threshold_any_scope(ftl):
    from app import alerts

    now = int(time.time())
    # Clearly inside "the last 1 day", well clear of a bucket boundary.
    burst_ts = now - 3 * 3600 - 90
    for _ in range(12):
        _insert_at(ftl, "192.168.1.10", "ads.example.com", burst_ts)

    result = alerts.backtest_rule(
        "volume_threshold", {"scope": "any", "threshold": 10, "window_minutes": 60}, days=1
    )
    assert result["would_have_fired"] >= 1
    assert any("queries from" in m for m in result["sample_messages"])


def test_backtest_volume_threshold_per_client(ftl):
    from app import alerts

    now = int(time.time())
    burst_ts = now - 3 * 3600 - 90
    for _ in range(12):
        _insert_at(ftl, "192.168.1.11", "ads.example.com", burst_ts)

    result = alerts.backtest_rule(
        "volume_threshold", {"scope": "per_client", "threshold": 10, "window_minutes": 60}, days=1
    )
    assert result["would_have_fired"] >= 1


def test_backtest_domain_keyword(ftl):
    from app import alerts

    now = int(time.time())
    burst_ts = now - 3 * 3600 - 90
    for _ in range(3):
        _insert_at(ftl, "192.168.1.10", "tracker.bad.co", burst_ts)

    result = alerts.backtest_rule(
        "domain_keyword", {"keyword": "tracker", "min_count": 2, "window_minutes": 60}, days=1
    )
    assert result["would_have_fired"] >= 1
    assert any('"tracker"' in m for m in result["sample_messages"])


def test_backtest_device_quiet(ftl):
    from app import alerts

    now = int(time.time())
    # Active well within a 60m bucket ~3h ago, then nothing in the following bucket.
    active_ts = now - 3 * 3600 - 90
    for _ in range(25):
        _insert_at(ftl, "192.168.1.12", "cdn.site.net", active_ts)

    result = alerts.backtest_rule(
        "device_quiet", {"min_prior": 20, "window_minutes": 60}, days=1
    )
    assert result["would_have_fired"] >= 1


def test_backtest_returns_zero_when_never_crossed(ftl):
    from app import alerts

    result = alerts.backtest_rule(
        "volume_threshold",
        {"scope": "any", "threshold": 999999, "window_minutes": 60},
        days=1,
    )
    assert result["would_have_fired"] == 0
    assert result["sample_messages"] == []


def test_api_backtest_shape(client, ftl):
    now = int(time.time())
    burst_ts = now - 3 * 3600 - 90
    for _ in range(12):
        _insert_at(ftl, "192.168.1.10", "ads.example.com", burst_ts)

    r = client.post("/api/alert-rules/backtest", json={
        "type": "volume_threshold",
        "params": {"scope": "any", "threshold": 10, "window_minutes": 60},
        "days": 1,
    })
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"would_have_fired", "buckets_checked", "days", "sample_messages"}
    assert body["would_have_fired"] >= 1
def test_unusual_query_type_fires_for_new_type_with_established_history(ftl):
    from app import db

    now = int(time.time())
    ip = "192.168.1.10"
    # Established history (well before the 60m window): only ever type A.
    for i in range(5):
        _insert_typed(ftl, ip, "steady.example.com", 1, now - 3 * 3600 - i)
    # Within the recent window: a brand-new type for this client, TXT.
    _insert_typed(ftl, ip, "tunnel.example.test", 7, now - 60)

    hits = db.unusual_query_types(window_minutes=60)
    hit = next((h for h in hits if h["ip"] == ip), None)
    assert hit is not None
    assert "TXT" in hit["new_types"]


def test_unusual_query_type_skips_client_with_no_established_history(ftl):
    """A client with NO queries at all before the window is skipped --
    every type would look 'new' for a brand-new device, which would just
    duplicate new_device/new_vendor without adding a genuine signal."""
    from app import db

    now = int(time.time())
    ip = "192.168.1.13"  # a standard CLIENTS ip -- may have build_ftl fixture
    # rows, but we only assert on a completely fresh ip with zero rows ever.
    fresh_ip = "192.168.1.250"
    _insert_typed(ftl, ip, "placeholder.example.com", 1, now - 3 * 3600)  # unused, keeps ip in scope

    # fresh_ip isn't in CLIENTS, so use the idstore/new/real-aware new-client
    # helper instead of _insert_typed (which assumes an existing CLIENTS ip).
    _insert_new_client_query(ftl, fresh_ip, "brand-new-gadget", "first-query.example.test", now - 60)

    hits = db.unusual_query_types(window_minutes=60)
    assert not any(h["ip"] == fresh_ip for h in hits)


def _clear_client_queries(ftl, ip: str) -> None:
    """Wipe every query build_ftl's own randomized fixture already gave this
    ip, so a test asserting an ABSENCE (no new type) isn't contaminated by
    the fixture's random type choices among build_ftl's own TYPES list."""
    import sqlite3

    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        row = conn.execute("SELECT id FROM client WHERE ip = ?", (ip,)).fetchone()
        if row:
            conn.execute("DELETE FROM queries WHERE client_id = ?", (row[0],))
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        row = cur.execute("SELECT id FROM client_by_id WHERE ip = ?", (ip,)).fetchone()
        if row:
            conn.execute("DELETE FROM query_storage WHERE client = ?", (row[0],))
    else:
        conn.execute("DELETE FROM queries WHERE client = ?", (ip,))
    conn.commit()
    conn.close()


def test_unusual_query_type_no_new_type_not_flagged(ftl):
    from app import db

    now = int(time.time())
    ip = "192.168.1.11"
    _clear_client_queries(ftl, ip)
    for i in range(5):
        _insert_typed(ftl, ip, "steady.example.com", 1, now - 3 * 3600 - i)
    _insert_typed(ftl, ip, "steady.example.com", 1, now - 60)  # same type, recent

    hits = db.unusual_query_types(window_minutes=60)
    assert not any(h["ip"] == ip for h in hits)


def test_unusual_query_type_alert_rule_fires(client, ftl):
    ip = "192.168.1.12"
    now = int(time.time())
    for i in range(5):
        _insert_typed(ftl, ip, "steady.example.com", 1, now - 3 * 3600 - i)
    _insert_typed(ftl, ip, "tunnel.example.test", 7, now - 60)

    client.post("/api/alert-rules", json={
        "name": "QType", "type": "unusual_query_type", "params": {"window_minutes": 60}})
    events = client.get("/api/alerts").json()["events"]
    hits = [e for e in events if e["type"] == "unusual_query_type"]
    assert any(e["client_ip"] == ip for e in hits)
