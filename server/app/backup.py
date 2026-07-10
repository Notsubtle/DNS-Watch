"""
Config backup/export (#45) — a portable JSON snapshot of everything a user
manually curated in DNS Watch's own writable store: alert rules, tags,
manual device names, and webhook delivery settings. Nothing here ever
touches Pi-hole's read-only FTL db.

Deliberately excludes `alert_events` (fired-event history): that's
operational log data, not configuration, and restoring old events would
just be noise, not something worth backing up.

Also deliberately excludes the webhook secret: `alerts.get_settings()`
never returns it in plaintext (it's a bearer credential for an external
service — see that function's own docstring), so there's nothing for this
module to export. Restoring a backup therefore never touches whatever
secret is currently configured, and the user re-enters it by hand if
they're restoring onto a fresh install.

Restore uses MERGE semantics, not a destructive replace-all:
  - Tags are looked up by name and created if missing; backed-up members are
    added via tags.add_member, which is already idempotent
    (INSERT OR IGNORE) — re-running the same restore twice is harmless.
  - Alert rules have no natural business key across an export/import
    round-trip (a rule's `id` is DB-assigned, and `name` alone isn't
    guaranteed unique), so blindly upserting by name risks silently
    overwriting an unrelated rule that happens to share one. Instead, a rule
    is only created if an identical (name, type, params) triple doesn't
    already exist — this makes re-restoring the same backup idempotent
    without ever mutating an existing rule.
  - Device names are a natural one-per-ip upsert via names.set_name.
  - Settings (webhook url/format/enabled) are restored via
    alerts.update_settings, leaving the secret field untouched.
"""

from __future__ import annotations

import json

from app import alerts, names, tags

BACKUP_VERSION = 1


def export_backup() -> dict:
    settings = alerts.get_settings()
    return {
        "version": BACKUP_VERSION,
        "tags": [{"name": t["name"], "ips": t["ips"]} for t in tags.list_tags()],
        "alert_rules": [
            {"name": r["name"], "type": r["type"], "params": r["params"], "enabled": r["enabled"]}
            for r in alerts.list_rules()
        ],
        "device_names": [{"ip": n["ip"], "name": n["name"]} for n in names.list_names()],
        "settings": {
            "webhook_enabled": settings["webhook_enabled"],
            "webhook_url": settings["webhook_url"],
            "webhook_format": settings["webhook_format"],
        },
    }


def _rule_key(name: str, type_: str, params: dict) -> tuple[str, str, str]:
    """A rule's identity for merge-dedup purposes -- see module docstring on
    why (name, type) alone isn't enough. sort_keys makes the params
    comparison independent of key order, since a round-tripped dict from
    JSON isn't guaranteed to preserve insertion order the same way."""
    return (name, type_, json.dumps(params or {}, sort_keys=True))


def restore_backup(data: dict) -> dict:
    """Merge a backup's contents into the current store. Returns a summary
    of how many items from each section were actually applied -- callers
    don't need per-item detail, just confirmation something happened.
    Missing/malformed sections are skipped rather than erroring, so a
    partial or hand-edited backup file still restores what it can."""
    existing_tags = {t["name"]: t for t in tags.list_tags()}
    tags_applied = 0
    for t in data.get("tags") or []:
        name = t.get("name")
        if not name:
            continue
        tag = existing_tags.get(name)
        if tag is None:
            try:
                tag = tags.create_tag(name)
            except tags.InvalidTag:
                continue
            existing_tags[name] = tag
        for ip in t.get("ips") or []:
            tags.add_member(tag["id"], ip)
        tags_applied += 1

    existing_rule_keys = {
        _rule_key(r["name"], r["type"], r["params"]) for r in alerts.list_rules()
    }
    rules_applied = 0
    for rule in data.get("alert_rules") or []:
        name, type_ = rule.get("name"), rule.get("type")
        params = rule.get("params") or {}
        if not name or not type_:
            continue
        key = _rule_key(name, type_, params)
        if key in existing_rule_keys:
            continue  # identical rule already exists -- keeps re-restores idempotent
        try:
            alerts.create_rule(name, type_, params, rule.get("enabled", True))
        except ValueError:
            continue  # unknown rule type, e.g. a backup taken on a newer version
        existing_rule_keys.add(key)
        rules_applied += 1

    names_applied = 0
    for row in data.get("device_names") or []:
        ip, name = row.get("ip"), row.get("name")
        if not ip or not name:
            continue
        try:
            names.set_name(ip, name)
        except names.InvalidName:
            continue
        names_applied += 1

    settings_restored = False
    settings = data.get("settings")
    if settings:
        try:
            alerts.update_settings(
                webhook_enabled=settings.get("webhook_enabled"),
                webhook_url=settings.get("webhook_url"),
                webhook_format=settings.get("webhook_format"),
            )
            settings_restored = True
        except ValueError:
            pass  # unrecognized webhook_format, e.g. a backup from a newer version

    return {
        "tags": tags_applied,
        "alert_rules": rules_applied,
        "device_names": names_applied,
        "settings_restored": settings_restored,
    }
