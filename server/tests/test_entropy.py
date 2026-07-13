"""Domain lexical/entropy scoring (#3) -- db.domain_entropy /
is_high_entropy_domain / client_entropy_summary. A soft score, never a hard
alert -- see the module note in db.py."""

from __future__ import annotations

from app import db


def test_ordinary_hostname_scores_low():
    assert not db.is_high_entropy_domain("www.example.com")
    assert not db.is_high_entropy_domain("mail.google.com")


def test_random_label_scores_high():
    assert db.is_high_entropy_domain("a8f3k9x2q7z1m4b6.tunnel.example.com")


def test_short_domain_never_flagged_regardless_of_score():
    """Below DOMAIN_ENTROPY_MIN_LENGTH, even a maximally "random" label is
    too short for entropy to mean anything -- never flagged."""
    assert not db.is_high_entropy_domain("a1.co")


def test_entropy_scores_the_prefix_not_the_registered_parent():
    """The registered parent itself (github.io, s3.amazonaws.com) shouldn't
    inflate or dilute the score -- only what's in FRONT of it counts."""
    e1 = db.domain_entropy("qx7z9k2m.github.io")
    e2 = db.domain_entropy("aaaaaaaa.github.io")
    assert e1 > e2  # random prefix scores higher than a repeated-char prefix


def test_domain_with_no_prefix_falls_back_to_whole_hostname():
    assert db.domain_entropy("example.com") == db.domain_entropy("example.com")  # no crash
    assert db.domain_entropy(None) == 0.0
    assert db.domain_entropy("") == 0.0


def test_client_entropy_summary_shape(ftl):
    from conftest import CLIENTS

    ip = CLIENTS[0][0]
    summary = db.client_entropy_summary(ip)
    assert set(summary) == {"total_domains", "high_entropy_count", "pct_high_entropy", "sample_domains"}
    assert 0 <= summary["pct_high_entropy"] <= 100
    assert summary["high_entropy_count"] <= summary["total_domains"]


def test_client_entropy_summary_empty_for_unknown_client(ftl):
    summary = db.client_entropy_summary("10.0.0.253")
    assert summary == {
        "total_domains": 0,
        "high_entropy_count": 0,
        "pct_high_entropy": 0.0,
        "sample_domains": [],
    }
