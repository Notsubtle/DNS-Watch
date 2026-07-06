"""Offline OUI (MAC vendor) lookup — issue #5."""

from __future__ import annotations

from app import oui


def test_known_prefix_resolves():
    # 00:00:01 is IEEE's own long-registered Xerox block — stable in every
    # MA-L snapshot, safe to assert on directly.
    assert oui.lookup_vendor("00:00:01:aa:bb:cc") == "XEROX CORPORATION"


def test_unlisted_prefix_is_a_plain_miss():
    # The all-ones prefix isn't a registered MA-L assignment.
    assert oui.lookup_vendor("ff:ff:ff:ab:cd:ef") is None


def test_locally_administered_bit_detected():
    assert oui.is_locally_administered("02:11:22:33:44:55") is True
    assert oui.is_locally_administered("06:11:22:33:44:55") is True  # 0x06 also has 0x02 set
    assert oui.is_locally_administered("00:00:01:aa:bb:cc") is False


def test_malformed_hwaddr_is_not_locally_administered_and_has_no_vendor():
    assert oui.is_locally_administered("not-a-mac") is False
    assert oui.lookup_vendor("not-a-mac") is None


def test_lookup_is_case_and_delimiter_insensitive():
    assert oui.lookup_vendor("00:00:01:AA:BB:CC") == oui.lookup_vendor("00-00-01-aa-bb-cc")
