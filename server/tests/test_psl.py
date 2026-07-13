"""app/psl.py: offline Public Suffix List lookup backing the DNS-tunneling
detector (#2). Exercises plain, wildcard, and exception rules from the real
bundled list."""

from __future__ import annotations

from app import psl


def test_simple_com_domain():
    assert psl.registered_domain("a1b2c3.tunnel.example.com") == "example.com"
    assert psl.registered_domain("example.com") == "example.com"


def test_multi_part_suffix():
    assert psl.registered_domain("foo.co.uk") == "foo.co.uk"
    assert psl.registered_domain("www.foo.co.uk") == "foo.co.uk"


def test_wildcard_private_suffix_keeps_tenant_label():
    """*.s3.amazonaws.com is a wildcard rule -- the registered "domain" for a
    bucket is bucket.s3.amazonaws.com, one label ABOVE the wildcard suffix,
    so unrelated buckets under the same CDN aren't folded into one entity."""
    assert psl.registered_domain("bucket.s3.amazonaws.com") == "bucket.s3.amazonaws.com"
    assert psl.registered_domain("sub.bucket.s3.amazonaws.com") == "bucket.s3.amazonaws.com"


def test_exception_rule():
    """!city.kawasaki.jp carves that label out of the "*.kawasaki.jp"
    wildcard suffix -- city.kawasaki.jp is registrable, not part of the
    suffix itself."""
    assert psl.registered_domain("city.kawasaki.jp") == "city.kawasaki.jp"
    assert psl.registered_domain("foo.city.kawasaki.jp") == "city.kawasaki.jp"


def test_single_label_returned_as_is():
    assert psl.registered_domain("localhost") == "localhost"


def test_unlisted_tld_falls_back_to_implicit_star_rule():
    assert psl.registered_domain("random.unknowntld123") == "random.unknowntld123"
    assert psl.registered_domain("a.b.unknowntld123") == "b.unknowntld123"


def test_trailing_dot_and_case_normalized():
    assert psl.registered_domain("Example.COM.") == "example.com"
