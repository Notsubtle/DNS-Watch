"""resolve.py: the reverse-DNS (PTR) cache and its own minimal DNS packet
codec. Network I/O itself (_lookup) is exercised via a real loopback UDP
"fake resolver" rather than mocked away, so the packet builder/parser are
tested against each other honestly, not against a hand-verified fixture that
could drift from what the parser actually expects.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from app import resolve


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(resolve, "STORE_PATH", str(tmp_path / "resolve.db"))


def test_reverse_name_builds_in_addr_arpa():
    assert resolve._reverse_name("192.168.1.10") == "10.1.168.192.in-addr.arpa"


def test_reverse_name_rejects_non_ipv4():
    assert resolve._reverse_name("not-an-ip") is None
    assert resolve._reverse_name("::1") is None


def _fake_ptr_server(hostname_by_qname: dict[str, str]):
    """A real UDP socket on loopback that answers PTR queries for the given
    qname->hostname map (and no others), so _lookup's socket/timeout/parsing
    path runs against actual bytes on the wire, not a mock."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def _serve():
        try:
            data, addr = sock.recvfrom(512)
        except OSError:
            return
        req_id = struct.unpack(">H", data[:2])[0]
        qname = resolve._decode_name(data, 12)
        hostname = hostname_by_qname.get(qname)
        if hostname is None:
            return  # simulate NXDOMAIN-ish silence; caller will time out
        header = struct.pack(">HHHHHH", req_id, 0x8180, 1, 1, 0, 0)
        # Echo the question section verbatim (offset 12 to just before the answer).
        question = data[12:len(data)]
        rdata = b"".join(bytes([len(l)]) + l.encode() for l in hostname.split(".")) + b"\x00"
        answer = (
            b"\xc0\x0c"  # NAME: pointer back to the question's qname at offset 12
            + struct.pack(">HHIH", 12, 1, 60, len(rdata))
            + rdata
        )
        sock.sendto(header + question + answer, addr)

    threading.Thread(target=_serve, daemon=True).start()
    return port, sock


def test_lookup_resolves_against_real_udp_server():
    port, sock = _fake_ptr_server({"10.1.168.192.in-addr.arpa": "desktop.lan"})
    try:
        name = resolve._lookup_via("192.168.1.10", "127.0.0.1", port, timeout=2.0)
        assert name == "desktop.lan"
    finally:
        sock.close()


def test_lookup_times_out_cleanly_on_silence():
    port, sock = _fake_ptr_server({})  # server never answers this qname
    try:
        name = resolve._lookup_via("192.168.1.99", "127.0.0.1", port, timeout=0.3)
        assert name is None
    finally:
        sock.close()


def test_lookup_uses_a_fresh_query_id_each_call(monkeypatch):
    """Regression: the query id used to be a constant derived from
    os.getpid(), identical for the whole process lifetime -- an attacker
    racing the real reply on a shared LAN only had to guess one fixed value.
    It must vary from call to call."""
    sent_ids = []
    real_sendto = socket.socket.sendto

    def _spy_sendto(self, data, addr):
        sent_ids.append(struct.unpack(">H", data[:2])[0])
        return real_sendto(self, data, addr)

    monkeypatch.setattr(socket.socket, "sendto", _spy_sendto)
    for _ in range(5):
        # port 1 is a valid but (almost certainly) closed/unreachable port on
        # loopback -- sendto succeeds either way, and we only care about what
        # id got baked into the packet, not the (irrelevant, expected-to-fail)
        # response.
        resolve._lookup_via("192.168.1.10", "127.0.0.1", 1, timeout=0.05)
    assert len(set(sent_ids)) > 1, f"query id did not vary across calls: {sent_ids}"


def test_lookup_rejects_reply_from_unexpected_source_address():
    """Regression: recvfrom() doesn't filter by peer address on its own, so
    without an explicit source check, ANY host that can get a packet to our
    ephemeral port -- not just the server we actually queried -- could inject
    a PTR answer. Model this without needing raw sockets/root (real IP
    spoofing) by having the reply come from a genuinely different, legitimate
    loopback address than the one _lookup_via was told to trust -- exactly
    the shape of an off-path attacker racing the real reply from their own
    machine. A byte-for-byte well-formed reply from the wrong address must be
    discarded, not accepted."""
    query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query_sock.bind(("127.0.0.1", 0))
    query_port = query_sock.getsockname()[1]

    reply_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reply_sock.bind(("127.0.0.2", 0))  # different address than we'll ask _lookup_via to trust

    def _serve():
        try:
            data, client_addr = query_sock.recvfrom(512)
        except OSError:
            return
        req_id = struct.unpack(">H", data[:2])[0]
        header = struct.pack(">HHHHHH", req_id, 0x8180, 1, 1, 0, 0)
        question = data[12:len(data)]
        rdata = b"".join(bytes([len(l)]) + l.encode() for l in "spoofed.lan".split(".")) + b"\x00"
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 60, len(rdata)) + rdata
        reply_sock.sendto(header + question + answer, client_addr)

    threading.Thread(target=_serve, daemon=True).start()
    try:
        name = resolve._lookup_via("192.168.1.10", "127.0.0.1", query_port, timeout=0.5)
        assert name is None
    finally:
        query_sock.close()
        reply_sock.close()


def test_resolve_batch_caches_success(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: "phone.lan")
    n = resolve.resolve_batch(["192.168.1.5"], now=1000)
    assert n == 1
    assert resolve.get_names() == {"192.168.1.5": "phone.lan"}


def test_resolve_batch_negative_caches_and_backs_off(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: None)
    resolve.resolve_batch(["192.168.1.6"], now=1000)
    # A failed lookup contributes no name...
    assert resolve.get_names() == {}
    # ...but IS remembered, so an immediate re-check (before backoff elapses)
    # does not re-query — verified by never calling the real network path.
    calls = []
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: calls.append(ip))
    resolved_count = resolve.resolve_batch(["192.168.1.6"], now=1001)
    assert resolved_count == 0
    assert calls == []


def test_resolve_batch_retries_after_backoff_elapses(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: None)
    resolve.resolve_batch(["192.168.1.7"], now=1000)
    calls = []
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: calls.append("192.168.1.7") or None)
    resolve.resolve_batch(["192.168.1.7"], now=1000 + resolve._FAILURE_BACKOFF[0] + 1)
    assert calls == ["192.168.1.7"]


def test_resolve_batch_respects_batch_size_cap(monkeypatch):
    calls = []
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: calls.append(ip) or None)
    ips = [f"192.168.1.{i}" for i in range(resolve.BATCH_SIZE + 10)]
    n = resolve.resolve_batch(ips, now=1000)
    assert n == resolve.BATCH_SIZE
    assert len(calls) == resolve.BATCH_SIZE


def test_get_names_excludes_negative_cache_entries(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: None if ip == "192.168.1.1" else "named.lan")
    resolve.resolve_batch(["192.168.1.1", "192.168.1.2"], now=1000)
    assert resolve.get_names() == {"192.168.1.2": "named.lan"}
