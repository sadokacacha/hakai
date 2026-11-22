"""
Tests for network/rawsock.RawL2Sender (STEP 4).

Mocked socket factory — no real AF_PACKET socket (that needs root). Pins that the
sender binds to the iface, sends raw bytes, and degrades to unavailable/False
(never raises) when the socket can't be opened or a send fails, so the caller's
scapy fallback kicks in.
"""

from __future__ import annotations

from network import rawsock as rawsock_mod
from network.rawsock import RawL2Sender


class _FakeSock:
    def __init__(self):
        self.bound = None
        self.sent: list[bytes] = []
        self.closed = False

    def bind(self, addr):
        self.bound = addr

    def send(self, b):
        self.sent.append(b)
        return len(b)

    def close(self):
        self.closed = True


def test_available_binds_and_sends():
    fs = _FakeSock()
    s = RawL2Sender("eth0", sock_factory=lambda: fs)
    assert s.available is True
    assert fs.bound == ("eth0", 0)
    assert s.send(b"frame") is True
    assert fs.sent == [b"frame"]
    s.close()
    assert fs.closed is True
    assert s.available is False


def test_permission_error_is_unavailable_not_fatal():
    def boom():
        raise PermissionError("need root")

    s = RawL2Sender("eth0", sock_factory=boom)
    assert s.available is False
    assert s.send(b"x") is False  # falls through, never raises


def test_windows_is_unavailable(monkeypatch):
    monkeypatch.setattr(rawsock_mod, "_IS_WINDOWS", True)
    s = RawL2Sender("eth0", sock_factory=lambda: _FakeSock())
    assert s.available is False


def test_empty_iface_is_unavailable():
    s = RawL2Sender("", sock_factory=lambda: _FakeSock())
    assert s.available is False


def test_send_failure_returns_false():
    class _BadSock(_FakeSock):
        def send(self, b):
            raise OSError("ENOBUFS")

    s = RawL2Sender("eth0", sock_factory=lambda: _BadSock())
    assert s.available is True
    assert s.send(b"x") is False  # degrades, caller falls back to scapy
