"""
Regression tests for network/recon_engine.py (Phase-2 hunt).

Reliability only (recon is best-effort intel) — connection cleanup + input
validation, not recon accuracy.

RECON-1  get_ssl_cert_cn closed the writer only on the success path, leaking the
         connection whenever cert parsing raised.
RECON-2  get_upnp_friendly_name leaked a writer per failed port probe.
RECON-4  run_recon didn't validate the target IP before launching probes.

Mocked: asyncio.open_connection / create_subprocess_exec are patched; no sockets.
"""

from __future__ import annotations

import asyncio

from network import recon_engine as recon_mod
from network.recon_engine import ReconEngine

_EMPTY = {"ssl_cn": "", "upnp_model": "", "netbios": "", "ptr_name": "", "ipv6_ll": ""}


class FakeReader:
    def __init__(self, raise_on_read=False):
        self._raise = raise_on_read

    async def read(self, n):
        if self._raise:
            raise OSError("read boom")
        return b""


class FakeWriter:
    def __init__(self, ssl_obj=None):
        self._ssl = ssl_obj
        self.closed = False

    def get_extra_info(self, key):
        return self._ssl

    def write(self, data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def test_ssl_cert_cn_closes_writer_on_error(monkeypatch):
    re = ReconEngine()
    fw = FakeWriter(ssl_obj=object())  # object() has no getpeercert → AttributeError

    async def fake_open(*a, **k):
        return (FakeReader(), fw)

    monkeypatch.setattr(recon_mod.asyncio, "open_connection", fake_open)
    result = asyncio.run(re.get_ssl_cert_cn("10.0.0.5"))
    assert result == ""
    assert fw.closed is True, "writer must be closed even when cert parsing fails"


def test_upnp_closes_every_writer_on_error(monkeypatch):
    re = ReconEngine()
    writers: list = []

    async def fake_open(host, port, **k):
        fw = FakeWriter()
        writers.append(fw)
        return (FakeReader(raise_on_read=True), fw)

    monkeypatch.setattr(recon_mod.asyncio, "open_connection", fake_open)
    result = asyncio.run(re.get_upnp_friendly_name("10.0.0.5"))
    assert result == ""
    assert len(writers) >= 1
    assert all(w.closed for w in writers), "each opened writer must be closed"


def test_run_recon_rejects_invalid_ip(monkeypatch):
    opened: list = []

    async def fake_open(*a, **k):
        opened.append(a)
        return (FakeReader(), FakeWriter())

    async def fake_exec(*a, **k):
        class _P:
            async def communicate(self):
                return (b"", b"")

        return _P()

    monkeypatch.setattr(recon_mod.asyncio, "open_connection", fake_open)
    monkeypatch.setattr(recon_mod.asyncio, "create_subprocess_exec", fake_exec)

    re = ReconEngine()
    result = asyncio.run(re.run_recon("not-an-ip", "10.0.0.1"))
    assert result == _EMPTY
    assert opened == [], "no probe should connect for an invalid target ip"
