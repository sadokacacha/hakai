"""
Regression tests for network/scanner.py (Phase-2 hunt).

SCAN-3  _fetch_upnp_friendly fetched the SSDP LOCATION url (attacker-controlled
        from an untrusted packet) with no scheme check, so a rogue
        'LOCATION: file:///etc/passwd' made the root scanner read local files.
SCAN-2  _merge_host validated IPs with a loose regex that accepted invalid
        octets like 192.300.1.1.

Mocked: urllib.request.urlopen is patched; no real HTTP/file fetches.
"""

from __future__ import annotations

import urllib.request

from network import scanner as scan_mod
from network.scanner import Scanner


# ── SCAN-3: UPnP LOCATION scheme guard ───────────────────────────────────────


def test_upnp_fetch_rejects_file_scheme(monkeypatch):
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: calls.append(a))
    scan_mod._upnp_cache.pop("10.9.9.9", None)

    scan_mod._fetch_upnp_friendly("10.9.9.9", "file:///etc/passwd")

    assert calls == [], "must not fetch a non-http(s) LOCATION url"


def test_upnp_fetch_allows_http_scheme(monkeypatch):
    calls: list = []

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=0):
            return b"<friendlyName>Office Printer</friendlyName>"

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: calls.append(a) or _FakeResp())
    scan_mod._upnp_cache.pop("10.9.9.8", None)

    scan_mod._fetch_upnp_friendly("10.9.9.8", "http://10.9.9.8:80/desc.xml")

    assert len(calls) == 1
    assert scan_mod._upnp_cache.get("10.9.9.8") == "Office Printer"


# ── SCAN-2: _merge_host strict IP validation ─────────────────────────────────


def test_merge_host_rejects_invalid_octets():
    found: dict = {}
    Scanner._merge_host(found, "192.300.1.1", "aa:bb:cc:dd:ee:ff")
    assert found == {}, "an IP with an out-of-range octet must not become a device"


def test_merge_host_rejects_ipv6():
    found: dict = {}
    Scanner._merge_host(found, "fe80::1", "aa:bb:cc:dd:ee:ff")
    assert found == {}


def test_merge_host_rejects_multicast():
    found: dict = {}
    Scanner._merge_host(found, "224.0.0.251", "aa:bb:cc:dd:ee:ff")
    assert found == {}


def test_merge_host_accepts_valid_unicast():
    found: dict = {}
    Scanner._merge_host(found, "192.168.1.5", "aa:bb:cc:dd:ee:ff")
    assert "192.168.1.5" in found
    assert found["192.168.1.5"].mac == "AA:BB:CC:DD:EE:FF"
