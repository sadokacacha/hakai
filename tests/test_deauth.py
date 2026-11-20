"""
Regression tests for network/deauth.py lifecycle (Phase-2 hunt).

Offensive module — these are state-management fixes, not deauth effectiveness.

DEAUTH-1  _pmf_loop broke on empty targets without resetting _running, so it
          stayed True after the targets drained; start_pmf_bypass's
          `if not self._running` guard then never restarted the loop → deauth
          silently died after the first use.
DEAUTH-2  start_pmf_bypass ignored self._active, so with scapy's Dot11 layer
          unavailable it spawned a worker that crashes building RadioTap()/Dot11()
          (both None), leaving _running stale-True.

Mocked: threading.Thread is stubbed; no real worker runs, no packets are sent.
"""

from __future__ import annotations

from network import deauth as deauth_mod
from network.deauth import DeauthManager


class _FakeThread:
    def __init__(self, registry, kwargs):
        registry.append(kwargs)

    def start(self):
        pass


def test_pmf_loop_resets_running_when_no_targets():
    d = DeauthManager(bssid="AA:BB:CC:DD:EE:FF", iface="wlan0mon")
    d._running = True  # simulate a running worker whose targets then drained
    d._pmf_loop()  # no targets → must mark not-running and return promptly
    assert d._running is False, "loop must reset _running on drain so it can restart"


def test_start_pmf_bypass_restarts_after_drain(monkeypatch):
    threads: list = []
    monkeypatch.setattr(deauth_mod.threading, "Thread", lambda *a, **k: _FakeThread(threads, k))

    d = DeauthManager(bssid="AA:BB:CC:DD:EE:FF", iface="wlan0mon")
    d.start_pmf_bypass("11:22:33:44:55:66")
    assert len(threads) == 1

    # Drain → the loop (run for real here, synchronously) resets _running.
    d._targets.clear()
    d._pmf_loop()
    assert d._running is False

    # A new target must spawn a fresh worker.
    d.start_pmf_bypass("aa:bb:cc:11:22:33")
    assert len(threads) == 2, "start must restart the worker after a drain"


def test_start_pmf_bypass_noop_when_scapy_wifi_unavailable(monkeypatch):
    monkeypatch.setattr(deauth_mod, "SCAPY_WIFI_OK", False)
    d = DeauthManager(bssid="AA:BB:CC:DD:EE:FF", iface="wlan0mon")
    assert d._active is False

    threads: list = []
    monkeypatch.setattr(deauth_mod.threading, "Thread", lambda *a, **k: _FakeThread(threads, k))
    d.start_pmf_bypass("11:22:33:44:55:66")

    assert threads == [], "no deauth worker may start when scapy Dot11 is unavailable"
