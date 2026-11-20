"""
Regression test for network/ipv6.py restoration (Phase-2 hunt).

Offensive module — this is a *cleanup/restoration* fix (reduce collateral), not a
hijack-effectiveness change.

IPV6-1  _ra_loop advertises the host as the default IPv6 router with
        routerlifetime=1800, but stop() only set _running=False and never
        withdrew the route, so targets kept the bogus default router for up to
        30 minutes after "stop". stop() now sends a routerlifetime=0 RA.

Mocked: scapy sendp is patched; no real packets, no threads started.
"""

from __future__ import annotations

from scapy.all import ICMPv6ND_RA

from network import ipv6 as ipv6_mod
from network.ipv6 import IPv6Hijacker


def test_stop_sends_withdrawal_ra(monkeypatch):
    sent: list = []
    monkeypatch.setattr(ipv6_mod, "sendp", lambda pkt, **k: sent.append(pkt))

    h = IPv6Hijacker("eth0", "aa:bb:cc:dd:ee:ff")
    h._running = True  # simulate "started" without spawning the RA/DHCP threads
    h.stop()

    assert len(sent) >= 1, "stop() must send a withdrawal RA"
    ra = sent[0].getlayer(ICMPv6ND_RA)
    assert ra is not None and ra.routerlifetime == 0, "withdrawal RA must set router lifetime 0"


def test_stop_when_not_running_sends_nothing(monkeypatch):
    sent: list = []
    monkeypatch.setattr(ipv6_mod, "sendp", lambda pkt, **k: sent.append(pkt))

    h = IPv6Hijacker("eth0", "aa:bb:cc:dd:ee:ff")
    h.stop()  # was never running

    assert sent == []
