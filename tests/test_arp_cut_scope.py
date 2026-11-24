"""
Regression test for network/arp.py — targeted-cut blast radius (ARP-3).

ARP-3  The ARP flood blasted a broadcast gratuitous ARP claiming the *gateway's*
       IP was at our MAC (Ether dst ff:ff:ff:ff:ff:ff, ARP psrc=gateway). That
       rewrites the gateway entry on every host on the segment, so cutting one
       device routed the entire subnet through us and knocked it offline
       ("cut one → cuts everyone"). A targeted cut must poison only the
       target↔gateway pair, unicast.

These assertions pin _build_l2_frames (the extracted, pure frame builder). On the
pre-fix code the frame set included the broadcast GARP with psrc=gateway, so the
"no broadcast frame" / "no segment-wide gateway claim" assertions would fail.
"""

from __future__ import annotations

import pytest

from network.arp import SCAPY_OK, ArpManager

pytestmark = pytest.mark.skipif(not SCAPY_OK, reason="scapy not installed")

BROADCAST = "ff:ff:ff:ff:ff:ff"
TARGET_IP = "10.0.0.9"
GATEWAY_IP = "10.0.0.1"
TARGET_MAC = "aa:aa:aa:aa:aa:aa"
GW_MAC = "bb:bb:bb:bb:bb:bb"
MY_MAC = "cc:cc:cc:cc:cc:cc"


def _frames(gw_mac: str = GW_MAC):
    return ArpManager._build_l2_frames(TARGET_IP, GATEWAY_IP, TARGET_MAC, gw_mac, MY_MAC)


def test_no_broadcast_frame_in_targeted_cut():
    """Every poison frame is unicast to the target or the gateway — never the
    broadcast address (which would hit the whole segment)."""
    from scapy.all import Ether

    frames = _frames()
    assert frames, "expected poison frames for a resolved target"
    for f in frames:
        dst = f[Ether].dst.lower()
        assert dst != BROADCAST, "targeted cut emitted a broadcast frame (segment-wide poison)"
        assert dst in (TARGET_MAC, GW_MAC), f"frame sent to an unexpected host: {dst}"


def test_no_segment_wide_gateway_claim():
    """No frame may announce the gateway's IP (psrc=gateway) to the broadcast
    address — that is exactly the rule that cut the whole subnet."""
    from scapy.all import ARP, Ether

    for f in _frames():
        arp = f[ARP]
        if f[Ether].dst.lower() == BROADCAST:
            assert arp.psrc != GATEWAY_IP, "broadcast gateway spoof present (cuts everyone)"


def test_target_and_gateway_are_poisoned_unicast():
    """The scoped poison is still correct: target told gateway=our MAC, gateway
    told target=our MAC, each unicast to the right host."""
    from scapy.all import ARP, Ether

    frames = _frames()
    to_target = [f for f in frames if f[Ether].dst.lower() == TARGET_MAC]
    to_gw = [f for f in frames if f[Ether].dst.lower() == GW_MAC]

    assert to_target, "target was not poisoned"
    assert to_gw, "gateway was not poisoned"
    # To the target we impersonate the gateway; to the gateway we impersonate the target.
    assert all(f[ARP].psrc == GATEWAY_IP and f[ARP].hwsrc == MY_MAC for f in to_target)
    assert all(f[ARP].psrc == TARGET_IP and f[ARP].hwsrc == MY_MAC for f in to_gw)


def test_unknown_gateway_mac_skips_rather_than_broadcasts():
    """If the gateway MAC is unresolved we drop the gateway half entirely — we do
    NOT fall back to a broadcast (the old behaviour that poisoned the segment)."""
    from scapy.all import Ether

    frames = _frames(gw_mac="")
    assert frames, "target half should still be built"
    for f in frames:
        assert f[Ether].dst.lower() == TARGET_MAC, "unresolved gateway MAC must not broadcast"
