"""
Regression test — mDNS naming: show the device's real/friendly name, not an
app label that collides (IDENT-1).

"I used to know where the TV is; now I show 'Spotify Desktop'."

A device's name comes from a bare ``<host>.local`` A/AAAA record OR a *friendly*
service instance (a cast/AirPlay/Sonos/HomeKit name — the only place that name is
published). What must NOT become a name is an app/generic label that collides
across devices: ``Spotify Desktop._spotify-connect._tcp.local`` is the same on
every Spotify client and identifies no device.

Fix: core.identity.is_identifying_mdns_name() gates every mDNS name; the
service-type → device-class mapping still consumes the full name.
"""

from __future__ import annotations

import pytest

from core.identity import is_identifying_mdns_name

# ── Predicate unit tests ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        # bare host records
        "Johns-Laptop.local",
        "DESKTOP-AB12CD.local",
        "android-9f3a.local",
        "iPhone.local",
        # friendly service instances — the owner's device name
        "Living Room TV._googlecast._tcp.local",
        "Bedroom._airplay._tcp.local",
        "Office Sonos._sonos._tcp.local",
        "Iheb's-iPhone._apple-mobdev2._tcp.local",
    ],
)
def test_real_and_friendly_names_are_kept(name):
    assert is_identifying_mdns_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        # app label that collides across devices — the reported case
        "Spotify Desktop._spotify-connect._tcp.local",
        "Someone._spotify._tcp.local",
        # pure service types / non-local / empty
        "_spotify-connect._tcp.local",
        "_services._dns-sd._udp.local",
        "",
        "not-mdns.example.com",
    ],
)
def test_app_labels_and_non_names_are_rejected(name):
    assert is_identifying_mdns_name(name) is False


# ── End-to-end parser test ──────────────────────────────────────────────────


def test_cast_name_kept_spotify_label_dropped():
    scapy = pytest.importorskip("scapy.all")
    from network.mdns_sniff import sniff_mdns_name

    def _names(pkt):
        calls: list = []
        sniff_mdns_name(pkt, lambda ip, name, os_class: calls.append((name, os_class)))
        return [n for n, _c in calls if n], [c for _n, c in calls if c]

    # A Chromecast announcing its friendly name via _googlecast.
    cast = (
        scapy.IP(src="10.0.0.50")
        / scapy.UDP(sport=5353, dport=5353)
        / scapy.DNS(qd=scapy.DNSQR(qname="Living Room TV._googlecast._tcp.local"))
    )
    names, classes = _names(cast)
    assert any("living room tv" in n.lower() for n in names), f"friendly cast name lost: {names}"

    # A Spotify Connect client — the colliding app label must NOT become a name,
    # but the service type still yields a device-class hint.
    spot = (
        scapy.IP(src="10.0.0.51")
        / scapy.UDP(sport=5353, dport=5353)
        / scapy.DNS(qd=scapy.DNSQR(qname="Spotify Desktop._spotify-connect._tcp.local"))
    )
    names, classes = _names(spot)
    assert not any("spotify" in n.lower() for n in names), f"app label leaked into name: {names}"
    assert any("Spotify" in c for c in classes), f"class hint lost: {classes}"
