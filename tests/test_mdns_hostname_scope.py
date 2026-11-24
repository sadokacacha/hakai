"""
Regression test — mDNS service-instance names leaking into the hostname column
(IDENT-1). "I can't tell who is who — it shows 'Spotify Desktop'."

A device's real mDNS hostname is a bare ``<host>.local`` A/AAAA record. A service
*instance* name like ``Spotify Desktop._spotify-connect._tcp.local`` is an app/zone
label that collides across devices and is not a host identity. The old parsers
accepted any ``.local`` name not starting with ``_`` as a hostname, so the Spotify
Connect instance label became the device name.

Fix: core.identity.is_mdns_host_record() gates every mDNS hostname; the
service-type → class mapping still consumes the full name.
"""

from __future__ import annotations

import pytest

from core.identity import is_mdns_host_record

# ── Predicate unit tests ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "Johns-Laptop.local",
        "DESKTOP-AB12CD.local",
        "android-9f3a.local",
        "iPhone.local",
        "BRW00AABB.local",
    ],
)
def test_bare_host_records_are_hostnames(name):
    assert is_mdns_host_record(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "Spotify Desktop._spotify-connect._tcp.local",  # the reported case
        "Living Room._googlecast._tcp.local",
        "Kitchen._airplay._tcp.local",
        "_spotify-connect._tcp.local",  # pure service type
        "_services._dns-sd._udp.local",
        "host._workstation._tcp.local",
        "",
        "not-mdns.example.com",
    ],
)
def test_service_instances_and_non_local_are_rejected(name):
    assert is_mdns_host_record(name) is False


# ── End-to-end parser test ──────────────────────────────────────────────────


def test_spotify_instance_is_not_a_hostname_but_host_record_is():
    scapy = pytest.importorskip("scapy.all")
    from network.mdns_sniff import sniff_mdns_name

    pkt = (
        scapy.IP(src="10.0.0.42")
        / scapy.UDP(sport=5353, dport=5353)
        / scapy.DNS(
            qd=scapy.DNSQR(qname="Spotify Desktop._spotify-connect._tcp.local"),
            an=scapy.DNSRR(rrname="Johns-Laptop.local", type="A", rdata="10.0.0.42"),
        )
    )

    calls: list[tuple[str, str | None, str | None]] = []
    sniff_mdns_name(pkt, lambda ip, name, os_class: calls.append((ip, name, os_class)))

    hostnames = [name for _ip, name, _c in calls if name]
    classes = [c for _ip, _n, c in calls if c]

    # The app/zone label must NOT have been offered as a hostname.
    assert not any("spotify" in h.lower() for h in hostnames), (
        f"service-instance label leaked into hostname: {hostnames}"
    )
    # The real host record IS a hostname.
    assert any("johns" in h.lower() for h in hostnames), f"host record lost: {hostnames}"
    # The service type is still mined for a device-class hint.
    assert any("Spotify" in c for c in classes), f"class hint lost: {classes}"
