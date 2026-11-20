"""
Regression test for network/mdns_sniff.py (Phase-2 hunt).

MDNS-4  The question-record loop iterated range(dns.qdcount) and indexed
        dns.qd[i]. The qdcount header is attacker-influenced: an inflated value
        wastes thousands of IndexError iterations per packet, and a value that
        under-reports the carried records silently drops them. The loop now
        iterates the actual dissected record list.

Uses real scapy packets (no network).
"""

from __future__ import annotations

from scapy.all import DNS, DNSQR, IP, UDP  # type: ignore[attr-defined]  # scapy.all is dynamic

from network.mdns_sniff import sniff_mdns_name


def test_qd_iterates_actual_records_not_qdcount():
    # Header claims 1 question, but two real .local questions are carried.
    pkt = (
        IP(src="192.168.1.5")
        / UDP(sport=5353, dport=5353)
        / DNS(qdcount=1, qd=[DNSQR(qname=b"host-a.local"), DNSQR(qname=b"host-b.local")])
    )
    names: list = []
    sniff_mdns_name(pkt, lambda ip, n, label: names.append(n) if n else None)
    assert len(names) >= 2, "both question records must be parsed regardless of qdcount"


def test_inflated_qdcount_parses_without_error():
    # Header over-reports; must still parse the single real record and not error.
    pkt = (
        IP(src="192.168.1.9")
        / UDP(sport=5353, dport=5353)
        / DNS(qdcount=65535, qd=[DNSQR(qname=b"printer.local")])
    )
    names: list = []
    sniff_mdns_name(pkt, lambda ip, n, label: names.append(n) if n else None)
    assert len(names) == 1
