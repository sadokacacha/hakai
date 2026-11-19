"""
Regression tests for network/traffic.py counter parsing (Phase-2 hunt).

TRAF-1  _read_proc matched the interface name as a substring (`iface in line`),
        so 'eth0' wrongly matched 'veth0…' / 'eth0.100' lines in /proc/net/dev.
TRAF-2  _proc_loop corrected a negative delta with +2**32 (32-bit wrap), which on
        a 64-bit counter reset produces a bogus ~4 GB spike.
"""

from __future__ import annotations

from network.traffic import TrafficCounter

# Realistic /proc/net/dev: header rows, then a veth and a VLAN that both contain
# the substring "eth0", placed BEFORE the real eth0 line.
_PROC = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes\n"
    "  veth0: 111 0 0 0 0 0 0 0 222 0 0 0 0 0 0 0\n"
    "  eth0.100: 333 0 0 0 0 0 0 0 444 0 0 0 0 0 0 0\n"
    "  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"
    "    lo: 55 0 0 0 0 0 0 0 55 0 0 0 0 0 0 0\n"
)


def test_parse_iface_counters_exact_match():
    assert TrafficCounter._parse_iface_counters(_PROC, "eth0") == (1000, 2000)


def test_parse_iface_counters_vlan_is_distinct():
    assert TrafficCounter._parse_iface_counters(_PROC, "eth0.100") == (333, 444)


def test_parse_iface_counters_absent_iface():
    assert TrafficCounter._parse_iface_counters(_PROC, "wlan0") == (0, 0)


def test_parse_iface_counters_ignores_garbage():
    assert TrafficCounter._parse_iface_counters("not a valid file\n", "eth0") == (0, 0)


def test_counter_delta_normal_increase():
    assert TrafficCounter._counter_delta(500, 100) == 400


def test_counter_delta_reset_returns_zero_not_wrap():
    # Counter went backwards (iface reset): must be 0, not 50 + 2**32.
    assert TrafficCounter._counter_delta(50, 1_000_000) == 0
