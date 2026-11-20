"""Tests for the shared core/netutil validation helpers (Phase-4 consolidation)."""

from __future__ import annotations

from core.netutil import valid_cidr, valid_dns, valid_ip


def test_valid_ip():
    assert valid_ip("192.168.1.5")
    assert valid_ip("10.0.0.1")
    assert valid_ip("::1")  # IPv6, matching the old _valid_ip behaviour
    assert not valid_ip("192.300.1.1")
    assert not valid_ip("1.2.3")
    assert not valid_ip("not-an-ip")
    assert not valid_ip("")


def test_valid_cidr():
    assert valid_cidr("192.168.1.5/24")
    assert valid_cidr("192.168.1.5")  # bare host address is allowed
    assert not valid_cidr("192.168.1.5/99")
    assert not valid_cidr("garbage")
    assert not valid_cidr("")


def test_valid_dns():
    assert valid_dns("8.8.8.8")
    assert valid_dns("8.8.8.8, 1.1.1.1")
    assert valid_dns("8.8.8.8,1.1.1.1,9.9.9.9")
    assert not valid_dns("8.8.8.8, not-an-ip")
    assert not valid_dns("")
    assert not valid_dns(",")
    assert not valid_dns("   ")
