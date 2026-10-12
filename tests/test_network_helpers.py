"""Tests for pure helpers in the network/ and system/ layers."""
import collections

from network.dhcp_sniffer import infer_os
from network.oui_lookup import get_vendor, is_randomized
from network.traffic import TrafficCounter
from system.tc_manager import TCManager


def test_infer_os_exact_signatures():
    assert infer_os([1, 3, 6, 15, 119, 252]) == "Apple/iOS (Modern)"
    assert infer_os(
        [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
    ) == "Windows 11"
    assert infer_os([]) == "Generic Device"


def test_get_vendor_fallback_dict():
    # Prefix lookup happens before any optional library, so this is deterministic.
    assert get_vendor("00:03:93:aa:bb:cc") == "Apple Inc."
    assert get_vendor("00-03-93-aa-bb-cc") == "Apple Inc."  # dash form normalized


def test_is_randomized():
    assert is_randomized("02:aa:bb:cc:dd:ee") is True
    assert is_randomized("0e:aa:bb:cc:dd:ee") is True
    assert is_randomized("00:aa:bb:cc:dd:ee") is False


def test_tc_burst():
    # burst = bytes/sec // 10, floored at one MTU (1600).
    assert TCManager._burst(80) == "1600"
    assert TCManager._burst(80000) == "1000000"


def test_traffic_spd_window():
    import time
    tc = TrafficCounter()
    now = time.time()
    dq = collections.deque([(now, 5000)])
    # (total_bytes / WINDOW) * 8 / 1e6  →  (5000/5)*8/1e6
    expected = (5000 / tc.WINDOW) * 8 / 1_000_000
    assert abs(tc._spd(dq) - expected) < 1e-9
    # Entries older than the window are dropped → zero.
    old = collections.deque([(now - tc.WINDOW - 10, 9999)])
    assert tc._spd(old) == 0.0
