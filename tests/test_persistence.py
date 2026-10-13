"""Tests for pure helpers in core/persistence.py."""
from types import SimpleNamespace

from core.persistence import (
    _is_junk_hostname,
    classify_device,
    fmt_mbps,
    fmt_speed,
    fmt_total,
    is_private_mac,
    is_stealth_mac,
    sanitize_mdns_name,
    sanitize_vendor,
)


def test_fmt_speed():
    assert fmt_speed(0) == "0 B/s"
    assert fmt_speed(-5) == "0 B/s"
    assert fmt_speed(512) == "512 B/s"
    assert fmt_speed(2048) == "2.0 KB/s"
    assert fmt_speed(2 * 1048576) == "2.00 MB/s"


def test_fmt_total():
    assert fmt_total(0) == "0 B"
    assert fmt_total(1536) == "1.5 KB"
    assert fmt_total(1048576) == "1.0 MB"
    assert fmt_total(1073741824) == "1.00 GB"


def test_fmt_mbps():
    assert fmt_mbps(0) == "0.00 Mbps"
    assert fmt_mbps(0.5) == "500 Kbps"
    assert fmt_mbps(2.5) == "2.50 Mbps"


def test_is_private_mac():
    assert is_private_mac("02:11:22:33:44:55") is True
    assert is_private_mac("06:11:22:33:44:55") is True
    assert is_private_mac("00:11:22:33:44:55") is False
    assert is_private_mac("") is False


def test_is_stealth_mac():
    assert is_stealth_mac("0a:11:22:33:44:55") is True
    assert is_stealth_mac("00:11:22:33:44:55") is False
    assert is_stealth_mac("") is False


def test_sanitize_mdns_name():
    assert sanitize_mdns_name("") == ""
    assert sanitize_mdns_name("_airplay._tcp.local") == ""
    assert sanitize_mdns_name("DESKTOP-AB12CD.local") == "DESKTOP-AB12CD"


def test_sanitize_vendor():
    assert sanitize_vendor("") == ""
    assert sanitize_vendor("unknown") == ""
    assert sanitize_vendor("Apple, Inc.") == "Apple"
    assert sanitize_vendor("Samsung Electronics Co.,Ltd.") == "Samsung"
    # Obscure OEM strings are discarded so a better source can name the device.
    assert sanitize_vendor("Shenzhen Foo Technology Co.,Ltd.") == ""


def test_is_junk_hostname():
    assert _is_junk_hostname("") is True
    assert _is_junk_hostname("_airplay") is True
    assert _is_junk_hostname("localhost") is True
    assert _is_junk_hostname("192.168.1.1") is True
    assert _is_junk_hostname("MyLaptop") is False


def _fake_device(**kw):
    base = dict(
        nickname="", vendor="", os_guess="", hostname="",
        recon_data={}, tcp_ttl=0, tcp_window=0,
        mac="00:11:22:33:44:55", services={}, open_ports=[], confidence=0,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_classify_device_nickname_wins():
    dev = _fake_device(nickname="Bob")
    out = classify_device(dev)
    assert "Bob" in out
    assert dev.confidence == 100


def test_classify_device_dhcp_hostname():
    dev = _fake_device(hostname="Galaxy-S23")
    out = classify_device(dev)
    assert "Galaxy S23" in out
    assert dev.confidence == 100


def test_classify_device_unknown():
    dev = _fake_device()
    out = classify_device(dev)
    assert out.startswith("❓")
