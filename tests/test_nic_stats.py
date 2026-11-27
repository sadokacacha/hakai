"""Cross-platform NIC stats + interface enumeration (psutil-backed).

psutil and the platform flag are mocked so these run identically on any OS and
never touch real hardware.
"""

from __future__ import annotations

import socket
import types

import network.traffic as traffic
import system.netinfo as netinfo
from network.traffic import TrafficCounter


def _snetio(rx, tx):
    return types.SimpleNamespace(bytes_recv=rx, bytes_sent=tx)


def _snicstats(isup=True, speed=100):
    return types.SimpleNamespace(isup=isup, speed=speed)


# ── TrafficCounter._read_nic_psutil / _read_proc ───────────────────────────────


def test_read_nic_psutil_returns_counters(monkeypatch):
    fake = types.SimpleNamespace(net_io_counters=lambda pernic: {"eth0": _snetio(1000, 250)})
    monkeypatch.setattr(traffic, "PSUTIL_OK", True)
    monkeypatch.setattr(traffic, "psutil", fake)
    assert TrafficCounter._read_nic_psutil("eth0") == (1000, 250)


def test_read_nic_psutil_unknown_iface_returns_none(monkeypatch):
    fake = types.SimpleNamespace(net_io_counters=lambda pernic: {"eth0": _snetio(1, 2)})
    monkeypatch.setattr(traffic, "PSUTIL_OK", True)
    monkeypatch.setattr(traffic, "psutil", fake)
    assert TrafficCounter._read_nic_psutil("wlan9") is None


def test_read_nic_psutil_absent_returns_none(monkeypatch):
    monkeypatch.setattr(traffic, "PSUTIL_OK", False)
    assert TrafficCounter._read_nic_psutil("eth0") is None


def test_read_proc_prefers_psutil(monkeypatch):
    fake = types.SimpleNamespace(net_io_counters=lambda pernic: {"eth0": _snetio(5, 7)})
    monkeypatch.setattr(traffic, "PSUTIL_OK", True)
    monkeypatch.setattr(traffic, "psutil", fake)
    # Even on "Linux", psutil wins; /proc is never consulted.
    monkeypatch.setattr(traffic, "_IS_WINDOWS", False)
    assert TrafficCounter._read_proc("eth0") == (5, 7)


def test_read_proc_windows_without_psutil_is_honest_zero(monkeypatch):
    monkeypatch.setattr(traffic, "PSUTIL_OK", False)
    monkeypatch.setattr(traffic, "_IS_WINDOWS", True)
    # No psutil, no /proc on Windows → (0, 0). The capability layer reports why.
    assert TrafficCounter._read_proc("Ethernet") == (0, 0)


def test_read_proc_linux_falls_back_to_proc(monkeypatch, tmp_path):
    monkeypatch.setattr(traffic, "PSUTIL_OK", False)
    monkeypatch.setattr(traffic, "_IS_WINDOWS", False)
    sample = (
        "Inter-|   Receive                    |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes ...\n"
        "  eth0: 123456    10    0    0    0     0          0         0  65432 ...\n"
    )
    import builtins

    real_open = builtins.open

    def fake_open(path, *a, **k):
        if path == "/proc/net/dev":
            import io

            return io.StringIO(sample)
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    assert TrafficCounter._read_proc("eth0") == (123456, 65432)


# ── list_interfaces ────────────────────────────────────────────────────────────


def test_list_interfaces_psutil_filters_loopback_and_sorts(monkeypatch):
    addrs = {
        "lo": [types.SimpleNamespace(family=socket.AF_INET, address="127.0.0.1")],
        "eth0": [
            types.SimpleNamespace(family=socket.AF_INET, address="192.168.1.5"),
            types.SimpleNamespace(
                family=getattr(socket, "AF_PACKET", -99), address="aa:bb:cc:dd:ee:ff"
            ),
        ],
        "eth1": [types.SimpleNamespace(family=socket.AF_INET, address="10.0.0.2")],
    }
    stats = {"eth0": _snicstats(isup=True, speed=1000), "eth1": _snicstats(isup=False, speed=0)}
    fake = types.SimpleNamespace(net_if_addrs=lambda: addrs, net_if_stats=lambda: stats)
    monkeypatch.setattr(netinfo, "_PSUTIL_OK", True)
    monkeypatch.setattr(netinfo, "psutil", fake)

    out = netinfo.list_interfaces()
    names = [i.name for i in out]
    assert "lo" not in names  # loopback filtered
    # up interface (eth0) sorts before down interface (eth1)
    assert names == ["eth0", "eth1"]
    eth0 = out[0]
    assert eth0.ipv4 == "192.168.1.5"
    assert eth0.is_up and eth0.speed_mbps == 1000


def test_list_interfaces_include_loopback(monkeypatch):
    addrs = {"lo": [types.SimpleNamespace(family=socket.AF_INET, address="127.0.0.1")]}
    fake = types.SimpleNamespace(net_if_addrs=lambda: addrs, net_if_stats=lambda: {})
    monkeypatch.setattr(netinfo, "_PSUTIL_OK", True)
    monkeypatch.setattr(netinfo, "psutil", fake)
    out = netinfo.list_interfaces(include_loopback=True)
    assert [i.name for i in out] == ["lo"]


def test_list_interfaces_enumeration_failure_returns_empty(monkeypatch):
    def boom():
        raise RuntimeError("no access")

    fake = types.SimpleNamespace(net_if_addrs=boom, net_if_stats=lambda: {})
    monkeypatch.setattr(netinfo, "_PSUTIL_OK", True)
    monkeypatch.setattr(netinfo, "psutil", fake)
    # Must degrade to [] (reported by capability layer), never raise into startup.
    assert netinfo.list_interfaces() == []


def test_list_interfaces_linux_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(netinfo, "_PSUTIL_OK", False)
    # Build a fake /sys/class/net
    base = tmp_path / "net"
    for nm, mac, up in [("eth0", "aa:bb:cc:dd:ee:01", "up"), ("lo", "00:00:00:00:00:00", "down")]:
        d = base / nm
        d.mkdir(parents=True)
        (d / "address").write_text(mac + "\n")
        (d / "operstate").write_text(up + "\n")

    import os as _os

    real_listdir, real_open = _os.listdir, open

    def fake_listdir(path):
        if path == "/sys/class/net":
            return real_listdir(str(base))
        return real_listdir(path)

    def fake_open(path, *a, **k):
        if isinstance(path, str) and path.startswith("/sys/class/net/"):
            return real_open(str(base / path[len("/sys/class/net/") :]), *a, **k)
        return real_open(path, *a, **k)

    monkeypatch.setattr(netinfo, "list_interfaces", netinfo.list_interfaces)
    monkeypatch.setattr(_os, "listdir", fake_listdir)
    import builtins

    monkeypatch.setattr(builtins, "open", fake_open)

    out = netinfo.list_interfaces()
    names = [i.name for i in out]
    assert names == ["eth0"]  # lo filtered
    assert out[0].mac == "AA:BB:CC:DD:EE:01"
    assert out[0].is_up
