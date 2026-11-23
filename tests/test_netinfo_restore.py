"""
Regression tests for system/netinfo.py restoration symmetry (Phase-2 hunt).

These are MOCKED tests: subprocess is patched, so they prove the restore logic
issues the correct commands with the captured original values. They do NOT
prove real-kernel restoration on a live host (that needs root + a real NIC).

Covers:
  NET-1  every sysctl engage_mitm() writes is reverted by restore_network()
         to the value captured before mutation (proxy_arp + per-iface rp_filter
         were previously never restored).
  NET-2  ethtool offloads are restored to their captured originals, not blindly
         forced back to "on".
  NET-3  restore_network() reports failure (returns False) when a command fails,
         instead of silently swallowing it.
"""

from __future__ import annotations

import subprocess

import pytest

from system import netinfo
from system.netinfo import NetInfo, engage_mitm, restore_network


def _mk_info() -> NetInfo:
    """A NetInfo whose captured originals deliberately differ from the values
    engage_mitm() forces, so a correct restore must put the originals back."""
    info = NetInfo(iface="eth0", my_ip="192.168.1.5", my_mac="aa:bb:cc:dd:ee:ff")
    info._orig_forwarding = "1"  # host was already a router
    info._orig_rp_filter = "2"  # loose mode (common modern default)
    info._orig_redirects = "1"
    info._orig_accept_redirects = "1"
    info._orig_proxy_arp = "0"
    info._orig_iface_rp_filter = "1"
    info._orig_promisc = False
    info._orig_offloads = {"gro": "off", "tso": "on"}
    return info


class _Recorder:
    """Records sysctl -w and ethtool -K invocations; makes every command succeed
    unless its arg-tuple is listed in ``fail``."""

    def __init__(self, fail: set[tuple[str, ...]] | None = None):
        self.sysctl_writes: list[str] = []  # "key=value"
        self.ethtool_sets: list[list[str]] = []
        self.fail = fail or set()

    def __call__(self, cmd, *args, **kwargs):
        rc = 1 if tuple(cmd) in self.fail else 0
        if cmd[:2] == ["sysctl", "-w"]:
            self.sysctl_writes.append(cmd[2])
        elif len(cmd) > 1 and cmd[1] == "-K":  # ethtool -K <iface> ... (path may be absolute)
            self.ethtool_sets.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=rc, stdout="", stderr="boom")


@pytest.fixture(autouse=True)
def _ethtool_present(monkeypatch):
    # restore_network / engage_mitm gate offload handling on shutil.which("ethtool")
    monkeypatch.setattr(netinfo.shutil, "which", lambda name: "/usr/sbin/ethtool")


def test_restore_reverts_every_engaged_sysctl(monkeypatch):
    """NET-1: restore must write back the captured original for every sysctl
    that engage mutated — including proxy_arp and the per-iface rp_filter."""
    info = _mk_info()

    engage = _Recorder()
    monkeypatch.setattr(netinfo.subprocess, "run", engage)
    engage_mitm(info)

    restore = _Recorder()
    monkeypatch.setattr(netinfo.subprocess, "run", restore)
    restore_network(info)

    engaged_keys = {w.split("=", 1)[0] for w in engage.sysctl_writes}
    restored = dict(w.split("=", 1) for w in restore.sysctl_writes)

    expected_original = {
        "net.ipv4.ip_forward": info._orig_forwarding,
        "net.ipv4.conf.all.rp_filter": info._orig_rp_filter,
        "net.ipv4.conf.eth0.rp_filter": info._orig_iface_rp_filter,
        "net.ipv4.conf.all.proxy_arp": info._orig_proxy_arp,
        "net.ipv4.conf.all.send_redirects": info._orig_redirects,
        "net.ipv4.conf.all.accept_redirects": info._orig_accept_redirects,
    }

    for key in engaged_keys:
        assert key in restored, f"{key} was engaged but never restored"
        assert restored[key] == expected_original[key], (
            f"{key} restored to {restored[key]!r}, expected original {expected_original[key]!r}"
        )


def test_restore_offloads_to_captured_state_not_blindly_on(monkeypatch):
    """NET-2: a feature captured as 'off' must be restored to 'off'."""
    info = _mk_info()

    monkeypatch.setattr(netinfo.subprocess, "run", _Recorder())
    engage_mitm(info)

    restore = _Recorder()
    monkeypatch.setattr(netinfo.subprocess, "run", restore)
    restore_network(info)

    # Flatten the ethtool -K calls into {feature: state}
    restored_offloads: dict[str, str] = {}
    for call in restore.ethtool_sets:
        # ["ethtool", "-K", "eth0", "gro", "off", "tso", "on", ...]
        params = call[3:]
        for i in range(0, len(params) - 1, 2):
            restored_offloads[params[i]] = params[i + 1]

    assert restored_offloads.get("gro") == "off", "gro was off originally; must not be forced on"
    assert restored_offloads.get("tso") == "on"


def test_restore_reports_failure(monkeypatch):
    """NET-3: a failing restore command must surface as a False return, not a
    swallowed no-op."""
    info = _mk_info()
    fail = {("sysctl", "-w", f"net.ipv4.ip_forward={info._orig_forwarding}")}

    monkeypatch.setattr(netinfo.subprocess, "run", _Recorder(fail=fail))
    ok = restore_network(info)
    assert ok is False


def test_restore_reports_success(monkeypatch):
    info = _mk_info()
    monkeypatch.setattr(netinfo.subprocess, "run", _Recorder())
    assert restore_network(info) is True


# ── NET-4 (C3): engage/restore offload symmetry ─────────────────────────────


def test_engage_disables_only_captured_offloads(monkeypatch):
    """engage must disable exactly the offloads whose originals were captured —
    so every offload it turns off has a record restore can turn back on."""
    info = _mk_info()  # captured {"gro": "off", "tso": "on"}

    rec = _Recorder()
    monkeypatch.setattr(netinfo.subprocess, "run", rec)
    engage_mitm(info)

    assert len(rec.ethtool_sets) == 1, "exactly one ethtool -K disable call"
    call = rec.ethtool_sets[0]
    params = call[call.index("-K") + 2 :]  # skip "-K <iface>"
    flags = params[0::2]
    states = params[1::2]
    assert set(flags) == {"gro", "tso"}, "only the captured offloads are touched"
    assert set(states) == {"off"}, "engage turns the captured offloads off"


def test_engage_skips_offloads_when_none_captured(monkeypatch):
    """If `ethtool -k` yielded nothing at detect time (empty capture), engage
    must NOT force offloads off — there'd be no record to restore them."""
    info = _mk_info()
    info._orig_offloads = {}  # capture returned nothing

    rec = _Recorder()
    monkeypatch.setattr(netinfo.subprocess, "run", rec)
    engage_mitm(info)

    assert rec.ethtool_sets == [], "must not disable offloads we can't restore"
