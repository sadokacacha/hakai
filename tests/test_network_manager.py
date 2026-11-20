"""
Regression tests for system/network_manager.py (Phase-2 hunt).

NM-1  apply_static_config passed the user-typed ip/gateway/dns straight into
      privileged nmcli with no validation.
NM-2  the 5-step nmcli modify sequence had no rollback: a mid-sequence failure
      left the connection half-configured in manual mode (connectivity can drop).

Mocked: shutil.which + subprocess are patched; no real nmcli runs.
"""

from __future__ import annotations

import subprocess

from system import network_manager as nm_mod


def _cp(rc: int):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr="err")


def _patch_nmcli(monkeypatch):
    monkeypatch.setattr(nm_mod.shutil, "which", lambda name: "/usr/bin/nmcli")


def test_apply_rejects_invalid_ip(monkeypatch):
    _patch_nmcli(monkeypatch)
    calls: list = []
    monkeypatch.setattr(nm_mod.subprocess, "run", lambda *a, **k: calls.append(a) or _cp(0))
    ok, _ = nm_mod.apply_static_config("Wired", "garbage", "192.168.1.1")
    assert ok is False
    assert calls == [], "no nmcli command may run for an invalid address"


def test_apply_rejects_invalid_gateway(monkeypatch):
    _patch_nmcli(monkeypatch)
    calls: list = []
    monkeypatch.setattr(nm_mod.subprocess, "run", lambda *a, **k: calls.append(a) or _cp(0))
    ok, _ = nm_mod.apply_static_config("Wired", "192.168.1.50/24", "999.1.1.1")
    assert ok is False
    assert calls == []


def test_apply_rejects_invalid_dns(monkeypatch):
    _patch_nmcli(monkeypatch)
    calls: list = []
    monkeypatch.setattr(nm_mod.subprocess, "run", lambda *a, **k: calls.append(a) or _cp(0))
    ok, _ = nm_mod.apply_static_config("Wired", "192.168.1.50/24", "192.168.1.1", dns="not-an-ip")
    assert ok is False
    assert calls == []


def test_apply_accepts_valid_config(monkeypatch):
    _patch_nmcli(monkeypatch)
    monkeypatch.setattr(nm_mod.subprocess, "run", lambda *a, **k: _cp(0))
    ok, _ = nm_mod.apply_static_config(
        "Wired", "192.168.1.50/24", "192.168.1.1", dns="8.8.8.8,1.1.1.1"
    )
    assert ok is True


def test_apply_reverts_to_dhcp_on_mid_sequence_failure(monkeypatch):
    _patch_nmcli(monkeypatch)
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        if "ipv4.gateway" in cmd:  # fail the gateway step
            if k.get("check"):
                raise subprocess.CalledProcessError(1, cmd)
            return _cp(1)
        return _cp(0)

    monkeypatch.setattr(nm_mod.subprocess, "run", fake_run)
    ok, msg = nm_mod.apply_static_config("Wired", "192.168.1.50/24", "192.168.1.1")

    assert ok is False
    reverted = any("ipv4.method" in cmd and "auto" in cmd and "Wired" in cmd for cmd in calls)
    assert reverted, "a mid-sequence failure must revert the connection to DHCP"
    assert "DHCP" in msg.upper()
