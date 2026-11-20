"""
Regression tests for system/firewall_apex.py (Phase-2 hunt).

FW-1  On enable, the chain is created with `policy drop` first, then the
      established/lo accept rules are added. If a rule add failed mid-build, the
      old code returned an error but left a drop-policy chain WITHOUT the accept
      rules — locking the host out of its own network — while self.active stayed
      False (so the UI wouldn't show it on to let the user disable it). The build
      must now be rolled back (table deleted) on any failure.

Mocked: subprocess is patched; no real nft runs.
"""

from __future__ import annotations

import subprocess

from system import firewall_apex as fw_mod
from system.firewall_apex import GhostFirewall


def _cp(rc: int):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr="err")


def test_enable_rolls_back_half_built_table_on_failure(monkeypatch):
    fw = GhostFirewall()
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        # Fail when adding the "established,related accept" rule.
        if cmd[:3] == ["nft", "add", "rule"] and any("established,related" in str(x) for x in cmd):
            if k.get("check"):
                raise subprocess.CalledProcessError(1, cmd)
            return _cp(1)
        return _cp(0)

    monkeypatch.setattr(fw_mod.subprocess, "run", fake_run)
    status = fw.toggle_stealth(True)

    assert fw.active is False
    assert "FAIL" in status.upper() or "ERROR" in status.upper()
    # Two deletes: the initial clean-slate one AND the rollback after the failure.
    deletes = [c for c in calls if c[:3] == ["nft", "delete", "table"]]
    assert len(deletes) >= 2, "a partial build must be torn down so the host isn't locked out"


def test_enable_success_sets_active(monkeypatch):
    fw = GhostFirewall()
    monkeypatch.setattr(fw_mod.subprocess, "run", lambda cmd, *a, **k: _cp(0))
    status = fw.toggle_stealth(True)
    assert fw.active is True
    assert "LOCKED" in status.upper()


def test_disable_removes_table_and_clears_active(monkeypatch):
    fw = GhostFirewall()
    fw.active = True
    calls: list = []
    monkeypatch.setattr(fw_mod.subprocess, "run", lambda cmd, *a, **k: calls.append(cmd) or _cp(0))
    status = fw.toggle_stealth(False)
    assert fw.active is False
    assert "DISENGAGED" in status.upper()
    assert ["nft", "delete", "table", "inet", "hakai_stealth"] in calls
