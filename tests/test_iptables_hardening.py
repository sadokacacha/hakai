"""
Regression tests for system/iptables_manager.py hardening (Phase-2 hunt).

IPT-1  add_accounting/add_drop ignored the insert (-A/-I) exit code: they
       recorded the IP even when the rule failed to apply, silently. They now
       return a success bool and log the failure (still tracking the IP so
       cleanup removes any rule that *did* get added).
IPT-2  no ipaddress validation before issuing root iptables commands.
IPT-5  _ipt raised on a missing iptables binary instead of degrading.

Mocked: _ipt / subprocess are patched, so no real iptables runs.
"""

from __future__ import annotations

import subprocess

from system import iptables_manager as ipt_mod
from system.iptables_manager import IPTManager


def _cp(rc: int):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr="err")


def test_add_accounting_reports_insert_failure(monkeypatch):
    # -C says the rule is absent (rc=1) and -A fails (rc=1).
    monkeypatch.setattr(ipt_mod, "_ipt", lambda *a, **k: _cp(1))
    m = IPTManager()
    assert m.add_accounting("10.0.0.5") is False, "a failed insert must not report success"
    # Still tracked so cleanup removes anything that partially applied.
    assert "10.0.0.5" in m._accounting


def test_add_accounting_success_when_rule_present(monkeypatch):
    # -C says the rule already exists (rc=0) → no -A needed → success.
    monkeypatch.setattr(ipt_mod, "_ipt", lambda *a, **k: _cp(0))
    m = IPTManager()
    assert m.add_accounting("10.0.0.5") is True
    assert "10.0.0.5" in m._accounting


def test_add_drop_reports_insert_failure(monkeypatch):
    monkeypatch.setattr(ipt_mod, "_ipt", lambda *a, **k: _cp(1))
    m = IPTManager()
    assert m.add_drop("10.0.0.9") is False


def test_add_accounting_rejects_invalid_ip(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ipt_mod, "_ipt", lambda *a, **k: calls.append(a) or _cp(0))
    m = IPTManager()
    assert m.add_accounting("not-an-ip") is False
    assert calls == [], "no iptables command may be issued for an invalid IP"
    assert "not-an-ip" not in m._accounting


def test_add_drop_rejects_invalid_ip(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ipt_mod, "_ipt", lambda *a, **k: calls.append(a) or _cp(0))
    m = IPTManager()
    assert m.add_drop("999.1.1.1") is False
    assert calls == []


def test_ipt_handles_missing_binary(monkeypatch):
    def _boom(*a, **k):
        raise FileNotFoundError("iptables not installed")

    monkeypatch.setattr(ipt_mod.subprocess, "run", _boom)
    r = ipt_mod._ipt("-C", "FORWARD", "-s", "10.0.0.5", "-j", "ACCEPT")
    assert r.returncode != 0, "_ipt must degrade, not raise, when iptables is missing"
