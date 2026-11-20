"""
Regression tests for system/tc_manager.py (Phase-2 hunt).

TC-1  limit() returned True unconditionally — the class add/change return code
      only controlled a loop break, and the u32 filter results were ignored, so a
      failed `tc class`/`tc filter` still reported success to the UI.
TC-2  limit() issued tc commands for an unvalidated IP.

Mocked: _tc is patched; no real `tc` runs.
"""

from __future__ import annotations

import subprocess

from system import tc_manager as tc_mod
from system.tc_manager import TCManager


def _cp(rc: int):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr="err")


def _mgr():
    m = TCManager()
    m._iface = "eth0"
    m._active = True
    return m


def test_limit_returns_false_when_class_add_fails(monkeypatch):
    def fake_tc(iface, *args, **k):
        if args and args[0] == "class" and args[1] in ("add", "change"):
            return _cp(1)
        return _cp(0)

    monkeypatch.setattr(tc_mod, "_tc", fake_tc)
    assert _mgr().limit("192.168.1.5", 500) is False


def test_limit_returns_false_when_filter_add_fails(monkeypatch):
    def fake_tc(iface, *args, **k):
        if args and args[0] == "filter" and args[1] == "add":
            return _cp(1)
        return _cp(0)

    monkeypatch.setattr(tc_mod, "_tc", fake_tc)
    assert _mgr().limit("192.168.1.5", 500) is False


def test_limit_returns_true_when_all_ok(monkeypatch):
    monkeypatch.setattr(tc_mod, "_tc", lambda iface, *a, **k: _cp(0))
    assert _mgr().limit("192.168.1.5", 500) is True


def test_limit_rejects_invalid_ip(monkeypatch):
    calls: list = []
    monkeypatch.setattr(tc_mod, "_tc", lambda iface, *a, **k: calls.append(a) or _cp(0))
    assert _mgr().limit("not-an-ip", 500) is False
    assert calls == [], "no tc command may run for an invalid IP"


def test_failed_class_add_does_not_leave_phantom_class(monkeypatch):
    def fake_tc(iface, *args, **k):
        if args and args[0] == "class" and args[1] in ("add", "change"):
            return _cp(1)
        return _cp(0)

    monkeypatch.setattr(tc_mod, "_tc", fake_tc)
    m = _mgr()
    m.limit("192.168.1.5", 500)
    assert "192.168.1.5" not in m._classes, "a failed limit must not leave a phantom class id"
