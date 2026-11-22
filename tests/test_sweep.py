"""
Tests for system/sweep.sweep_legacy (STEP 1 rename / orphan sweep).

A host that ran the pre-rename (Hakai) build may hold kernel objects the new
code would never clear. sweep_orphans removes them — plus our own current tables
that a hard kill could have left populated — at startup, best-effort.
"""

from __future__ import annotations

import subprocess

from system import sweep as sweep_mod
from system.sweep import sweep_orphans


def _cp(rc: int):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr="")


def test_sweep_clears_legacy_and_current_orphans(monkeypatch):
    monkeypatch.setattr(sweep_mod, "_IS_WINDOWS", False)
    calls: list[list[str]] = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        # iptables -D returns 1 once "no more rules" so the loop stops after one.
        return _cp(1 if "-D" in cmd else 0)

    sweep_orphans(run=fake_run)

    assert ["nft", "delete", "table", "inet", "hakai_stealth"] in calls
    assert ["nft", "delete", "table", "inet", "lanwarden"] in calls, "clears current FORWARD orphan"
    assert any("hakai_killswitch" in c for c in calls), "must delete the legacy killswitch rule"


def test_sweep_is_noop_on_windows(monkeypatch):
    monkeypatch.setattr(sweep_mod, "_IS_WINDOWS", True)
    calls: list = []
    sweep_orphans(run=lambda *a, **k: calls.append(a) or _cp(0))
    assert calls == []


def test_sweep_survives_missing_binaries(monkeypatch):
    monkeypatch.setattr(sweep_mod, "_IS_WINDOWS", False)

    def boom(cmd, *a, **k):
        raise FileNotFoundError("nft not installed")

    sweep_orphans(run=boom)  # must not raise
