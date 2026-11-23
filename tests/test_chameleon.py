"""
Regression tests for system/chameleon.py (Phase-2 hunt).

Evasion module — restore correctness + cleanup hygiene only, not evasion
effectiveness.

CHAM-1  disable hardcoded `mtu 1500`; the original MTU was never captured, so a
        non-1500 setup (VPN/PPPoE/jumbo) was restored to the wrong value.
CHAM-3  enable used -A with no -C, stacking duplicate mangle rules on repeat.
CHAM-4  no empty-interface guard.

Mocked: subprocess is patched; no real ip/iptables runs.
"""

from __future__ import annotations

import subprocess

from system import chameleon as cham_mod


def _cp(rc: int, stdout: str = ""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr="err")


def test_disable_restores_captured_original_mtu(monkeypatch):
    cham_mod._ORIG_MTU.clear()
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        if cmd[:4] == ["ip", "-o", "link", "show"]:
            return _cp(0, stdout="2: eth0: <BROADCAST> mtu 1400 qdisc fq_codel")
        return _cp(0)

    monkeypatch.setattr(cham_mod.subprocess, "run", fake_run)
    cham_mod.toggle_chameleon("eth0", True)  # captures 1400, sets 1492
    cham_mod.toggle_chameleon("eth0", False)  # must restore 1400, not 1500

    assert ["ip", "link", "set", "dev", "eth0", "mtu", "1400"] in calls
    assert ["ip", "link", "set", "dev", "eth0", "mtu", "1500"] not in calls


def test_enable_checks_before_adding_mss_rule(monkeypatch):
    cham_mod._ORIG_MTU.clear()
    seen: list = []

    def fake_run(cmd, *a, **k):
        seen.append(cmd)
        if cmd[:4] == ["ip", "-o", "link", "show"]:
            return _cp(0, stdout="mtu 1500")
        return _cp(0)  # -C returns 0 → rule already present

    monkeypatch.setattr(cham_mod.subprocess, "run", fake_run)
    cham_mod.toggle_chameleon("eth0", True)

    adds = [c for c in seen if "-A" in c]
    assert adds == [], "must not -A when -C says the mangle rule already exists"


def test_toggle_rejects_empty_iface(monkeypatch):
    calls: list = []
    monkeypatch.setattr(cham_mod.subprocess, "run", lambda *a, **k: calls.append(a) or _cp(0))
    status = cham_mod.toggle_chameleon("", True)
    assert "FAIL" in status.upper() or "ERROR" in status.upper()
    assert calls == [], "no command may run without an interface"


# ── CHAM-5 (C5): capture-or-None + rollback on partial engage failure ───────


def test_engage_skips_mtu_shift_when_capture_fails(monkeypatch):
    """If the original MTU can't be read, the engine must NOT shift the MTU to
    1492 (it could never be restored) and must record no original."""
    cham_mod._ORIG_MTU.clear()
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        if cmd[:4] == ["ip", "-o", "link", "show"]:
            return _cp(1, stdout="")  # MTU read FAILS (rc=1)
        return _cp(0)

    monkeypatch.setattr(cham_mod.subprocess, "run", fake_run)
    cham_mod.toggle_chameleon("eth0", True)

    assert ["ip", "link", "set", "dev", "eth0", "mtu", "1492"] not in calls, (
        "must not shift an MTU whose original wasn't captured"
    )
    assert "eth0" not in cham_mod._ORIG_MTU


def test_engage_reverts_mtu_when_mss_clamp_fails(monkeypatch):
    """If the MSS clamp -A fails after the MTU was shifted, the MTU must be
    reverted to its captured original (no half-changed state left behind)."""
    cham_mod._ORIG_MTU.clear()
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        if cmd[:4] == ["ip", "-o", "link", "show"]:
            return _cp(0, stdout="2: eth0: <BROADCAST> mtu 1400 qdisc fq_codel")
        if "-C" in cmd:
            return _cp(1)  # rule absent → engine will try -A
        if "-A" in cmd:
            return _cp(1)  # the MSS clamp add FAILS
        return _cp(0)  # MTU sets and the rollback -D succeed

    monkeypatch.setattr(cham_mod.subprocess, "run", fake_run)
    status = cham_mod.toggle_chameleon("eth0", True)

    assert ["ip", "link", "set", "dev", "eth0", "mtu", "1492"] in calls, "MTU was shifted"
    assert ["ip", "link", "set", "dev", "eth0", "mtu", "1400"] in calls, (
        "the shifted MTU must be reverted to the captured original on MSS failure"
    )
    assert "FAIL" in status.upper() or "ERROR" in status.upper()
    assert "eth0" not in cham_mod._ORIG_MTU, "rollback must clear the capture record"


def test_restore_does_not_touch_mtu_when_never_engaged(monkeypatch):
    # P9: calling _restore for an iface we never engaged must NOT set an MTU
    # (previously it guessed 1500, clobbering jumbo/VPN MTUs) — this makes it
    # safe for Controller.stop() to call unconditionally.
    cham_mod._ORIG_MTU.clear()
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        return _cp(1)  # any mangle -D "fails" (rule absent) → loop breaks

    monkeypatch.setattr(cham_mod.subprocess, "run", fake_run)
    cham_mod.toggle_chameleon("eth0", False)

    mtu_sets = [c for c in calls if c[:4] == ["ip", "link", "set", "dev"]]
    assert mtu_sets == [], "no MTU must be set for an iface that was never engaged"
