"""
Regression tests for system/masquerade.py restoration (Phase-2 hunt).

Evasion module — only the *disable* path (restore the real TCP/IP fingerprint,
the un-masquerade/safe direction) is changed; engage (apply the mimic) is kept
functionally identical.

MASQ-2  disable used a single `for … sysctl -w … check=True` loop, so one failed
        restore aborted the rest, leaving the host partially masqueraded.
MASQ-3  disable did not report a partial restore truthfully.

Mocked: subprocess is patched; no real sysctl runs.
"""

from __future__ import annotations

import subprocess

from system import masquerade as masq_mod

_KEYS = ("net.ipv4.ip_default_ttl", "net.ipv4.tcp_window_scaling", "net.ipv4.tcp_timestamps")


def _seed_orig():
    masq_mod._ORIG.clear()
    masq_mod._ORIG.update({_KEYS[0]: "64", _KEYS[1]: "1", _KEYS[2]: "1"})


def test_restore_isolates_failures_and_reports_truthfully(monkeypatch):
    _seed_orig()
    writes: list = []

    def fake_run(cmd, *a, **k):
        writes.append(cmd)
        rc = 1 if cmd[-1].startswith("net.ipv4.ip_default_ttl=") else 0
        if k.get("check") and rc:
            raise subprocess.CalledProcessError(rc, cmd)
        return subprocess.CompletedProcess(cmd, rc, "", "err")

    monkeypatch.setattr(masq_mod.subprocess, "run", fake_run)
    status = masq_mod.apply_stack_masquerade(False)

    written = [c[-1] for c in writes]
    assert any("ip_default_ttl=" in w for w in written)
    assert any("tcp_window_scaling=" in w for w in written), (
        "a failure must not abort later restores"
    )
    assert any("tcp_timestamps=" in w for w in written)
    assert "INCOMPLETE" in status.upper()


def test_restore_reports_native_when_all_ok(monkeypatch):
    _seed_orig()
    monkeypatch.setattr(
        masq_mod.subprocess, "run", lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, "", "")
    )
    assert "NATIVE" in masq_mod.apply_stack_masquerade(False).upper()


def test_restore_noop_when_nothing_captured(monkeypatch):
    masq_mod._ORIG.clear()
    calls: list = []
    monkeypatch.setattr(
        masq_mod.subprocess,
        "run",
        lambda cmd, *a, **k: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    status = masq_mod.apply_stack_masquerade(False)
    assert calls == [], "nothing was masqueraded → no sysctl writes on restore"
    assert "NATIVE" in status.upper()


def test_engage_still_applies_mimic_values(monkeypatch):
    # The evasion apply path must stay functionally unchanged by the refactor.
    masq_mod._ORIG.clear()
    writes: list = []

    def fake_run(cmd, *a, **k):
        writes.append(cmd)
        out = "64" if cmd[:2] == ["sysctl", "-n"] else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(masq_mod.subprocess, "run", fake_run)
    status = masq_mod.apply_stack_masquerade(True)
    applied = [c[-1] for c in writes if c[:2] == ["sysctl", "-w"]]
    assert "net.ipv4.ip_default_ttl=128" in applied
    assert "net.ipv4.tcp_timestamps=0" in applied
    assert "MATCH" in status.upper()
