"""
Regression tests for system/stealth.py un-cloak restoration (Phase-2 hunt).

This covers disengage_stealth (restore the REAL identity) only — not the cloak
itself, which is an evasion feature left functionally unchanged.

STEALTH-1  disengage_stealth ran every restore step in one try/except with
           check=True, so a hostname-restore failure aborted the MAC restore and
           the nft-table removal — leaving the spoofed MAC and stealth firewall
           in place.
STEALTH-2  it returned "[IDENTITY RESTORED]" unconditionally, even on failure.

Mocked: subprocess is patched; no real hostnamectl/ip/nft runs.
"""

from __future__ import annotations

import subprocess

from system import stealth as stealth_mod


def test_disengage_restores_mac_and_firewall_even_if_hostname_fails(monkeypatch):
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        rc = 1 if cmd[:2] == ["hostnamectl", "set-hostname"] else 0
        if k.get("check") and rc != 0:
            raise subprocess.CalledProcessError(rc, cmd)
        return subprocess.CompletedProcess(cmd, rc, "", "boom")

    monkeypatch.setattr(stealth_mod.subprocess, "run", fake_run)

    status = stealth_mod.disengage_stealth(
        "wlan0", orig_mac="aa:bb:cc:dd:ee:ff", orig_hostname="real-host"
    )

    # The MAC restore must be attempted despite the hostname failure.
    assert ["ip", "link", "set", "wlan0", "address", "aa:bb:cc:dd:ee:ff"] in calls
    # The stealth firewall table removal must be attempted too.
    assert any(c[:3] == ["nft", "delete", "table"] for c in calls)
    # And the status must be truthful (not a false "RESTORED").
    assert "INCOMPLETE" in status.upper()


def test_disengage_reports_success_when_all_ok(monkeypatch):
    monkeypatch.setattr(
        stealth_mod.subprocess,
        "run",
        lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    status = stealth_mod.disengage_stealth(
        "wlan0", orig_mac="aa:bb:cc:dd:ee:ff", orig_hostname="real-host"
    )
    assert "RESTORED" in status.upper() and "INCOMPLETE" not in status.upper()
