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


# ── engage_mirage_cloak: link recovery + GhostFirewall reuse ────────────────
# C1/C2 (inline stealth firewall could lock the host out, lacked `iif lo accept`)
# and C7 (a failed MAC change left the interface stranded down, silently).


class _FakeGhostFirewall:
    """Stand-in so engage never shells out to real nft; records engagement."""

    engaged: bool = False

    def toggle_stealth(self, enable: bool) -> str:
        type(self).engaged = enable
        return "[SHIELDS: LOCKED]"


def test_engage_recovers_link_up_when_mac_change_fails(monkeypatch):
    """C7: a FAILED MAC capture/apply must bring the interface back UP (never
    leave it stranded down) and report an empty MAC so the caller doesn't adopt
    a MAC it never actually set."""
    _FakeGhostFirewall.engaged = False
    calls: list = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd)
        # The MAC *address* set fails; everything else (down/up) succeeds.
        rc = 1 if cmd[:5] == ["ip", "link", "set", "wlan0", "address"] else 0
        return subprocess.CompletedProcess(cmd, rc, "", "cannot assign")

    monkeypatch.setattr(stealth_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(stealth_mod, "GhostFirewall", _FakeGhostFirewall)
    monkeypatch.setattr(stealth_mod.time, "sleep", lambda *_a: None)

    msg, new_mac = stealth_mod.engage_mirage_cloak("wlan0", "iPhone-15-Pro")

    # The link must be brought back up after the failed address set.
    assert ["ip", "link", "set", "wlan0", "up"] in calls, "stranded-down link must be recovered"
    # The caller must not be handed a MAC that was never applied.
    assert new_mac == ""
    assert "PARTIAL" in msg.upper()


def test_engage_cloaks_and_reuses_ghost_firewall_when_all_ok(monkeypatch):
    """C1/C2: the firewall is built via GhostFirewall (established + loopback
    accepts, rollback-on-failure) rather than the old inline drop-only copy."""
    _FakeGhostFirewall.engaged = False
    monkeypatch.setattr(
        stealth_mod.subprocess,
        "run",
        lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    monkeypatch.setattr(stealth_mod, "GhostFirewall", _FakeGhostFirewall)
    monkeypatch.setattr(stealth_mod.time, "sleep", lambda *_a: None)

    msg, new_mac = stealth_mod.engage_mirage_cloak("wlan0", "iPhone-15-Pro")

    assert new_mac, "a successful cloak must report the new MAC"
    assert "CLOAKED" in msg.upper()
    assert _FakeGhostFirewall.engaged is True, (
        "must engage the shared GhostFirewall, not inline nft"
    )
