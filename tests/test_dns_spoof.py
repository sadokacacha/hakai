"""
Regression tests for network/dns_spoof.py cleanup correctness (Phase-2 hunt).

Scope note: this is an offensive module. These tests/fixes target reliability
only — input validation and iptables rule-leak/cleanup — not spoof effectiveness.

DNS-1  start_spoof/stop_spoof passed target_ip to root iptables with no
       ipaddress validation.
DNS-2  start_spoof used -I with no -C guard and stop_spoof did a single -D, so a
       repeated start leaked a duplicate NAT REDIRECT rule that cleanup missed.

Mocked: subprocess and the sniff loop are patched; no real iptables or sniffer.
"""

from __future__ import annotations

import subprocess

import pytest

from network import dns_spoof as dns_mod
from network.dns_spoof import DnsSpoofManager


def _cp(rc: int):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr="err")


@pytest.fixture(autouse=True)
def _no_real_sniffer(monkeypatch):
    # Prevent start_spoof from launching a real scapy sniff thread.
    monkeypatch.setattr(dns_mod.DnsSpoofManager, "_sniff_loop", lambda self: None)


def test_start_spoof_rejects_invalid_ip(monkeypatch):
    calls: list = []
    monkeypatch.setattr(dns_mod.subprocess, "run", lambda *a, **k: calls.append(a) or _cp(0))
    mgr = DnsSpoofManager()
    assert mgr.start_spoof("not-an-ip") is False
    assert calls == [], "no iptables command may run for an invalid IP"
    assert "not-an-ip" not in mgr._spoof_map


def test_start_spoof_checks_before_insert(monkeypatch):
    seen: list = []

    def _fake(cmd, *a, **k):
        seen.append(cmd)
        return _cp(0)  # -C reports the rule already exists

    monkeypatch.setattr(dns_mod.subprocess, "run", _fake)
    mgr = DnsSpoofManager()
    mgr.start_spoof("10.0.0.5")

    inserts = [c for c in seen if "-I" in c]
    assert inserts == [], "must not -I when -C says the rule already exists (duplicate leak)"


def test_stop_spoof_clears_duplicate_rules(monkeypatch):
    calls: list = []
    results = iter([_cp(0), _cp(0), _cp(1)])  # two duplicates removed, then none left

    def _fake(cmd, *a, **k):
        calls.append(cmd)
        return next(results, _cp(1))

    monkeypatch.setattr(dns_mod.subprocess, "run", _fake)
    mgr = DnsSpoofManager()
    mgr._spoof_map["10.0.0.5"] = "1.2.3.4"
    mgr.stop_spoof("10.0.0.5")

    deletes = [c for c in calls if "-D" in c]
    assert len(deletes) >= 2, "stop_spoof must retry -D to clear duplicate NAT rules"


# ── /wire: start_spoof must report the truth about the REDIRECT rule ─────────


def test_start_spoof_returns_false_when_insert_fails(monkeypatch):
    def _fake(cmd, *a, **k):
        # -C says absent (rc=1), then -I also fails (rc=1) → rule NOT installed.
        return _cp(1)

    monkeypatch.setattr(dns_mod.subprocess, "run", _fake)
    mgr = DnsSpoofManager()
    assert mgr.start_spoof("10.0.0.5") is False
    assert "10.0.0.5" not in mgr._spoof_map, "optimistic state must be rolled back"
    assert mgr._running is False


def test_start_spoof_returns_true_when_rule_added(monkeypatch):
    results = iter([_cp(1), _cp(0)])  # -C absent, then -I succeeds

    monkeypatch.setattr(dns_mod.subprocess, "run", lambda *a, **k: next(results, _cp(0)))
    mgr = DnsSpoofManager()
    assert mgr.start_spoof("10.0.0.5") is True
    assert mgr._spoof_map.get("10.0.0.5") == "1.2.3.4"
