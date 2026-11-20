"""
Regression tests for network/fingerprint.py (Phase-2 hunt).

FP-1  fingerprint_device issued nmap for an unvalidated IP (and always spawned a
      thread to do it). It now validates synchronously and skips nmap on a bad IP.
FP-parse  the nmap output parsing is extracted into a pure, testable helper.

Mocked: subprocess/shutil are patched; no real nmap runs.
"""

from __future__ import annotations

from network import fingerprint as fp_mod


def test_invalid_ip_skips_nmap_and_returns_empty(monkeypatch):
    ran: list = []
    monkeypatch.setattr(fp_mod.subprocess, "run", lambda *a, **k: ran.append(a))
    monkeypatch.setattr(fp_mod.shutil, "which", lambda name: "/usr/bin/nmap")

    got: dict = {}
    fp_mod.fingerprint_device("not-an-ip", lambda p, o, s: got.update(ports=p, os=o, svcs=s))

    assert got == {"ports": [], "os": "", "svcs": {}}, "invalid IP → empty result, synchronously"
    assert ran == [], "nmap must not run for an invalid IP"


def test_parse_nmap_extracts_ports_services_and_os():
    out = (
        "Nmap scan report for 192.168.1.5\n"
        "22/tcp open ssh OpenSSH 8.9\n"
        "80/tcp open http nginx 1.24\n"
        "443/tcp open https\n"
        "OS details: Linux 5.15\n"
    )
    ports, os_g, svcs = fp_mod._parse_nmap(out)
    assert ports == [22, 80, 443]
    assert svcs[22] == "ssh OpenSSH 8.9"
    assert svcs[443] == "https"
    assert os_g == "Linux 5.15"


def test_parse_nmap_aggressive_guess_when_no_os_details():
    out = "Aggressive OS guesses: Linux 4.x (95%), Linux 5.x (90%)\n"
    ports, os_g, _ = fp_mod._parse_nmap(out)
    assert ports == []
    assert os_g == "Linux 4.x"


def test_parse_nmap_empty_output():
    assert fp_mod._parse_nmap("") == ([], "", {})
