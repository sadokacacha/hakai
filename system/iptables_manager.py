"""
system/iptables_manager.py — Manages two sets of iptables FORWARD rules:
  1. ACCEPT rules for byte-counting traffic (Layer 1 of TrafficCounter)
  2. DROP rules for actually cutting a device off the network
"""
from __future__ import annotations

import subprocess
import sys

_IS_WINDOWS = sys.platform == "win32"


def _ipt(*args, capture=True):
    """Run iptables command. No-op on Windows."""
    if _IS_WINDOWS:
        # Return a fake CompletedProcess with returncode=0
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    return subprocess.run(["iptables"] + list(args),
                          capture_output=capture, text=True)


class IPTManager:
    def __init__(self):
        self._accounting: set[str] = set()   # IPs with ACCEPT rules
        self._dropped:    set[str] = set()   # IPs with DROP rules

    # ── Accounting (byte counting) ─────────────────────────────────────────

    def add_accounting(self, ip: str):
        """Append FORWARD ACCEPT rules to count bytes for this IP (idempotent).

        These rules are *appended* (-A), never inserted at the top: cut DROP
        rules are inserted at FORWARD position 1, so appending guarantees a
        DROP always precedes the accounting ACCEPT and a cut cannot be shadowed.
        Byte counting is position-independent, so this does not affect totals.
        """
        if ip in self._accounting:
            return
        for flag in ("-s", "-d"):
            chk = _ipt("-C", "FORWARD", flag, ip, "-j", "ACCEPT")
            if chk.returncode != 0:
                _ipt("-A", "FORWARD", flag, ip, "-j", "ACCEPT")
        self._accounting.add(ip)

    def remove_accounting(self, ip: str):
        if ip not in self._accounting:
            return
        for flag in ("-s", "-d"):
            _ipt("-D", "FORWARD", flag, ip, "-j", "ACCEPT")
        self._accounting.discard(ip)

    def remove_all_accounting(self):
        for ip in list(self._accounting):
            self.remove_accounting(ip)

    # ── DROP (cut) ─────────────────────────────────────────────────────────

    def add_drop(self, ip: str):
        """Insert kernel-level FORWARD DROP rules — device instantly loses internet."""
        for flag in ("-s", "-d"):
            chk = _ipt("-C", "FORWARD", flag, ip, "-j", "DROP")
            if chk.returncode != 0:
                _ipt("-I", "FORWARD", "1", flag, ip, "-j", "DROP")
        self._dropped.add(ip)

    def remove_drop(self, ip: str):
        """Remove DROP rules (retries 3× to clear any duplicates)."""
        for _ in range(3):
            r1 = _ipt("-D", "FORWARD", "-s", ip, "-j", "DROP")
            r2 = _ipt("-D", "FORWARD", "-d", ip, "-j", "DROP")
            if r1.returncode != 0 and r2.returncode != 0:
                break
        self._dropped.discard(ip)

    def remove_all_drops(self):
        for ip in list(self._dropped):
            self.remove_drop(ip)

    def is_dropped(self, ip: str) -> bool:
        return ip in self._dropped

    # ── Full cleanup ──────────────────────────────────────────────────────

    def cleanup(self):
        self.remove_all_drops()
        self.remove_all_accounting()