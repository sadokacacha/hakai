"""
system/iptables_manager.py — Manages two sets of iptables FORWARD rules:
  1. ACCEPT rules for byte-counting traffic (Layer 1 of TrafficCounter)
  2. DROP rules for actually cutting a device off the network

NOTE: the DROP half (add_drop/remove_drop/is_dropped) is currently unreferenced
by the app — network/arp.py applies its own FORWARD DROP. See audit.md IPT/ARP.
"""

from __future__ import annotations

import logging
import subprocess
import sys

from core.netutil import valid_ip

_IS_WINDOWS = sys.platform == "win32"
_log = logging.getLogger(__name__)


def _ipt(*args, capture=True):
    """Run an iptables command. No-op on Windows; degrades (rc != 0) rather than
    raising if the iptables binary is missing."""
    if _IS_WINDOWS:
        # Returns rc=0, but callers log a warning for Windows — see audit IPT-win.
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    try:
        return subprocess.run(["iptables"] + list(args), capture_output=capture, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        _log.warning("iptables %s failed to run: %s", " ".join(args), e)
        return subprocess.CompletedProcess(args=list(args), returncode=1, stdout="", stderr=str(e))


class IPTManager:
    def __init__(self):
        self._accounting: set[str] = set()  # IPs with ACCEPT rules
        self._dropped: set[str] = set()  # IPs with DROP rules

    # ── Accounting (byte counting) ─────────────────────────────────────────

    def add_accounting(self, ip: str) -> bool:
        """Append FORWARD ACCEPT rules to count bytes for this IP (idempotent).

        These rules are *appended* (-A), never inserted at the top: cut DROP
        rules are inserted at FORWARD position 1, so appending guarantees a
        DROP always precedes the accounting ACCEPT and a cut cannot be shadowed.
        Byte counting is position-independent, so this does not affect totals.

        Returns True if both rules are present after the call (pre-existing or
        newly added). The IP is tracked for cleanup even on partial failure, so
        any rule that *was* added still gets removed later.
        """
        if not valid_ip(ip):
            return False
        if ip in self._accounting:
            return True
        ok = True
        for flag in ("-s", "-d"):
            chk = _ipt("-C", "FORWARD", flag, ip, "-j", "ACCEPT")
            if chk.returncode != 0:
                r = _ipt("-A", "FORWARD", flag, ip, "-j", "ACCEPT")
                if r.returncode != 0:
                    _log.warning(
                        "iptables -A FORWARD %s %s ACCEPT failed: %s", flag, ip, r.stderr.strip()
                    )
                    ok = False
        self._accounting.add(ip)
        return ok

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

    def add_drop(self, ip: str) -> bool:
        """Insert kernel-level FORWARD DROP rules — device instantly loses
        internet. Returns True if both rules are present after the call."""
        if not valid_ip(ip):
            return False
        ok = True
        for flag in ("-s", "-d"):
            chk = _ipt("-C", "FORWARD", flag, ip, "-j", "DROP")
            if chk.returncode != 0:
                r = _ipt("-I", "FORWARD", "1", flag, ip, "-j", "DROP")
                if r.returncode != 0:
                    _log.warning(
                        "iptables -I FORWARD 1 %s %s DROP failed: %s", flag, ip, r.stderr.strip()
                    )
                    ok = False
        self._dropped.add(ip)
        return ok

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
