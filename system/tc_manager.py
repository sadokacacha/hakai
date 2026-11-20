"""
system/tc_manager.py — Per-IP bandwidth shaping via HTB (Hierarchical Token Bucket).

Why HTB over the old TBF approach:
  • TBF applies one queue to the WHOLE interface — one limit for all.
  • HTB gives each IP its own leaf class (1:10, 1:11, …) under a shared
    root class, so limits are truly per-device and can be changed live.

Interface is auto-detected at init() time — no hardcoded 'eth0'.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import threading

from core.netutil import valid_ip

_IS_WINDOWS = sys.platform == "win32"
_log = logging.getLogger(__name__)


def _tc(iface: str, *args, capture=True):
    """Run tc command. No-op on Windows."""
    if _IS_WINDOWS:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    tc_bin = shutil.which("tc") or "/usr/sbin/tc"
    if len(args) < 2:
        return subprocess.run([tc_bin, *args, "dev", iface], capture_output=capture, text=True)

    # Standard tc syntax: tc <subcmd> <action> dev <iface> <params>
    # e.g. tc qdisc add dev eth0 ...
    cmd = [tc_bin, args[0], args[1], "dev", iface] + list(args[2:])
    return subprocess.run(cmd, capture_output=capture, text=True)


class TCManager:
    _HANDLE = "1:"
    _ROOT = "1:1"

    def __init__(self):
        self._iface = ""
        self._lock = threading.Lock()
        self._active = False
        self._classes: dict[str, int] = {}  # ip → class id int
        self._next_id = 10
        self._tc = shutil.which("tc") or "/usr/sbin/tc"
        self.last_error = ""

    def init(self, iface: str) -> bool:
        """Set up HTB root qdisc on iface. Always tears down first for a clean slate."""
        self._iface = iface

        if _IS_WINDOWS:
            # tc (Traffic Control) is Linux-only; on Windows bandwidth limiting is unavailable
            self._active = True  # mark active so the manager doesn't crash
            return True

        # 1. Tear down anything that may exist
        _tc(iface, "qdisc", "del", "root", capture=True)

        # 2. Add root qdisc
        r = _tc(iface, "qdisc", "add", "root", "handle", "1:", "htb", "default", "1")
        if r.returncode != 0:
            self.last_error = r.stderr.strip()
            _log.error("TC init error: %s", self.last_error)
            return False

        # 3. Root class — effectively unlimited (1000 Mbit ceiling)
        r = _tc(iface, "class", "add", "parent", "1:", "classid", "1:1", "htb", "rate", "1000mbit")
        if r.returncode != 0:
            self.last_error = r.stderr.strip()
            _log.error("TC class error: %s", self.last_error)
            return False

        self._active = True
        self._classes = {}
        self._next_id = 10
        return True

    # ── Internal helpers ──────────────────────────────────────────────────

    def _class_id(self, ip: str) -> int:
        if ip not in self._classes:
            self._classes[ip] = self._next_id
            self._next_id += 1
        return self._classes[ip]

    @staticmethod
    def _burst(kbit: int) -> str:
        """burst = rate_bytes / 10  → 100 ms of data. Minimum 1600 B (one MTU)."""
        bps = (kbit * 1000) // 8
        burst = max(bps // 10, 1600)
        return str(burst)

    # ── Public API ────────────────────────────────────────────────────────

    def limit(self, ip: str, kb: int) -> bool:
        """Limit download+upload speed for ip to kb KB/s using HTB.

        Returns True only if the HTB class and both u32 filters actually applied,
        instead of always claiming success — a failed `tc` must not report a limit
        the kernel never installed.
        """
        if not self._active:
            return False
        if not valid_ip(ip):
            _log.warning("tc: refusing to limit invalid IP %r", ip)
            return False
        with self._lock:
            cid = self._class_id(ip)
            kbit = kb * 8  # KB/s → kbit/s
            burst = self._burst(kbit)
            # Each device gets its OWN priority (cid) so filters never collide.
            # prio 1 was shared across all devices — that was the bug.
            prio_dst = cid * 2  # even  → dst (download)
            prio_src = cid * 2 + 1  # odd   → src (upload)

            # Remove stale filters for this IP (absence is fine — ignore rc)
            _tc(
                self._iface,
                "filter",
                "del",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                str(prio_dst),
            )
            _tc(
                self._iface,
                "filter",
                "del",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                str(prio_src),
            )

            # Add or change the HTB leaf class
            class_ok = False
            r: subprocess.CompletedProcess | None = None
            for action in ("add", "change"):
                r = _tc(
                    self._iface,
                    "class",
                    action,
                    "parent",
                    "1:1",
                    "classid",
                    f"1:{cid}",
                    "htb",
                    "rate",
                    f"{kbit}kbit",
                    "ceil",
                    f"{kbit}kbit",
                    "burst",
                    burst,
                    "cburst",
                    burst,
                )
                if r.returncode == 0:
                    class_ok = True
                    break
            if not class_ok:
                self.last_error = (r.stderr or "").strip() if r else ""
                _log.error("tc: class add/change failed for %s: %s", ip, self.last_error)
                self._classes.pop(ip, None)  # don't leave a phantom class id
                return False

            # Attach fq_codel to the leaf class — prevents bufferbloat (best-effort)
            _tc(
                self._iface,
                "qdisc",
                "replace",
                "parent",
                f"1:{cid}",
                "handle",
                f"{cid}:",
                "fq_codel",
            )

            # u32 filter: destination IP → throttle downloads
            rf_dst = _tc(
                self._iface,
                "filter",
                "add",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                str(prio_dst),
                "u32",
                "match",
                "ip",
                "dst",
                ip,
                "255.255.255.255",
                "flowid",
                f"1:{cid}",
            )

            # u32 filter: source IP → throttle uploads
            rf_src = _tc(
                self._iface,
                "filter",
                "add",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                str(prio_src),
                "u32",
                "match",
                "ip",
                "src",
                ip,
                "255.255.255.255",
                "flowid",
                f"1:{cid}",
            )

            if rf_dst.returncode != 0 or rf_src.returncode != 0:
                self.last_error = (rf_dst.stderr or rf_src.stderr or "").strip()
                _log.error("tc: filter add failed for %s: %s", ip, self.last_error)
                # The class exists; keep the id so unlimit()/teardown() removes it.
                return False
            return True

    def unlimit(self, ip: str):
        """Remove the HTB class and both filters for ip."""
        if not self._active:
            return
        with self._lock:
            cid = self._classes.pop(ip, None)
            if cid is None:
                return
            prio_dst = cid * 2
            prio_src = cid * 2 + 1
            _tc(
                self._iface,
                "filter",
                "del",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                str(prio_dst),
            )
            _tc(
                self._iface,
                "filter",
                "del",
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                str(prio_src),
            )
            _tc(self._iface, "class", "del", "parent", "1:1", "classid", f"1:{cid}")

    def teardown(self):
        """Remove the entire HTB qdisc — clean exit."""
        with self._lock:
            if self._iface:
                _tc(self._iface, "qdisc", "del", "root")
            self._active = False
            self._classes = {}
            self._next_id = 10
