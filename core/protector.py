"""
core/protector.py — Defensive engine for Hakai.
Protects the attacker from being spoofed or tracked.
"""

import logging
import subprocess
import threading
import time

from scapy.all import ARP, sniff

from core.netutil import valid_ip
from core.osutil import IS_WINDOWS as _IS_WINDOWS

_log = logging.getLogger(__name__)


class Protector:
    def __init__(self, controller):
        self.ctrl = controller
        self.net = controller.net
        self._running = False

        self.arp_guard_enabled = False
        self.kill_switch_enabled = False
        self._killswitch_tripped = False  # True once the DROP is in place (idempotency)
        self.gateway_mac = ""

        # Reputation Tracking: IP -> { 'arp_count': int, 'macs': set, 'status': str, 'last_reset': float }
        self.reputation: dict[str, dict] = {}
        self._monitor_thread = None
        self._sentry_thread = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="protector_monitor"
        )
        self._monitor_thread.start()

        self._sentry_thread = threading.Thread(
            target=self._self_healing_sentry, daemon=True, name="protector_sentry"
        )
        self._sentry_thread.start()

    def _gateway_is_unlocked(self, arp_text: str) -> bool:
        """True if the gateway appears in /proc/net/arp but is NOT permanent
        (Flags != 0x6), i.e. the kernel lock must be re-applied.

        Short/blank lines are skipped, not treated as fatal — the old code
        indexed parts[0]/parts[2] unconditionally, so one malformed line raised
        IndexError and aborted the whole scan cycle.
        """
        gw = self.net.gateway
        if not gw:
            return False
        for line in arp_text.splitlines()[1:]:  # skip the header row
            parts = line.split()
            if len(parts) < 3:
                continue
            if parts[0] == gw:
                return parts[2] != "0x6"
        return False

    def _self_healing_sentry(self):
        """
        Polls /proc/net/arp every 500ms (Linux only).
        Ensures the gateway stays NUD_PERMANENT (Flags 0x6).
        """
        if _IS_WINDOWS:
            return  # /proc/net/arp not available on Windows
        while self._running:
            if self.arp_guard_enabled and self.net.gateway:
                try:
                    with open("/proc/net/arp") as f:
                        text = f.read()
                except OSError as e:
                    _log.debug("sentry: cannot read /proc/net/arp: %s", e)
                    text = ""
                if text and self._gateway_is_unlocked(text):
                    self.enable_arp_guard()
                    if hasattr(self.ctrl, "on_protection_alert"):
                        self.ctrl.on_protection_alert("🛡️ SENTRY: Kernel lock restored!")
            time.sleep(0.5)

    def stop(self):
        self._running = False
        self.disable_arp_guard()
        self.disable_kill_switch()

    # ── ARP Guard ─────────────────────────────────────────────────────────────

    def enable_arp_guard(self, log=None):
        """Lock the gateway MAC in the ARP table."""
        if not self.net.gateway:
            return False
        if not valid_ip(self.net.gateway):
            if log:
                log("✕ ARP Guard: invalid gateway address", "err")
            return False

        # Resolve gateway MAC if not known
        if not self.gateway_mac:
            _, gw_mac, _ = self.ctrl.arp._resolve_macs("", self.net.gateway, self.net.iface)
            self.gateway_mac = gw_mac

        if not self.gateway_mac:
            if log:
                log("✕ Failed to resolve gateway MAC for ARP Guard", "err")
            return False

        if _IS_WINDOWS:
            if log:
                log("🛡️ ARP Guard not supported on Windows", "info")
            return False
        # Set permanent neighbor entry, and verify it actually applied instead
        # of reporting a false "ACTIVE".
        try:
            r = subprocess.run(
                [
                    "ip",
                    "neigh",
                    "replace",
                    self.net.gateway,
                    "lladdr",
                    self.gateway_mac,
                    "dev",
                    self.net.iface,
                    "nud",
                    "permanent",
                ],
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as e:
            if log:
                log(f"✕ ARP Guard Error: {e}", "err")
            return False
        if r.returncode != 0:
            _log.warning("ARP guard: ip neigh replace failed: %s", r.stderr.strip())
            if log:
                log("✕ ARP Guard failed to apply kernel lock", "err")
            return False
        self.arp_guard_enabled = True
        if log:
            log(
                f"🛡️ ARP Guard ACTIVE — Gateway {self.net.gateway} locked to {self.gateway_mac}",
                "ok",
            )
        return True

    def disable_arp_guard(self, log=None):
        if not self.arp_guard_enabled:
            return
        if _IS_WINDOWS:
            self.arp_guard_enabled = False
            return
        try:
            subprocess.run(
                ["ip", "neigh", "del", self.net.gateway, "dev", self.net.iface], capture_output=True
            )
            self.arp_guard_enabled = False
            if log:
                log("🛡️ ARP Guard DISABLED", "info")
        except Exception:
            pass

    # ── Kill-Switch ──────────────────────────────────────────────────────────

    def toggle_kill_switch(self, state: bool, log=None):
        self.kill_switch_enabled = state
        if state:
            if log:
                log("🚨 Kill-Switch ARMED — Network will drop on hijack detection", "warn")
        else:
            self.disable_kill_switch(log)

    def disable_kill_switch(self, log=None):
        self.kill_switch_enabled = False
        self._killswitch_tripped = False
        if not _IS_WINDOWS:
            # Remove every copy of our own marked rule (Linux only); repeated
            # triggers can insert duplicates, so delete until none remain.
            for _ in range(10):
                r = subprocess.run(
                    [
                        "iptables",
                        "-D",
                        "OUTPUT",
                        "-m",
                        "comment",
                        "--comment",
                        "hakai_killswitch",
                        "-j",
                        "DROP",
                    ],
                    capture_output=True,
                )
                if r.returncode != 0:
                    break
        if log:
            log("🚨 Kill-Switch DISARMED", "info")

    def _trigger_kill_switch(self) -> bool:
        """Emergency defensive shutdown: drop our own outbound traffic and KEEP
        it dropped until the operator disarms (toggle off → disable_kill_switch).

        Returns True only on the transition into the tripped state, so the sentry
        (which calls this on every spoofed ARP packet) inserts the DROP exactly
        once and alerts once. Previously this also called self.ctrl.stop(), whose
        teardown runs disable_kill_switch() and removed the very DROP just
        inserted — so a detected hijack stopped everything but did NOT cut the
        network, the opposite of the armed promise (P7 #23).
        """
        if self._killswitch_tripped:
            return False
        self._killswitch_tripped = True
        if not _IS_WINDOWS:
            # Marked so disable_kill_switch removes exactly our rule(s).
            subprocess.run(
                [
                    "iptables",
                    "-I",
                    "OUTPUT",
                    "1",
                    "-m",
                    "comment",
                    "--comment",
                    "hakai_killswitch",
                    "-j",
                    "DROP",
                ],
                capture_output=True,
            )
        return True

    # ── Monitor Loop ─────────────────────────────────────────────────────────

    def _monitor_loop(self):
        def _arp_cb(pkt):
            if not self._running:
                return
            if not pkt.haslayer(ARP):
                return

            psrc = pkt[ARP].psrc
            hwsrc = pkt[ARP].hwsrc.lower()

            now = time.time()
            if psrc not in self.reputation:
                self.reputation[psrc] = {
                    "arp_count": 0,
                    "macs": {hwsrc},
                    "status": "CLEAN",
                    "last_reset": now,
                }

            rep = self.reputation[psrc]
            rep["arp_count"] += 1
            rep["macs"].add(hwsrc)

            if now - rep["last_reset"] > 60:
                rep["arp_count"] = 0
                rep["last_reset"] = now

            if rep["status"] == "CLEAN":
                if rep["arp_count"] > 30:
                    rep["status"] = "SUSPICIOUS"
                    self.ctrl.on_protection_alert(f"⚠️ SUSPICIOUS: {psrc} is sending an ARP storm!")

                if len(rep["macs"]) > 1:
                    rep["status"] = "SPOOFER"
                    self.ctrl.on_protection_alert(
                        f"⚠️ DANGER: {psrc} is spoofing (MAC changed to {hwsrc})!"
                    )

            if psrc == self.net.gateway:
                if self.gateway_mac and hwsrc != self.gateway_mac.lower():
                    msg = f"⚠️ ARP Conflict: {self.net.gateway} claimed by {hwsrc}"
                    if hasattr(self.ctrl, "on_protection_alert"):
                        self.ctrl.on_protection_alert(msg)

                    if self.arp_guard_enabled:
                        self.enable_arp_guard()
                        self.ctrl.on_protection_alert("🛡️ SELF-HEALING: Gateway lock re-applied!")

                    if self.kill_switch_enabled and self._trigger_kill_switch():
                        self.ctrl.on_protection_alert(
                            "🚨 KILL-SWITCH TRIGGERED: outbound traffic dropped until disarm"
                        )

        # Restart sniff automatically if the interface glitches or raises an exception
        while self._running:
            try:
                sniff(filter="arp", prn=_arp_cb, iface=self.net.iface, store=0, timeout=30)
            except Exception:
                if self._running:
                    time.sleep(2)  # brief cooldown before restart
