"""
core/protector.py — Defensive engine for Hakai.
Protects the attacker from being spoofed or tracked.
"""
import threading
import time
import subprocess
from scapy.all import sniff, ARP, Ether

class Protector:
    def __init__(self, controller):
        self.ctrl = controller
        self.net  = controller.net
        self._running = False
        
        self.arp_guard_enabled = False
        self.kill_switch_enabled = False
        self.gateway_mac = ""
        
        # Reputation Tracking: IP -> { 'arp_count': int, 'macs': set, 'status': str, 'last_reset': float }
        self.reputation: dict[str, dict] = {}
        self._monitor_thread = None
        self._sentry_thread = None

    def start(self):
        if self._running: return
        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True, name="protector_monitor")
        self._monitor_thread.start()
        
        self._sentry_thread = threading.Thread(target=self._self_healing_sentry, daemon=True, name="protector_sentry")
        self._sentry_thread.start()

    def _self_healing_sentry(self):
        """
        Polls /proc/net/arp every 500ms.
        Ensures Gateway is ALWAYS NUD_PERMANENT (0x6).
        """
        while self._running:
            if self.arp_guard_enabled and self.net.gateway:
                try:
                    with open("/proc/net/arp", "r") as f:
                        lines = f.readlines()[1:]
                        for line in lines:
                            parts = line.split()
                            if parts[0] == self.net.gateway:
                                if parts[2] != "0x6":
                                    self.enable_arp_guard()
                                    if hasattr(self.ctrl, "on_protection_alert"):
                                        self.ctrl.on_protection_alert("🛡️ SENTRY: Kernel lock restored!")
                except Exception: pass
            time.sleep(0.5)

    def stop(self):
        self._running = False
        self.disable_arp_guard()
        self.disable_kill_switch()

    # ── ARP Guard ─────────────────────────────────────────────────────────────

    def enable_arp_guard(self, log=None):
        """Lock the gateway MAC in the ARP table."""
        if not self.net.gateway: return False
        
        # Resolve gateway MAC if not known
        if not self.gateway_mac:
            _, gw_mac, _ = self.ctrl.arp._resolve_macs("", self.net.gateway, self.net.iface)
            self.gateway_mac = gw_mac
            
        if not self.gateway_mac:
            if log: log("✕ Failed to resolve gateway MAC for ARP Guard", "err")
            return False

        try:
            # Set permanent neighbor entry
            subprocess.run(["ip", "neigh", "replace", self.net.gateway, 
                            "lladdr", self.gateway_mac, "dev", self.net.iface, "nud", "permanent"],
                           capture_output=True)
            self.arp_guard_enabled = True
            if log: log(f"🛡️ ARP Guard ACTIVE — Gateway {self.net.gateway} locked to {self.gateway_mac}", "ok")
            return True
        except Exception as e:
            if log: log(f"✕ ARP Guard Error: {e}", "err")
            return False

    def disable_arp_guard(self, log=None):
        if not self.arp_guard_enabled: return
        try:
            subprocess.run(["ip", "neigh", "del", self.net.gateway, "dev", self.net.iface], capture_output=True)
            self.arp_guard_enabled = False
            if log: log("🛡️ ARP Guard DISABLED", "info")
        except Exception:
            pass

    # ── Kill-Switch ──────────────────────────────────────────────────────────

    def toggle_kill_switch(self, state: bool, log=None):
        self.kill_switch_enabled = state
        if state:
            if log: log("🚨 Kill-Switch ARMED — Network will drop on hijack detection", "warn")
        else:
            self.disable_kill_switch(log)

    def disable_kill_switch(self, log=None):
        self.kill_switch_enabled = False
        # Remove any block rules
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "DROP"], capture_output=True)
        if log: log("🚨 Kill-Switch DISARMED", "info")

    def _trigger_kill_switch(self):
        """Emergency network shutdown."""
        subprocess.run(["iptables", "-I", "OUTPUT", "1", "-j", "DROP"], capture_output=True)
        self.ctrl.stop() # Stop all operations
        # We don't log here directly to avoid threading issues, the monitor will handle it

    # ── Monitor Loop ─────────────────────────────────────────────────────────

    def _monitor_loop(self):
        def _arp_cb(pkt):
            if not self._running: return
            if not pkt.haslayer(ARP): return

            psrc  = pkt[ARP].psrc
            hwsrc = pkt[ARP].hwsrc.lower()

            now = time.time()
            if psrc not in self.reputation:
                self.reputation[psrc] = {
                    'arp_count': 0, 'macs': {hwsrc},
                    'status': 'CLEAN', 'last_reset': now}

            rep = self.reputation[psrc]
            rep['arp_count'] += 1
            rep['macs'].add(hwsrc)

            if now - rep['last_reset'] > 60:
                rep['arp_count'] = 0
                rep['last_reset'] = now

            if rep['status'] == 'CLEAN':
                if rep['arp_count'] > 30:
                    rep['status'] = 'SUSPICIOUS'
                    self.ctrl.on_protection_alert(
                        f"⚠️ SUSPICIOUS: {psrc} is sending an ARP storm!")

                if len(rep['macs']) > 1:
                    rep['status'] = 'SPOOFER'
                    self.ctrl.on_protection_alert(
                        f"⚠️ DANGER: {psrc} is spoofing (MAC changed to {hwsrc})!")

            if psrc == self.net.gateway:
                if self.gateway_mac and hwsrc != self.gateway_mac.lower():
                    msg = f"⚠️ ARP Conflict: {self.net.gateway} claimed by {hwsrc}"
                    if hasattr(self.ctrl, "on_protection_alert"):
                        self.ctrl.on_protection_alert(msg)

                    if self.arp_guard_enabled:
                        self.enable_arp_guard()
                        self.ctrl.on_protection_alert(
                            "🛡️ SELF-HEALING: Gateway lock re-applied!")

                    if self.kill_switch_enabled:
                        self._trigger_kill_switch()
                        self.ctrl.on_protection_alert(
                            "🚨 KILL-SWITCH TRIGGERED: NETWORK SHUTDOWN")

        # Restart sniff automatically if the interface glitches or raises an exception
        while self._running:
            try:
                sniff(filter="arp", prn=_arp_cb,
                      iface=self.net.iface, store=0, timeout=30)
            except Exception:
                if self._running:
                    time.sleep(2)  # brief cooldown before restart
