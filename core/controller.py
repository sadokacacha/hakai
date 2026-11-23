"""
core/controller.py — Central orchestrator wiring all modules together.
Thread-safe, event-driven, clean start/stop.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
from collections.abc import Callable
from datetime import datetime

from core.device import Device
from core.persistence import (
    _is_junk_hostname,
    classify_device,
    db,
    sanitize_mdns_name,
    sanitize_vendor,
)
from core.protector import Protector
from network.arp import ArpManager
from network.dhcp_sniffer import sniff_dhcp_os
from network.dns_spoof import DnsSpoofManager
from network.fingerprint import fingerprint_device
from network.ipv6 import IPv6Hijacker
from network.mdns_sniff import sniff_mdns_name
from network.oui_lookup import get_vendor
from network.recon_engine import ReconEngine
from network.scanner import Scanner, flush_hostnames, resolve_hostname
from network.traffic import TrafficCounter
from network.xdp_engine import XDPEngine
from system.chameleon import toggle_chameleon

# Legacy imports removed
from system.firewall_apex import GhostFirewall
from system.masquerade import apply_stack_masquerade
from system.netinfo import NetInfo, engage_mitm
from system.nft_filter import NftFilter
from system.stealth import disengage_stealth, engage_mirage_cloak
from system.sweep import sweep_orphans
from system.tc_manager import TCManager

_log = logging.getLogger(__name__)


class Controller:
    def __init__(self, net: NetInfo):
        self.net = net
        self.devices: dict[str, Device] = {}
        self._running = False
        self._stopped = False
        self._lock = threading.Lock()
        self._pending_names_by_mac: dict[str, str] = {}
        self._pending_names_by_ip: dict[str, str] = {}
        self._pending_os_by_mac: dict[str, str] = {}

        # Sub-systems
        self.scanner = Scanner(net.subnet or "192.168.1.0/24")
        self.traffic = TrafficCounter()
        self.arp = ArpManager()
        self.dns = DnsSpoofManager()
        self.ipv6 = IPv6Hijacker(net.iface, net.my_mac)
        self.xdp = XDPEngine(net.iface)
        self.xdp.load()
        self.nft = NftFilter()
        self.tc = TCManager()
        self.protector = Protector(self)
        self.firewall = GhostFirewall()
        self.recon = ReconEngine()

        # Share one nft FORWARD filter across cut (arp) and counters (traffic).
        self.arp.nft = self.nft
        self.traffic.nft = self.nft

        # Optional deauth (wired later if WiFi)
        self.deauth = None

        # Stealth state
        self.stealth_active = False
        self._orig_mac = net.my_mac
        self._orig_hn = socket.gethostname()

        # Protection-alert sink. The protector raises alerts from the sniffer
        # thread; a UI registers a thread-safe callback (e.g. a Qt signal's
        # emit) so the alert actually reaches the operator instead of a no-op.
        self._alert_cb: Callable[[str], None] | None = None

    def start(self):
        """Bootstrap the engine."""
        self._running = True
        # Clear orphaned kernel objects from a prior hard kill and legacy
        # (pre-rename) objects, before engaging anything of our own.
        sweep_orphans()
        # Create the nft FORWARD table/chain fresh (the sweep removed any orphan).
        self.nft.ensure()
        # Reconcile the cut ledger: the sweep removed any kernel drops, so cuts
        # still marked active in the DB are stale (a prior hard kill) — clear them.
        stale = db.active_cuts()
        if stale:
            for ip in stale:
                db.clear_cut(ip)
            db.log_operation("reconcile", detail=f"cleared {len(stale)} stale cut(s) after restart")
            _log.info("cut ledger: cleared %d stale cut(s) from a prior run", len(stale))
        # Apply MITM kernel/NIC tuning here (explicit engage), not as a side
        # effect of network detection. restore_network() reverts it on stop().
        engage_mitm(self.net)
        self.traffic.start(self.net.iface, self.net.my_ip, self.net.my_mac)
        self.scanner.start_passive_discovery(self.net.iface)
        self.protector.start()
        self.save_state()
        if self.net.iface:
            self.tc.init(self.net.iface)
            if self.net.gateway:
                threading.Thread(
                    target=self.arp._resolve_macs,
                    args=("", self.net.gateway, self.net.iface),
                    daemon=True,
                ).start()

        # Start Intel Sniffer (DHCP + mDNS)
        self._start_intel_sniffer()

    def toggle_ipv6_hijack(self, state: bool, log=None):
        if state:
            self.ipv6.start()
            if log:
                log("🔱 IPv6 HIJACK ACTIVE (RA + DHCPv6 Spoof)", "atk")
        else:
            self.ipv6.stop()
            if log:
                log("🔱 IPv6 HIJACK DISABLED", "info")
        return True

    def _start_intel_sniffer(self):
        """Background thread to capture identities via mDNS and DHCP."""

        def _cb(pkt):
            # Unmask OS via DHCP (option 55) + hostname via option 12
            sniff_dhcp_os(pkt, self._on_intel_os_found, self._on_intel_hostname_found)
            # Unmask Name/Class via mDNS
            sniff_mdns_name(pkt, self._on_intel_mdns_found)
            # Stage 1: Passive DNS Correlation
            ip_dns, dns_cls = self.recon.analyze_dns(pkt)
            if ip_dns and dns_cls:
                self._on_intel_dns_found(ip_dns, dns_cls)

            # TTL & TCP Window Fingerprinting (Stage 6)
            if pkt.haslayer(IP):
                ttl = pkt[IP].ttl
                win = pkt[TCP].window if pkt.haslayer(TCP) else 0
                self._on_intel_tcp_found(pkt[IP].src, ttl, win)

        from scapy.all import IP, TCP, sniff

        def _loop():
            while self._running:
                try:
                    sniff(
                        filter="udp and (port 67 or port 68 or port 5353)",
                        prn=_cb,
                        iface=self.net.iface,
                        store=0,
                        timeout=10,
                    )
                except Exception:
                    if self._running:
                        time.sleep(2)

        threading.Thread(target=_loop, daemon=True, name="intel_sniffer").start()

    def _on_intel_os_found(self, mac, os_guess):
        if mac and os_guess:
            self._pending_os_by_mac[mac.lower()] = os_guess
        with self._lock:
            for dev in self.devices.values():
                if dev.mac and dev.mac.lower() == mac.lower():
                    if not dev.os_guess or dev.os_guess in ("Generic Device", ""):
                        dev.os_guess = os_guess
                    dev.vendor = sanitize_vendor(get_vendor(mac) or dev.vendor)
                    # Re-classify so identity column reflects new OS info immediately
                    if not dev.identity or dev.identity in ("Unknown", "?"):
                        dev.identity = classify_device(dev)

    def _on_intel_hostname_found(self, ip, hostname, mac=""):
        """Called when DHCP option 12 yields a self-reported device name."""
        clean = sanitize_mdns_name(hostname) if hostname else ""
        if clean and not _is_junk_hostname(clean):
            if ip:
                self._pending_names_by_ip[ip] = clean
            if mac:
                self._pending_names_by_mac[mac.lower()] = clean

        with self._lock:
            if ip in self.devices:
                dev = self.devices[ip]
                if clean and not _is_junk_hostname(clean):
                    # DHCP hostnames are score-100 — always overwrite
                    if not dev.hostname or _is_junk_hostname(dev.hostname):
                        dev.hostname = clean
                    # Re-classify immediately
                    dev.identity = classify_device(dev)
            elif mac:
                mac_l = mac.lower()
                for dev in self.devices.values():
                    if dev.mac and dev.mac.lower() == mac_l:
                        if clean and (not dev.hostname or _is_junk_hostname(dev.hostname)):
                            dev.hostname = clean
                        dev.identity = classify_device(dev)
                        break

    def _apply_pending_identity(self, dev: Device):
        """Apply DHCP/mDNS data that arrived before the scan knew this device."""
        mac_l = (dev.mac or "").lower()
        pending_name = self._pending_names_by_ip.get(dev.ip) or (
            self._pending_names_by_mac.get(mac_l) if mac_l else ""
        )
        if pending_name and (not dev.hostname or _is_junk_hostname(dev.hostname)):
            dev.hostname = pending_name

        pending_os = self._pending_os_by_mac.get(mac_l) if mac_l else ""
        if pending_os and (not dev.os_guess or dev.os_guess in ("Generic Device", "")):
            dev.os_guess = pending_os

        dev.vendor = sanitize_vendor(dev.vendor)
        dev.identity = classify_device(dev)

    def _on_intel_mdns_found(self, ip, name, os_class):
        with self._lock:
            if ip in self.devices:
                dev = self.devices[ip]
                if name:
                    clean = sanitize_mdns_name(name)
                    if clean and not _is_junk_hostname(clean):
                        if not dev.hostname or _is_junk_hostname(dev.hostname):
                            dev.hostname = clean
                            dev.vendor = sanitize_vendor(get_vendor(dev.mac) or dev.vendor)
                if os_class and (not dev.os_guess or dev.os_guess in ("Generic Device", "")):
                    dev.os_guess = os_class
                # Always re-classify with new data
                dev.identity = classify_device(dev)

    def _on_intel_tcp_found(self, ip, ttl, window):
        """Stage 6: TCP/IP Stack Fingerprinting."""
        with self._lock:
            if ip in self.devices:
                dev = self.devices[ip]
                dev.tcp_ttl = ttl
                dev.tcp_window = window
                # Refine OS guess if generic
                if not dev.os_guess or dev.os_guess == "Generic Device":
                    if ttl >= 120:
                        dev.os_guess = "Windows"
                    elif ttl <= 64:
                        dev.os_guess = "Linux/Mobile"

                # Re-classify with new Stage 6 data
                dev.identity = classify_device(dev)

    def _on_intel_dns_found(self, ip, dns_cls):
        """Stage 1: DNS domain correlation intel."""
        with self._lock:
            if ip in self.devices:
                dev = self.devices[ip]
                # Only add if it adds new info
                if not dev.recon_data.get("dns_class"):
                    dev.recon_data["dns_class"] = dns_cls
                    dev.identity = classify_device(dev)

    def run_deep_recon(self, ip: str):
        """
        Sovereign Discovery Orchestrator (Stealth Mode).
        1. Wait 5s for passive intel (mDNS/DHCP/DNS) to fill in.
        2. If confidence is still low, fire active probes (Stage 3/4/5).
        """

        async def _run():
            # Stealth Grace Period
            await asyncio.sleep(5)

            with self._lock:
                if ip not in self.devices:
                    return
                dev = self.devices[ip]
                # If passive already unmasked it, stay silent
                if dev.confidence >= 60:
                    return

            data = await self.recon.run_recon(ip, self.net.gateway)
            with self._lock:
                if ip in self.devices:
                    dev = self.devices[ip]
                    dev.recon_data.update(data)
                    dev.identity = classify_device(dev)

        # Fire and forget in a separate thread/loop
        threading.Thread(target=lambda: asyncio.run(_run()), daemon=True).start()

    def stop(self):
        """Graceful shutdown — restore all devices, clean up kernel state.

        Idempotent and crash-tolerant: every cleanup step is isolated so a
        failure in one can't skip the rest, and the kernel/NIC restore is
        always attempted last regardless of earlier errors.
        """
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        self._running = False

        # Best-effort, isolated: a raise in one step (e.g. xdp.unload via bcc)
        # must not prevent the others — above all restore_network — from running.
        for name, step in (
            ("arp.restore_all", self.arp.restore_all),
            ("arp.stop_watchdog", self.arp.stop_watchdog),
            ("dns.stop_all", self.dns.stop_all),
            ("xdp.unload", self.xdp.unload),
            ("traffic.stop", self.traffic.stop),
            ("protector.stop", self.protector.stop),
            ("tc.teardown", self.tc.teardown),
            ("nft.cleanup", self.nft.cleanup),
            ("ipv6.stop", self.ipv6.stop),
            ("scanner.stop_passive_discovery", self.scanner.stop_passive_discovery),
            # Evasion subsystems are independently toggleable from the UI, so
            # their restore must run on shutdown too — otherwise a normal window
            # close leaks masquerade sysctls (TTL/timestamps), the chameleon MTU
            # shift + mangle TCPMSS rule, and the ghost-firewall nft drop table.
            # Each restore self-guards (no-op when the feature was never engaged).
            ("masquerade.restore", lambda: apply_stack_masquerade(False)),
            ("chameleon.restore", lambda: toggle_chameleon(self.net.iface, False)),
            ("firewall.stealth_off", lambda: self.firewall.toggle_stealth(False)),
        ):
            try:
                step()
            except Exception:
                _log.exception("cleanup step %s failed", name)

        # Revert kernel/NIC changes (promisc, redirects, rp_filter, proxy_arp…).
        # Always runs; a partial restore is surfaced, not swallowed.
        from system import netinfo

        try:
            if not netinfo.restore_network(self.net):
                _log.warning("restore_network reported a partial restore")
        except Exception:
            _log.exception("restore_network raised")

        # Disengage stealth if active
        if self.stealth_active:
            try:
                disengage_stealth(self.net.iface, self._orig_mac, self._orig_hn)
            except Exception:
                _log.exception("disengage_stealth raised")

    def snapshot_devices(self) -> list[Device]:
        """Thread-safe copy of the current device list for safe iteration.

        Sniffer-thread callbacks mutate self.devices under self._lock, so any
        loop over it must iterate a snapshot, not the live dict — otherwise a
        key added mid-iteration raises "dictionary changed size during iteration".
        """
        with self._lock:
            return list(self.devices.values())

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self, log=None):
        self.scanner.subnet = self.net.subnet or "192.168.1.0/24"
        found = self.scanner.scan(
            iface=self.net.iface,
            timeout_s=db.get("scan_timeout", 45),
            spoof_mac=self.net.my_mac if self.stealth_active else "",
        )

        if self.net.my_ip in found:
            found[self.net.my_ip].hostname = "YOU"
            found[self.net.my_ip].status = "self"
        if self.net.gateway in found:
            gw = found[self.net.gateway]
            if not gw.hostname:
                gw.hostname = "GATEWAY"

        new_ips: list[str] = []  # brand-new IPs we haven't seen before

        with self._lock:
            for ip, dev in found.items():
                if ip in self.devices:
                    existing = self.devices[ip]
                    # Merge scanner data: prefer non-empty values from new scan
                    clean_hostname = sanitize_mdns_name(dev.hostname) if dev.hostname else ""
                    existing.hostname = clean_hostname or existing.hostname
                    existing.os_guess = dev.os_guess or existing.os_guess
                    existing.vendor = sanitize_vendor(
                        get_vendor(dev.mac) or dev.vendor or existing.vendor
                    )
                    existing.mac = dev.mac or existing.mac
                    existing.last_seen = datetime.now().strftime("%H:%M:%S")
                    self._apply_pending_identity(existing)
                    self.traffic.register_device(ip, dev.mac)
                else:
                    if dev.hostname:
                        dev.hostname = sanitize_mdns_name(dev.hostname)
                    dev.last_seen = datetime.now().strftime("%H:%M:%S")
                    dev.vendor = sanitize_vendor(dev.vendor)
                    self._apply_pending_identity(dev)
                    self.devices[ip] = dev
                    self.traffic.register_device(ip, dev.mac)
                    new_ips.append(ip)

            for ip in self.devices:
                self.nft.add_accounting(ip)
            # Persist the current device set (upsert) for cross-restart history.
            for ip, dev in self.devices.items():
                db.save_device(ip, dev.mac, dev.vendor, dev.hostname, dev.identity)

        # Pre-populate identity immediately so the column isn't blank
        with self._lock:
            for dev in self.devices.values():
                if not dev.identity:
                    dev.identity = classify_device(dev)

        # Async hostname resolution for anything still missing
        for dev in self.snapshot_devices():
            if not dev.hostname or dev.hostname in ("-", ""):
                resolve_hostname(dev.ip)

        # Auto-fingerprint & Deep Recon (Stages 2-6)
        for dev in self.snapshot_devices():
            ip = dev.ip
            if ip not in (self.net.my_ip, self.net.gateway):
                if ip in new_ips:
                    self.fingerprint(ip, log=None)
                self.run_deep_recon(ip)

        if log:
            log(f"Scan complete — {len(self.devices)} devices | {len(new_ips)} new", "ok")

        return self.devices

    def flush_hostnames(self):
        with self._lock:
            flush_hostnames(self.devices)
            for dev in self.devices.values():
                # Hostnames can arrive asynchronously from mDNS/LLMNR/PTR after a
                # weak vendor/port label was already shown. Re-score anything
                # below a strong self-reported name so the table improves live.
                if dev.confidence < 90 or dev.identity in ("", "❓ Scanning...", "Unknown", "?"):
                    dev.identity = classify_device(dev)

    # ── Cut / Restore ─────────────────────────────────────────────────────────

    def cut_device(self, ip: str, log=None) -> bool:
        dev = self.devices.get(ip)
        if not dev or not self.net.gateway:
            if log:
                log(f"Cannot cut {ip} — no gateway", "err")
            return False

        if dev.status == "self" or ip == self.net.gateway:
            if log:
                log(f"✕ Safeguard: Cannot cut {ip} (Self/Gateway)", "warn")
            return False

        dev.cut = True
        dev.status = "cut"
        # Zero speed display immediately — don't wait for the 3-s window to drain
        self.traffic.mark_cut(ip)

        def _do():
            ok = self.arp.cut(ip, self.net.gateway, self.net.iface, self.net.my_ip)
            if not ok:
                # The cut failed — revert the optimistic state so the row doesn't
                # lie (🔒 CUT / BLOCKED) about a device that still has connectivity.
                dev.cut = False
                dev.status = "online"
                self.traffic.unmark_cut(ip)
                if log:
                    log(f"✕ {ip} — ARP resolution failed (target not reachable)", "err")
                return
            self.xdp.add_drop(ip)
            # WiFi deauth (if applicable)
            with self._lock:
                t_info = self.arp._cut_ips.get(ip, {})
            t_mac = t_info.get("target_mac", "")
            if self.deauth and t_mac:
                self.deauth.start_pmf_bypass(t_mac)
            db.record_cut(ip)
            db.log_operation("cut", ip)
            if log:
                log(f"🔒 {ip} LOCKED — XDP + ARP flood active", "atk")

        threading.Thread(target=_do, daemon=True, name=f"cut_{ip}").start()
        return True

    def monitor_device(self, ip: str, log=None):
        dev = self.devices.get(ip)
        if not dev or not self.net.gateway:
            return False
        if dev.status == "self" or ip == self.net.gateway:
            return False
        threading.Thread(
            target=self.arp.spoof,
            args=(ip, self.net.gateway, self.net.iface, self.net.my_ip),
            daemon=True,
        ).start()
        if log:
            log(f"👁 Monitoring {ip}...", "info")
        return True

    def restore_device(self, ip: str, log=None):
        dev = self.devices.get(ip)
        if not dev:
            return
        self.arp.restore(ip)
        self.dns.stop_spoof(ip)
        self.xdp.remove_drop(ip)
        if dev.limited:
            self.tc.unlimit(ip)
        dev.cut = False
        dev.limited = False
        dev.status = "online"
        self.traffic.unmark_cut(ip)
        db.clear_cut(ip)
        db.log_operation("restore", ip)
        if log:
            log(f"↺ {ip} restored", "ok")

    def cut_all(self, log=None):
        for ip, dev in list(self.devices.items()):
            if dev.status not in ("self", "cut") and ip != self.net.gateway:
                self.cut_device(ip, log)

    def restore_all(self, log=None):
        for ip, dev in list(self.devices.items()):
            if dev.cut or dev.limited:
                self.restore_device(ip, log)

    # ── Bandwidth shaping ─────────────────────────────────────────────────────

    def limit_device(self, ip: str, kb: int, log=None) -> bool:
        dev = self.devices.get(ip)
        if not dev:
            return False

        if dev.status == "self" or ip == self.net.gateway:
            if log:
                log(f"✕ Safeguard: Cannot limit {ip} (Self/Gateway)", "warn")
            return False

        ok = self.tc.limit(ip, kb)
        # Only mark the device limited when tc actually applied the shaping, so
        # the row doesn't render ⚡{kb}KB for a limit that never took effect.
        if ok:
            dev.limit_kb = kb
            dev.limited = True
            db.log_operation("limit", ip, f"{kb}KB")
        if log:
            log(f"⚡ {ip} → {kb} KB/s", "warn" if ok else "err")
        return ok

    def unlimit_device(self, ip: str, log=None):
        dev = self.devices.get(ip)
        if not dev:
            return
        self.tc.unlimit(ip)
        dev.limited = False
        if log:
            log(f"↺ {ip} limit removed", "ok")

    # ── Fingerprinting ────────────────────────────────────────────────────────

    def fingerprint(self, ip: str, done_cb=None, log=None):
        def cb(ports, os_guess, services):
            dev = self.devices.get(ip)
            if dev:
                dev.open_ports = ports
                dev.services = services or {}
                # Only overwrite if we got something more specific
                if os_guess and os_guess != "Generic Device":
                    dev.os_guess = os_guess
                dev.identity = classify_device(dev)
                if log:
                    log(f"[FP] {ip} -> {dev.identity}  OS:{dev.os_guess or '?'}", "ok")
            if done_cb:
                done_cb(ip, dev)

        fingerprint_device(ip, cb)

    # ── DNS Spoofing ──────────────────────────────────────────────────────────

    def toggle_dns_spoof(self, ip: str, state: bool, log=None):
        dev = self.devices.get(ip)
        if not dev:
            return False
        if ip == self.net.gateway or dev.status == "self":
            if log:
                log(f"✕ Safeguard: refusing DNS redirect on {ip} (Self/Gateway)", "warn")
            return False
        if state:
            ok = self.dns.start_spoof(ip)
            if log:
                log(
                    f"🌐 DNS redirect engaged for {ip}"
                    if ok
                    else f"✕ DNS redirect failed for {ip}",
                    "atk" if ok else "err",
                )
            return ok
        self.dns.stop_spoof(ip)
        if log:
            log(f"↺ DNS redirect stopped for {ip}", "info")
        return True

    # ── State persistence ─────────────────────────────────────────────────────

    def save_state(self, iface="", gateway="", log=None):
        # Persists iface/gateway to config.json. Device-state (state.json) was
        # write-only — nothing ever read it back — so that write was removed
        # (P7 #24); only the live config persistence remains.
        db.save_config(iface=iface or self.net.iface, gateway=gateway or self.net.gateway)
        if log:
            log("💾 State saved.", "ok")

    # ── Stealth Mode ──────────────────────────────────────────────────────────

    def toggle_stealth(self, state: bool, profile: str = "RANDOM", log=None):
        if state == self.stealth_active:
            return True
        if state:
            msg, new_mac = engage_mirage_cloak(self.net.iface, profile)
            if new_mac:
                self.net.my_mac = new_mac
                self.stealth_active = True
                if log:
                    log(msg, "atk")
        else:
            msg = disengage_stealth(self.net.iface, self._orig_mac, self._orig_hn)
            self.net.my_mac = self._orig_mac
            self.stealth_active = False
            if log:
                log(msg, "info")
        return True

    def _restart_services(self, log=None):
        try:
            self.traffic.stop()
            self.protector.stop()
            time.sleep(1)
            self.traffic.start(self.net.iface, self.net.my_ip, self.net.my_mac)
            self.protector.start()
        except Exception:
            pass

    def set_alert_callback(self, cb: Callable[[str], None] | None) -> None:
        """Register a sink for protection alerts. Called from the sniffer thread,
        so ``cb`` must be thread-safe — the Qt UI passes a signal's ``emit``,
        which marshals to the GUI thread."""
        self._alert_cb = cb

    def on_protection_alert(self, msg: str) -> None:
        """Surface a defensive alert (ARP storm, spoofer, kill-switch trip, …).

        Was a silent no-op, so every alert the protector raised vanished. Now it
        is logged and forwarded to the registered UI sink (if any). It does NOT
        persist to the DB: alerts can fire per-packet during an active spoof, so
        a write here would be unbounded — the log + live UI are the surfaces.
        """
        _log.warning("protection alert: %s", msg)
        cb = self._alert_cb
        if cb is not None:
            try:
                cb(msg)
            except Exception:
                _log.exception("protection-alert callback failed")

    # ── Sovereign Apex Modules ────────────────────────────────────────────────

    def toggle_ghost_firewall(self, state: bool, log=None) -> str:
        status = self.firewall.toggle_stealth(state)
        if log:
            log(f"🛡️ Ghost Firewall: {status}", "warn" if state else "info")
        return status

    def toggle_stack_masquerade(self, state: bool, log=None) -> str:
        status = apply_stack_masquerade(state)
        if log:
            log(f"🎭 Stack Masquerade: {status}", "warn" if state else "info")
        return status

    def toggle_chameleon(self, state: bool, log=None) -> str:
        status = toggle_chameleon(self.net.iface, state)
        if log:
            log(f"🧬 Chameleon Engine: {status}", "warn" if state else "info")
        return status

    # ── Usage / Speeds ────────────────────────────────────────────────────────

    def toggle_nuclear_stealth(self, state: bool, log=None) -> str:
        """
        Orchestrates Total Invisibility: Mirage + Masquerade + Shield.
        """
        if state:
            # 1. Engage Mirage Cloak (Random Identity)
            msg, new_mac = engage_mirage_cloak(self.net.iface)
            # Guard like toggle_stealth: a failed cloak returns an empty MAC;
            # assigning it would corrupt self.net.my_mac (later .lower()'d in the
            # traffic counter) and silently break self-traffic filtering.
            if new_mac:
                self.net.my_mac = new_mac
            self.stealth_active = True

            # 2. Stack Masquerade (Windows TTL)
            apply_stack_masquerade(True)

            # 3. Shield Lock (ARP)
            self.protector.enable_arp_guard(log=log)

            if log:
                log("☢️ NUCLEAR GHOST ENGAGED: TOTAL INVISIBILITY", "atk")
            return msg
        else:
            # Revert to Normal
            msg = disengage_stealth(self.net.iface, self._orig_mac, self._orig_hn)
            self.net.my_mac = self._orig_mac
            self.stealth_active = False

            # Revert Stack
            apply_stack_masquerade(False)

            # Revert Shields
            self.protector.disable_arp_guard(log=log)

            if log:
                log("☢️ SHIELDS DISENGAGED: IDENTITY RESTORED", "info")
            return msg

    def update_device_speeds(self):
        for dev in self.snapshot_devices():
            rx_s, tx_s, rx_t, tx_t = self.traffic.get(dev.ip)
            dev.rx_speed = rx_s
            dev.tx_speed = tx_s
            dev.rx_total = rx_t
            dev.tx_total = tx_t
            dev.update_history(rx_s, tx_s)
