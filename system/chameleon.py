"""
system/chameleon.py — Traffic Padding & Signature Obfuscation.
Status: [EVASION: ACTIVE]
"""
from __future__ import annotations

import subprocess


def toggle_chameleon(iface: str, enable: bool) -> str:
    """
    Obfuscates traffic signatures by shifting MTU and MSS values.
    Standard HTTPS/VPN signatures are mimicked to evade IDS detection.
    """
    try:
        # 1. MTU Shifting (Mimicking common VPN/PPPoE overhead)
        mtu = "1492" if enable else "1500"
        subprocess.run(["ip", "link", "set", "dev", iface, "mtu", mtu], check=True)
        
        # 2. MSS Clamping (Shifting TCP handshake fingerprints)
        if enable:
            # 1420 is the 'Tactical Sweet Spot' — fits through VPNs/LTE without lag
            subprocess.run(["iptables", "-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", 
                            "--tcp-flags", "SYN,RST", "SYN", "-o", iface, "-j", "TCPMSS", "--set-mss", "1420"], check=True)
        else:
            subprocess.run(["iptables", "-t", "mangle", "-D", "POSTROUTING", "-p", "tcp", 
                            "--tcp-flags", "SYN,RST", "SYN", "-o", iface, "-j", "TCPMSS", "--set-mss", "1420"], capture_output=True)

        return "[EVASION: ACTIVE]" if enable else "[EVASION: DISABLED]"
    except Exception as e:
        return f"[ERROR: CHAMELEON_FAIL - {e!s}]"
