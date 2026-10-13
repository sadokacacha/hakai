"""
system/masquerade.py — TCP/IP Stack Fingerprint Obfuscation.
Status: [CHAMELEON: ACTIVE]
"""
from __future__ import annotations

import subprocess

_KEYS = ("net.ipv4.ip_default_ttl", "net.ipv4.tcp_window_scaling", "net.ipv4.tcp_timestamps")
# Captured host values, saved the first time masquerade is enabled so disable
# can restore the real originals instead of hardcoded guesses.
_ORIG: dict[str, str] = {}


def apply_stack_masquerade(enable: bool) -> str:
    """
    Mimics a Windows 11 TCP/IP fingerprint (TTL 128, timestamps off) while
    enabled, and restores the host's captured original values on disable.
    """
    try:
        if enable:
            for key in _KEYS:
                if key not in _ORIG:
                    r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True)
                    _ORIG[key] = r.stdout.strip()
            settings = {
                "net.ipv4.ip_default_ttl": "128",
                "net.ipv4.tcp_window_scaling": "1",
                "net.ipv4.tcp_timestamps": "0",  # Windows often hides timestamps
            }
        else:
            # Restore only values we actually captured.
            settings = {k: _ORIG[k] for k in _KEYS if _ORIG.get(k)}

        for key, value in settings.items():
            subprocess.run(["sysctl", "-w", f"{key}={value}"], check=True, capture_output=True)

        return "[DNA_MATCH: 99% (Windows 11 Mimic)]" if enable else "[DNA: NATIVE]"
    except Exception as e:
        return f"[ERROR: STACK_SPOOF_FAIL - {e!s}]"
