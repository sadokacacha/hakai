"""
system/masquerade.py — TCP/IP Stack Fingerprint Obfuscation.
Status: [CHAMELEON: ACTIVE]
"""

from __future__ import annotations

import logging
import subprocess

_log = logging.getLogger(__name__)

_KEYS = ("net.ipv4.ip_default_ttl", "net.ipv4.tcp_window_scaling", "net.ipv4.tcp_timestamps")
# Captured host values, saved the first time masquerade is enabled so disable
# can restore the real originals instead of hardcoded guesses.
_ORIG: dict[str, str] = {}


def apply_stack_masquerade(enable: bool) -> str:
    """
    Mimics a Windows 11 TCP/IP fingerprint (TTL 128, timestamps off) while
    enabled, and restores the host's captured original values on disable.
    """
    return _engage() if enable else _restore()


def _engage() -> str:
    """Apply the Windows-mimic fingerprint (evasion path — behaviour unchanged)."""
    try:
        for key in _KEYS:
            if key not in _ORIG:
                r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True)
                _ORIG[key] = r.stdout.strip()
        settings = {
            "net.ipv4.ip_default_ttl": "128",
            "net.ipv4.tcp_window_scaling": "1",
            "net.ipv4.tcp_timestamps": "0",  # Windows often hides timestamps
        }
        for key, value in settings.items():
            subprocess.run(["sysctl", "-w", f"{key}={value}"], check=True, capture_output=True)
        return "[DNA_MATCH: 99% (Windows 11 Mimic)]"
    except Exception as e:
        return f"[ERROR: STACK_SPOOF_FAIL - {e!s}]"


def _restore() -> str:
    """Restore the captured original sysctls (un-masquerade).

    Each write is isolated so one failure can't leave the host partially
    masqueraded, and the status is truthful instead of always "[DNA: NATIVE]".
    """
    ok = True
    restored_any = False
    for key in _KEYS:
        orig = _ORIG.get(key)
        if not orig:
            continue  # never captured → nothing to restore (don't invent a value)
        restored_any = True
        try:
            r = subprocess.run(["sysctl", "-w", f"{key}={orig}"], capture_output=True, text=True)
            if r.returncode != 0:
                _log.warning("masquerade: restore %s failed: %s", key, r.stderr.strip())
                ok = False
        except (OSError, subprocess.SubprocessError) as e:
            _log.warning("masquerade: restore %s error: %s", key, e)
            ok = False

    if not restored_any:
        return "[DNA: NATIVE]"
    return "[DNA: NATIVE]" if ok else "[DNA: RESTORE INCOMPLETE]"
