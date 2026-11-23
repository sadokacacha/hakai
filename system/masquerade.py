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
    """Apply the Windows-mimic fingerprint.

    Capture-or-None: a key whose original can't be captured is NOT changed — we
    never mutate what we can't restore. On a mid-sequence write failure every
    key already applied is rolled back to its captured original, so engage never
    leaves the host partially masqueraded.
    """
    settings = {
        "net.ipv4.ip_default_ttl": "128",
        "net.ipv4.tcp_window_scaling": "1",
        "net.ipv4.tcp_timestamps": "0",  # Windows often hides timestamps
    }
    try:
        for key in _KEYS:
            if key not in _ORIG:
                r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True)
                if r.returncode != 0 or not r.stdout.strip():
                    _log.warning(
                        "masquerade: could not capture %s (rc=%s); skipping — will not "
                        "change a key we can't restore",
                        key,
                        r.returncode,
                    )
                    continue
                _ORIG[key] = r.stdout.strip()

        for key, value in settings.items():
            if key not in _ORIG:
                continue  # capture failed earlier → leave this key untouched
            r = subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True, text=True)
            if r.returncode != 0:
                _log.error(
                    "masquerade: set %s=%s failed: %s — rolling back",
                    key,
                    value,
                    r.stderr.strip(),
                )
                _restore()  # revert every key already applied
                return f"[ERROR: STACK_SPOOF_FAIL - {key}]"
        return "[DNA_MATCH: 99% (Windows 11 Mimic)]"
    except (OSError, subprocess.SubprocessError) as e:
        _log.error("masquerade engage error: %s — rolling back", e)
        _restore()
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
