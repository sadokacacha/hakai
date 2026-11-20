"""
system/chameleon.py — Traffic Padding & Signature Obfuscation.
Status: [EVASION: ACTIVE]
"""

from __future__ import annotations

import logging
import re
import subprocess

_log = logging.getLogger(__name__)

# Original MTU per interface, captured on engage so disable restores the real
# value instead of assuming 1500.
_ORIG_MTU: dict[str, str] = {}
_MANGLE = ("-t", "mangle")


def _mss_rule(iface: str) -> list[str]:
    return [
        "POSTROUTING",
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-o",
        iface,
        "-j",
        "TCPMSS",
        "--set-mss",
        "1420",
    ]


def _read_mtu(iface: str) -> str:
    try:
        r = subprocess.run(
            ["ip", "-o", "link", "show", "dev", iface], capture_output=True, text=True
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"\bmtu (\d+)", r.stdout)
    return m.group(1) if m else ""


def toggle_chameleon(iface: str, enable: bool) -> str:
    """
    Obfuscates traffic signatures by shifting MTU and MSS values.
    Standard HTTPS/VPN signatures are mimicked to evade IDS detection.
    """
    if not iface:
        return "[ERROR: CHAMELEON_FAIL - no interface]"
    return _engage(iface) if enable else _restore(iface)


def _engage(iface: str) -> str:
    """Apply the MTU shift + MSS clamp (evasion — values unchanged)."""
    try:
        # Capture the original MTU before changing it so _restore can put it back.
        if iface not in _ORIG_MTU:
            cur = _read_mtu(iface)
            if cur:
                _ORIG_MTU[iface] = cur

        # 1. MTU shifting (mimics common VPN/PPPoE overhead)
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "mtu", "1492"], check=True, capture_output=True
        )

        # 2. MSS clamping — idempotent: -C before -A so a repeated engage doesn't
        #    stack duplicate mangle rules that the single -D on restore would miss.
        chk = subprocess.run(
            ["iptables", *_MANGLE, "-C", *_mss_rule(iface)], capture_output=True, text=True
        )
        if chk.returncode != 0:
            subprocess.run(
                ["iptables", *_MANGLE, "-A", *_mss_rule(iface)], check=True, capture_output=True
            )
        return "[EVASION: ACTIVE]"
    except (subprocess.CalledProcessError, OSError) as e:
        _log.warning("chameleon engage failed on %s: %s", iface, e)
        return f"[ERROR: CHAMELEON_FAIL - {e!s}]"


def _restore(iface: str) -> str:
    """Revert MTU to the captured original and remove the MSS clamp.

    Each step is isolated so one failure can't skip the other, and the status is
    truthful instead of always claiming success.
    """
    ok = True

    # Restore the original MTU (or 1500 if we never captured one).
    mtu = _ORIG_MTU.get(iface, "1500")
    try:
        r = subprocess.run(
            ["ip", "link", "set", "dev", iface, "mtu", mtu], capture_output=True, text=True
        )
        if r.returncode != 0:
            _log.warning("chameleon: restore MTU %s on %s failed: %s", mtu, iface, r.stderr.strip())
            ok = False
    except (OSError, subprocess.SubprocessError) as e:
        _log.warning("chameleon: restore MTU error on %s: %s", iface, e)
        ok = False

    # Remove the MSS clamp, retrying to clear any duplicates.
    try:
        for _ in range(3):
            d = subprocess.run(
                ["iptables", *_MANGLE, "-D", *_mss_rule(iface)], capture_output=True, text=True
            )
            if d.returncode != 0:
                break
    except (OSError, subprocess.SubprocessError) as e:
        _log.warning("chameleon: remove MSS clamp error on %s: %s", iface, e)
        ok = False

    _ORIG_MTU.pop(iface, None)
    return "[EVASION: DISABLED]" if ok else "[EVASION: RESTORE INCOMPLETE]"
