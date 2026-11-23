"""
system/stealth.py — The Sovereign Mirage Engine.
Randomizes host identity across mobile, PC, and TV profiles.
"""

import logging
import random
import subprocess
import time

from system.firewall_apex import GhostFirewall

_log = logging.getLogger(__name__)

PROFILES = [
    {"name": "iPhone-15-Pro", "oui": "40:a6:d9", "type": "MOBILE"},
    {"name": "Galaxy-S24-Ultra", "oui": "dc:e5:78", "type": "MOBILE"},
    {"name": "Pixel-8-Pro", "oui": "1c:62:b8", "type": "MOBILE"},
    {"name": "MacBook-Pro-M3", "oui": "c8:6f:1d", "type": "PC"},
    {"name": "Surface-Laptop-5", "oui": "00:50:f2", "type": "PC"},
    {"name": "Dell-XPS-Highline", "oui": "d4:3d:7e", "type": "PC"},
    {"name": "Sony-Bravia-4K", "oui": "00:22:fb", "type": "TV"},
    {"name": "LG-OLED-WebOS", "oui": "60:c5:47", "type": "TV"},
    {"name": "Samsung-Smart-TV", "oui": "40:16:3b", "type": "TV"},
]


def _run(args: list[str]) -> bool:
    """Run a command, capturing output; log and return False on any failure
    instead of leaking stderr to the console or swallowing it silently."""
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        _log.warning("stealth: %s error: %s", " ".join(args), e)
        return False
    if r.returncode != 0:
        _log.warning("stealth: %s failed: %s", " ".join(args), r.stderr.strip())
        return False
    return True


def _current_ssid() -> str | None:
    """Read the currently-connected Wi-Fi SSID for an instant re-bind after a MAC
    change. Returns None (logged) on any read failure — never raises."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], capture_output=True, text=True
        )
    except (OSError, subprocess.SubprocessError) as e:
        _log.debug("stealth: could not read current SSID: %s", e)
        return None
    for line in r.stdout.splitlines():
        if line.startswith("yes") and ":" in line:
            return line.split(":", 1)[1]
    return None


def _change_mac(interface: str, new_mac: str, ssid: str | None) -> bool:
    """Bring the link down, set the new MAC, bring it back up — rolling the link
    back UP on any partial failure so the interface is never left stranded down.
    Returns True only when the MAC actually changed and the link is up."""
    if not _run(["ip", "link", "set", interface, "down"]):
        return False
    if not _run(["ip", "link", "set", interface, "address", new_mac]):
        # The address set failed; the link is still down → bring it back up so
        # the host isn't stranded off the network, and report the failure.
        _log.error("stealth: MAC change failed on %s; restoring link up", interface)
        _run(["ip", "link", "set", interface, "up"])
        return False
    if not _run(["ip", "link", "set", interface, "up"]):
        _log.error("stealth: %s left down after MAC change; retrying up", interface)
        _run(["ip", "link", "set", interface, "up"])
        return False
    if ssid:
        # Best-effort re-bind; failure here doesn't strand the link.
        subprocess.run(["nmcli", "dev", "wifi", "connect", ssid], capture_output=True)
    return True


def engage_mirage_cloak(
    interface: str = "wlo1", profile_name: str | None = None
) -> tuple[str, str]:
    """
    Tactical Cloak: apply the named Mirage profile, or a random one when
    profile_name is empty/"RANDOM"/unknown.

    Returns ``(status, new_mac)``. ``new_mac`` is empty when the MAC did not
    actually change, so the caller never adopts a MAC it doesn't really have.
    """
    if profile_name and profile_name != "RANDOM":
        profile = next((p for p in PROFILES if p["name"] == profile_name), None) or random.choice(
            PROFILES
        )
    else:
        profile = random.choice(PROFILES)
    hostname = f"{profile['name']}-{random.randint(10, 99)}"
    mac_prefix = profile["oui"]

    # 1. Change hostname (non-fatal; logged on failure).
    if not _run(["hostnamectl", "set-hostname", hostname]):
        _log.warning("stealth: hostname change to %s did not apply", hostname)

    # 2. Extract current SSID for instant re-bind.
    current_ssid = _current_ssid()

    # 3. Change MAC — with link recovery on partial failure.
    new_mac = (
        f"{mac_prefix}:{random.randint(10, 99):02x}:"
        f"{random.randint(10, 99):02x}:{random.randint(10, 99):02x}"
    )
    mac_ok = _change_mac(interface, new_mac, current_ssid)
    if not mac_ok:
        new_mac = ""  # don't claim a MAC we didn't actually set

    # 4. Engage the Ghost Firewall (silent-drop) after a short grace period.
    #    Reuse GhostFirewall, which builds the established/related AND loopback
    #    accept rules and rolls a half-built table back on failure instead of
    #    locking the host out of its own network (the inline copy did neither).
    time.sleep(1)
    fw_status = GhostFirewall().toggle_stealth(True)
    if "LOCKED" not in fw_status:
        _log.warning("stealth: ghost firewall did not engage: %s", fw_status)

    if new_mac:
        return f"[CLOAKED AS: {hostname}]", new_mac
    return f"[CLOAK PARTIAL: {hostname} — MAC unchanged]", ""


def disengage_stealth(
    interface: str = "wlo1", orig_mac: str | None = None, orig_hostname: str = "Lanwarden"
) -> str:
    """
    Restores the machine to its original identity.

    Each restore step is isolated so a failure in one (e.g. hostname) cannot skip
    the others (MAC, firewall) — the old single-try/check=True version left the
    spoofed MAC and stealth firewall in place if the first command failed. The
    returned status reflects whether the identity-critical restores (hostname,
    MAC) actually succeeded, instead of always claiming success.
    """
    ok = True

    # Restore hostname
    if orig_hostname:
        ok &= _run(["hostnamectl", "set-hostname", orig_hostname])

    # Restore MAC
    if orig_mac:
        ok &= _run(["ip", "link", "set", interface, "down"])
        ok &= _run(["ip", "link", "set", interface, "address", orig_mac])
        ok &= _run(["ip", "link", "set", interface, "up"])

    # Remove the stealth firewall table. Its absence is not a failure (the cloak
    # may not have fully engaged), so this does not affect the identity status.
    _run(["nft", "delete", "table", "inet", "lanwarden_stealth"])

    return "[IDENTITY RESTORED]" if ok else "[IDENTITY RESTORE INCOMPLETE]"
