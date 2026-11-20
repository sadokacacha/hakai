"""
system/network_manager.py — Static IP & DNS config via nmcli.
"""

import ipaddress
import logging
import shutil
import subprocess

_log = logging.getLogger(__name__)


def _valid_cidr(addr: str) -> bool:
    """Accepts a host address with or without a prefix (e.g. 192.168.1.50/24)."""
    try:
        ipaddress.ip_interface(addr)
    except ValueError:
        return False
    return True


def _valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


def _valid_dns(dns: str) -> bool:
    parts = [p.strip() for p in dns.split(",") if p.strip()]
    return bool(parts) and all(_valid_ip(p) for p in parts)


def get_connections() -> list[str]:
    """Returns a list of active NetworkManager connection names."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"],
            capture_output=True,
            text=True,
        )
        conns = []
        for line in r.stdout.splitlines():
            name = line.split(":")[0]
            if name:
                conns.append(name)
        return conns
    except Exception:
        return []


def apply_static_config(conn_name: str, ip: str, gateway: str, dns: str = "8.8.8.8"):
    """
    Applies static IP config using nmcli.
    Example: 192.168.1.50/24, 192.168.1.1, 8.8.8.8
    """
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return False, "nmcli not found"
    if not conn_name:
        return False, "no connection selected"
    # Validate the user-typed values before they reach privileged nmcli.
    if not _valid_cidr(ip):
        return False, f"invalid IP/prefix: {ip!r}"
    if not _valid_ip(gateway):
        return False, f"invalid gateway: {gateway!r}"
    if not _valid_dns(dns):
        return False, f"invalid DNS: {dns!r}"

    try:
        # 1. Set method to manual
        subprocess.run(
            [nmcli, "connection", "modify", conn_name, "ipv4.method", "manual"],
            check=True,
            capture_output=True,
        )
        # 2. Set address
        subprocess.run(
            [nmcli, "connection", "modify", conn_name, "ipv4.addresses", ip],
            check=True,
            capture_output=True,
        )
        # 3. Set gateway
        subprocess.run(
            [nmcli, "connection", "modify", conn_name, "ipv4.gateway", gateway],
            check=True,
            capture_output=True,
        )
        # 4. Set DNS
        subprocess.run(
            [nmcli, "connection", "modify", conn_name, "ipv4.dns", dns],
            check=True,
            capture_output=True,
        )
        # 5. Up the connection to apply
        subprocess.run([nmcli, "connection", "up", conn_name], check=True, capture_output=True)
        return True, "Static config applied successfully"
    except (subprocess.CalledProcessError, OSError) as e:
        _log.warning("static config failed for %s: %s", conn_name, e)
        # Partial apply leaves the connection half-configured in manual mode,
        # which can drop connectivity — revert to DHCP to restore a working state.
        try:
            subprocess.run(
                [nmcli, "connection", "modify", conn_name, "ipv4.method", "auto"],
                check=True,
                capture_output=True,
            )
            subprocess.run([nmcli, "connection", "up", conn_name], check=True, capture_output=True)
            return False, f"{e}; reverted to DHCP"
        except (subprocess.CalledProcessError, OSError) as e2:
            _log.error("static config revert to DHCP failed for %s: %s", conn_name, e2)
            return False, f"{e}; revert to DHCP also failed: {e2}"


def set_dhcp(conn_name: str):
    """Reverts connection to DHCP."""
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return False, "nmcli not found"
    if not conn_name:
        return False, "no connection selected"
    try:
        subprocess.run(
            [nmcli, "connection", "modify", conn_name, "ipv4.method", "auto"],
            check=True,
            capture_output=True,
        )
        subprocess.run([nmcli, "connection", "up", conn_name], check=True, capture_output=True)
        return True, "Reverted to DHCP"
    except (subprocess.CalledProcessError, OSError) as e:
        return False, str(e)
