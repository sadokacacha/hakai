"""
system/network_manager.py — Static IP & DNS config via nmcli.
"""
import shutil
import subprocess


def get_connections() -> list[str]:
    """Returns a list of active NetworkManager connection names."""
    try:
        r = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"],
                           capture_output=True, text=True)
        conns = []
        for line in r.stdout.splitlines():
            name = line.split(":")[0]
            if name: conns.append(name)
        return conns
    except Exception:
        return []

def apply_static_config(conn_name: str, ip: str, gateway: str, dns: str = "8.8.8.8"):
    """
    Applies static IP config using nmcli.
    Example: 192.168.1.50/24, 192.168.1.1, 8.8.8.8
    """
    nmcli = shutil.which("nmcli")
    if not nmcli: return False, "nmcli not found"

    try:
        # 1. Set method to manual
        subprocess.run([nmcli, "connection", "modify", conn_name, "ipv4.method", "manual"], check=True)
        # 2. Set address
        subprocess.run([nmcli, "connection", "modify", conn_name, "ipv4.addresses", ip], check=True)
        # 3. Set gateway
        subprocess.run([nmcli, "connection", "modify", conn_name, "ipv4.gateway", gateway], check=True)
        # 4. Set DNS
        subprocess.run([nmcli, "connection", "modify", conn_name, "ipv4.dns", dns], check=True)
        # 5. Up the connection to apply
        subprocess.run([nmcli, "connection", "up", conn_name], check=True)
        return True, "Static config applied successfully"
    except subprocess.CalledProcessError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def set_dhcp(conn_name: str):
    """Reverts connection to DHCP."""
    try:
        subprocess.run(["nmcli", "connection", "modify", conn_name, "ipv4.method", "auto"], check=True)
        subprocess.run(["nmcli", "connection", "up", conn_name], check=True)
        return True, "Reverted to DHCP"
    except Exception as e:
        return False, str(e)
