"""
system/netinfo.py — Auto-detect network interface, gateway, my IP, my MAC.
Disables rp_filter for reliable ARP spoofing (Linux only).
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field

_IS_WINDOWS = sys.platform == "win32"


def _run(*cmd, timeout=5) -> str:
    try:
        r = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


@dataclass
class NetInfo:
    iface:    str = ""
    gateway:  str = ""
    my_ip:    str = ""
    my_mac:   str = ""
    subnet:   str = ""
    is_wifi:  bool = False

    # Original states for restoration (Linux only)
    _orig_forwarding: str = "0"
    _orig_rp_filter:  str = "1"
    _orig_redirects:  str = "1"
    _orig_promisc:    bool = False


def _detect_network_windows() -> NetInfo:
    """Detect network info on Windows using ipconfig /all + route print."""
    info = NetInfo()

    # ── Gateway via route print ───────────────────────────────────────────
    route_out = _run("route", "print", "0.0.0.0")
    # Look for:  0.0.0.0  0.0.0.0  <gateway>  <local_ip>
    for line in route_out.splitlines():
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            info.gateway = m.group(1)
            info.my_ip   = m.group(2)
            break

    if not info.my_ip:
        # Fallback: socket trick
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info.my_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    # ── ipconfig /all — find adapter with our IP ──────────────────────────
    ipcfg = _run("ipconfig", "/all")
    sections = re.split(r"\r?\n\r?\n", ipcfg)

    for section in sections:
        if info.my_ip and info.my_ip in section:
            # Extract adapter name from section header (first non-blank line)
            hdr_m = re.match(r"([^\r\n]+)", section.strip())
            if hdr_m:
                # e.g. "Ethernet adapter Wi-Fi:" or "Wireless LAN adapter Wi-Fi:"
                adapter_raw = hdr_m.group(1).strip().rstrip(":")
                info.iface = adapter_raw

            # Extract MAC
            mac_m = re.search(r"Physical Address[.\s]+:\s*([\w-]+)", section)
            if mac_m:
                info.my_mac = mac_m.group(1).replace("-", ":").upper()

            # Extract subnet mask → prefix
            mask_m = re.search(r"Subnet Mask[.\s]+:\s*(\d+\.\d+\.\d+\.\d+)", section)
            if mask_m and info.my_ip:
                mask = mask_m.group(1)
                # Convert mask to prefix length
                prefix = sum(bin(int(o)).count("1") for o in mask.split("."))
                octets = info.my_ip.split(".")
                mask_int = int(mask.replace(".", ""))
                m_ints = [int(o) for o in mask.split(".")]
                net_oc = [str(int(octets[i]) & m_ints[i]) for i in range(4)]
                info.subnet = ".".join(net_oc) + f"/{prefix}"

            # Detect WiFi
            if re.search(r"wi.?fi|wireless|wlan|802\.11", section, re.IGNORECASE):
                info.is_wifi = True
            break

    return info


def _detect_network_linux(preferred_iface: str = "auto") -> NetInfo:
    """Detect network info on Linux using ip route / ip addr."""
    info = NetInfo()

    # ── Gateway + iface ───────────────────────────────────────────────────
    route_out = _run("ip", "route")
    for line in route_out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            try:
                info.gateway = parts[parts.index("via")  + 1]
                info.iface   = parts[parts.index("dev")  + 1]
            except (ValueError, IndexError):
                pass
            break

    # Override iface if user specified one explicitly
    if preferred_iface and preferred_iface not in ("auto", ""):
        info.iface = preferred_iface

    if not info.iface:
        return info

    # ── My IP + subnet ────────────────────────────────────────────────────
    addr_out = _run("ip", "-4", "addr", "show", info.iface)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr_out)
    if m:
        info.my_ip = m.group(1)
        prefix     = int(m.group(2))
        octets = info.my_ip.split(".")
        mask   = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net_oc = [str((int(octets[i]) & ((mask >> (24 - 8*i)) & 0xFF))) for i in range(4)]
        info.subnet = ".".join(net_oc) + f"/{prefix}"

    # ── My MAC (ioctl SIOCGIFHWADDR) ──────────────────────────────────────
    try:
        import fcntl, struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            raw = fcntl.ioctl(s.fileno(), 0x8927,
                              struct.pack("256s", info.iface[:15].encode()))
            info.my_mac = ":".join(f"{b:02x}" for b in raw[18:24])
        finally:
            s.close()
    except Exception:
        pass

    # ── Is wireless? ──────────────────────────────────────────────────────
    iw = shutil.which("iw")
    if iw:
        out = _run(iw, "dev")
        info.is_wifi = info.iface in out

    # ── Capture and Tune Kernel for Godly MITM ────────────────────────────
    try:
        info._orig_forwarding = _run("cat", "/proc/sys/net/ipv4/ip_forward").strip() or "0"
        info._orig_rp_filter  = _run("cat", "/proc/sys/net/ipv4/conf/all/rp_filter").strip() or "1"
        info._orig_redirects   = _run("cat", "/proc/sys/net/ipv4/conf/all/send_redirects").strip() or "1"

        link_info = _run("ip", "link", "show", info.iface)
        info._orig_promisc = "PROMISC" in link_info

        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{info.iface}.rp_filter=0"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.proxy_arp=1"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"], capture_output=True)
        subprocess.run(["ip", "link", "set", info.iface, "promisc", "on"], capture_output=True)

        ethtool = shutil.which("ethtool")
        if ethtool:
            subprocess.run([ethtool, "-K", info.iface, "gro", "off", "lro", "off", "tso", "off", "gso", "off"],
                           capture_output=True)
    except Exception:
        pass

    return info


def detect_network(preferred_iface: str = "auto") -> NetInfo:
    """
    Auto-detect the active network interface, gateway, IP, MAC, and subnet.
    Works on both Windows and Linux/macOS.
    """
    if _IS_WINDOWS:
        return _detect_network_windows()
    else:
        return _detect_network_linux(preferred_iface)


def restore_network(info: NetInfo):
    """Reverts kernel changes to original states (Linux only)."""
    if _IS_WINDOWS or not info.iface:
        return
    try:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={info._orig_forwarding}"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.all.rp_filter={info._orig_rp_filter}"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.all.send_redirects={info._orig_redirects}"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.all.accept_redirects={info._orig_redirects}"], capture_output=True)

        p_state = "on" if info._orig_promisc else "off"
        subprocess.run(["ip", "link", "set", info.iface, "promisc", p_state], capture_output=True)

        ethtool = shutil.which("ethtool")
        if ethtool:
            subprocess.run([ethtool, "-K", info.iface, "gro", "on", "lro", "on", "tso", "on", "gso", "on"],
                           capture_output=True)
    except Exception:
        pass
