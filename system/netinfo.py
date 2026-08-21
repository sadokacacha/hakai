"""
system/netinfo.py — Auto-detect network interface, gateway, my IP, my MAC.
Disables rp_filter for reliable ARP spoofing.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field


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
    
    # Original states for restoration
    _orig_forwarding: str = "0"
    _orig_rp_filter:  str = "1"
    _orig_redirects:  str = "1"
    _orig_promisc:    bool = False


def detect_network(preferred_iface: str = "auto") -> NetInfo:
    """
    Parse `ip route` for default gateway + interface,
    `ip addr` for our IP, ioctl for our MAC.
    """
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
        # Capture original states
        info._orig_forwarding = _run("cat", "/proc/sys/net/ipv4/ip_forward").strip() or "0"
        info._orig_rp_filter  = _run("cat", "/proc/sys/net/ipv4/conf/all/rp_filter").strip() or "1"
        info._orig_redirects   = _run("cat", "/proc/sys/net/ipv4/conf/all/send_redirects").strip() or "1"
        
        link_info = _run("ip", "link", "show", info.iface)
        info._orig_promisc = "PROMISC" in link_info

        # Enable forwarding
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        # Disable rp_filter (prevent dropping spoofed packets)
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{info.iface}.rp_filter=0"], capture_output=True)
        # Enable Proxy ARP
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.proxy_arp=1"], capture_output=True)
        # Disable sending/accepting local redirects
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"], capture_output=True)
        
        # Enable Promiscuous mode
        subprocess.run(["ip", "link", "set", info.iface, "promisc", "on"], capture_output=True)
        
        # Disable NIC Offloading (Ensure we see every packet individually)
        ethtool = shutil.which("ethtool")
        if ethtool:
            # We don't restore these because it's hardware-dependent and often better off for sniffing
            # But we only do it if we are sure we are in a high-performance scenario
            subprocess.run([ethtool, "-K", info.iface, "gro", "off", "lro", "off", "tso", "off", "gso", "off"], 
                           capture_output=True)
    except Exception:
        pass

    return info


def restore_network(info: NetInfo):
    """Reverts kernel changes to original states."""
    if not info.iface: return
    try:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={info._orig_forwarding}"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.all.rp_filter={info._orig_rp_filter}"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.all.send_redirects={info._orig_redirects}"], capture_output=True)
        subprocess.run(["sysctl", "-w", f"net.ipv4.conf.all.accept_redirects={info._orig_redirects}"], capture_output=True)
        
        p_state = "on" if info._orig_promisc else "off"
        subprocess.run(["ip", "link", "set", info.iface, "promisc", p_state], capture_output=True)
        
        # Re-enable offloading (Standard defaults)
        ethtool = shutil.which("ethtool")
        if ethtool:
            subprocess.run([ethtool, "-K", info.iface, "gro", "on", "lro", "on", "tso", "on", "gso", "on"], 
                           capture_output=True)
    except Exception:
        pass
