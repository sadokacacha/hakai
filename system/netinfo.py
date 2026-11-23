"""
system/netinfo.py — Auto-detect network interface, gateway, my IP, my MAC.

Detection is read-only: it captures (but never mutates) the kernel/NIC values
that engage_mitm() later changes, so restore_network() can put every one of
them back on exit — including proxy_arp, the per-interface rp_filter, and the
original NIC offload states. (Linux only; the Windows path only detects.)
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field

from core.osutil import IS_WINDOWS as _IS_WINDOWS

_log = logging.getLogger(__name__)

# NIC offload features engage_mitm() disables and restore_network() puts back.
# Maps the `ethtool -k` long name to the short flag `ethtool -K` expects.
_OFFLOAD_FEATURES = {
    "generic-receive-offload": "gro",
    "large-receive-offload": "lro",
    "tcp-segmentation-offload": "tso",
    "generic-segmentation-offload": "gso",
}


def _run(*cmd, timeout=5) -> str:
    try:
        r = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _read_sysctl(key: str, default: str = "") -> str:
    """Read a sysctl value read-only. Returns ``default`` if it can't be read,
    so a failed read can't masquerade as a real captured original."""
    try:
        r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.strip() or default
    except (OSError, subprocess.SubprocessError):
        pass
    return default


def _write_sysctl(key: str, value: str) -> bool:
    """Write a sysctl value. Returns True only on a verified success (rc == 0);
    logs and returns False otherwise instead of swallowing the failure."""
    if not value:
        # Never write an empty value — an uncaptured original must not blank a key.
        _log.warning("skipping sysctl write for %s: no value captured", key)
        return False
    try:
        r = subprocess.run(
            ["sysctl", "-w", f"{key}={value}"], capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            _log.warning(
                "sysctl -w %s=%s failed (rc=%s): %s", key, value, r.returncode, r.stderr.strip()
            )
            return False
        return True
    except (OSError, subprocess.SubprocessError) as e:
        _log.warning("sysctl -w %s=%s error: %s", key, value, e)
        return False


def _read_offloads(iface: str) -> dict[str, str]:
    """Capture current on/off state of the offload features we will toggle."""
    out: dict[str, str] = {}
    ethtool = shutil.which("ethtool")
    if not ethtool or not iface:
        return out
    try:
        r = subprocess.run([ethtool, "-k", iface], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return out
    except (OSError, subprocess.SubprocessError):
        return out
    for line in r.stdout.splitlines():
        m = re.match(r"\s*([a-z0-9-]+):\s*(on|off)", line)
        if m and m.group(1) in _OFFLOAD_FEATURES:
            out[_OFFLOAD_FEATURES[m.group(1)]] = m.group(2)
    return out


@dataclass
class NetInfo:
    iface: str = ""
    gateway: str = ""
    my_ip: str = ""
    my_mac: str = ""
    subnet: str = ""
    is_wifi: bool = False

    # Original states captured before engage_mitm() mutates them (Linux only).
    _orig_forwarding: str = "0"
    _orig_rp_filter: str = "1"  # net.ipv4.conf.all.rp_filter
    _orig_iface_rp_filter: str = "1"  # net.ipv4.conf.<iface>.rp_filter
    _orig_proxy_arp: str = "0"  # net.ipv4.conf.all.proxy_arp
    _orig_redirects: str = "1"  # send_redirects
    _orig_accept_redirects: str = "1"
    _orig_promisc: bool = False
    _orig_offloads: dict[str, str] = field(default_factory=dict)


def _detect_network_windows() -> NetInfo:
    """Detect network info on Windows using ipconfig /all + route print."""
    info = NetInfo()

    # ── Gateway via route print ───────────────────────────────────────────
    route_out = _run("route", "print", "0.0.0.0")
    for line in route_out.splitlines():
        m = re.search(
            r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line
        )
        if m:
            info.gateway = m.group(1)
            info.my_ip = m.group(2)
            break

    if not info.my_ip:
        # Fallback: socket trick
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info.my_ip = s.getsockname()[0]
            s.close()
        except OSError:
            pass

    # ── ipconfig /all — find adapter with our IP ──────────────────────────
    ipcfg = _run("ipconfig", "/all")
    sections = re.split(r"\r?\n\r?\n", ipcfg)

    for section in sections:
        if info.my_ip and info.my_ip in section:
            hdr_m = re.match(r"([^\r\n]+)", section.strip())
            if hdr_m:
                adapter_raw = hdr_m.group(1).strip().rstrip(":")
                info.iface = adapter_raw

            mac_m = re.search(r"Physical Address[.\s]+:\s*([\w-]+)", section)
            if mac_m:
                info.my_mac = mac_m.group(1).replace("-", ":").upper()

            mask_m = re.search(r"Subnet Mask[.\s]+:\s*(\d+\.\d+\.\d+\.\d+)", section)
            if mask_m and info.my_ip:
                mask = mask_m.group(1)
                prefix = sum(bin(int(o)).count("1") for o in mask.split("."))
                octets = info.my_ip.split(".")
                m_ints = [int(o) for o in mask.split(".")]
                net_oc = [str(int(octets[i]) & m_ints[i]) for i in range(4)]
                info.subnet = ".".join(net_oc) + f"/{prefix}"

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
                info.gateway = parts[parts.index("via") + 1]
                info.iface = parts[parts.index("dev") + 1]
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
        prefix = int(m.group(2))
        octets = info.my_ip.split(".")
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net_oc = [str(int(octets[i]) & ((mask >> (24 - 8 * i)) & 0xFF)) for i in range(4)]
        info.subnet = ".".join(net_oc) + f"/{prefix}"

    # ── My MAC (ioctl SIOCGIFHWADDR) ──────────────────────────────────────
    try:
        import fcntl
        import struct

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            raw = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", info.iface[:15].encode()))
            info.my_mac = ":".join(f"{b:02x}" for b in raw[18:24])
        finally:
            s.close()
    except OSError:
        pass

    # ── Is wireless? ──────────────────────────────────────────────────────
    iw = shutil.which("iw")
    if iw:
        out = _run(iw, "dev")
        info.is_wifi = info.iface in out

    # ── Capture original kernel/NIC state (read-only) ─────────────────────
    # Detection must not mutate anything — the actual MITM tuning happens in
    # engage_mitm(), called explicitly when the engine starts. Every value
    # engage_mitm() changes is captured here so restore_network() can revert it.
    info._orig_forwarding = _read_sysctl("net.ipv4.ip_forward", "0")
    info._orig_rp_filter = _read_sysctl("net.ipv4.conf.all.rp_filter", "1")
    info._orig_iface_rp_filter = _read_sysctl(f"net.ipv4.conf.{info.iface}.rp_filter", "1")
    info._orig_proxy_arp = _read_sysctl("net.ipv4.conf.all.proxy_arp", "0")
    info._orig_redirects = _read_sysctl("net.ipv4.conf.all.send_redirects", "1")
    info._orig_accept_redirects = _read_sysctl("net.ipv4.conf.all.accept_redirects", "1")
    info._orig_offloads = _read_offloads(info.iface)

    link_info = _run("ip", "link", "show", info.iface)
    info._orig_promisc = "PROMISC" in link_info

    return info


def engage_mitm(info: NetInfo) -> bool:
    """Apply the kernel/NIC changes needed for MITM (Linux only).

    Called explicitly when the engine starts — NOT as a side effect of
    detection — so merely detecting the network leaves the host untouched.
    Originals are captured in detect_network(); restore_network() reverts these.
    Returns True only if every change was applied successfully.
    """
    if _IS_WINDOWS or not info.iface:
        return False

    ok = True
    ok &= _write_sysctl("net.ipv4.ip_forward", "1")
    ok &= _write_sysctl("net.ipv4.conf.all.rp_filter", "0")
    ok &= _write_sysctl(f"net.ipv4.conf.{info.iface}.rp_filter", "0")
    ok &= _write_sysctl("net.ipv4.conf.all.proxy_arp", "1")
    ok &= _write_sysctl("net.ipv4.conf.all.send_redirects", "0")
    ok &= _write_sysctl("net.ipv4.conf.all.accept_redirects", "0")

    ok &= _set_promisc(info.iface, True)

    # Disable ONLY the offloads whose original state we captured, so engage and
    # restore stay symmetric. An offload we couldn't read (empty capture, e.g.
    # `ethtool -k` failed at detect time) is left untouched rather than forced
    # off with no record to turn it back on — capture-or-None.
    ethtool = shutil.which("ethtool")
    if ethtool and info._orig_offloads:
        args: list[str] = [ethtool, "-K", info.iface]
        for flag in info._orig_offloads:
            args += [flag, "off"]
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                _log.warning("ethtool -K (disable offloads) failed: %s", r.stderr.strip())
                ok = False
        except (OSError, subprocess.SubprocessError) as e:
            _log.warning("ethtool -K error: %s", e)
            ok = False
    elif ethtool:
        _log.warning("skipping offload disable: no original offload state captured")
    return ok


def _set_promisc(iface: str, enable: bool) -> bool:
    state = "on" if enable else "off"
    try:
        r = subprocess.run(
            ["ip", "link", "set", iface, "promisc", state],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            _log.warning("ip link set %s promisc %s failed: %s", iface, state, r.stderr.strip())
            return False
        return True
    except (OSError, subprocess.SubprocessError) as e:
        _log.warning("ip link set promisc error: %s", e)
        return False


def detect_network(preferred_iface: str = "auto") -> NetInfo:
    """
    Auto-detect the active network interface, gateway, IP, MAC, and subnet.
    Works on both Windows and Linux/macOS.
    """
    if _IS_WINDOWS:
        return _detect_network_windows()
    return _detect_network_linux(preferred_iface)


def restore_network(info: NetInfo) -> bool:
    """Revert every kernel/NIC change engage_mitm() made, back to the values
    captured before mutation (Linux only). Idempotent — safe to call twice.

    Returns True only if every revert command succeeded. A False result means
    the host may be left in a partially-modified state and the caller must not
    report restoration as successful.
    """
    if _IS_WINDOWS or not info.iface:
        return False

    ok = True
    ok &= _write_sysctl("net.ipv4.ip_forward", info._orig_forwarding)
    ok &= _write_sysctl("net.ipv4.conf.all.rp_filter", info._orig_rp_filter)
    ok &= _write_sysctl(f"net.ipv4.conf.{info.iface}.rp_filter", info._orig_iface_rp_filter)
    ok &= _write_sysctl("net.ipv4.conf.all.proxy_arp", info._orig_proxy_arp)
    ok &= _write_sysctl("net.ipv4.conf.all.send_redirects", info._orig_redirects)
    ok &= _write_sysctl("net.ipv4.conf.all.accept_redirects", info._orig_accept_redirects)

    ok &= _set_promisc(info.iface, info._orig_promisc)

    # Restore NIC offloads to their *captured* state, not a blanket "on".
    ethtool = shutil.which("ethtool")
    if ethtool and info._orig_offloads:
        args: list[str] = [ethtool, "-K", info.iface]
        for flag, state in info._orig_offloads.items():
            args += [flag, state]
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                _log.warning("ethtool -K (restore offloads) failed: %s", r.stderr.strip())
                ok = False
        except (OSError, subprocess.SubprocessError) as e:
            _log.warning("ethtool -K restore error: %s", e)
            ok = False

    if not ok:
        _log.warning("restore_network: one or more reverts failed; host state may be partial")
    return ok
