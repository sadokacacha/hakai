"""
network/scanner.py — Three-layer ARP/host scanner + async hostname resolver.

Layer 1: nmap -sn  (most info: hostname, MAC, vendor)
Layer 2: Scapy ARP sweep (fallback if nmap absent)
Layer 3: `arp -n` table (last resort — shows cached neighbours)
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from core.device import Device
from core.persistence import _is_junk_hostname, lookup_oui, sanitize_mdns_name

# ── Hostname resolver pool ─────────────────────────────────────────────────────
_hn_cache: dict[str, str] = {}
_hn_lock = threading.Lock()
_hn_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="hn_resolve")


def resolve_hostname(ip: str) -> str:
    """
    Non-blocking — submits a job to the pool and returns immediately.
    Re-call later or poll _hn_cache[ip] directly.
    """
    with _hn_lock:
        if ip in _hn_cache:
            return _hn_cache[ip]

    def _do():
        hn = ""
        av = shutil.which("avahi-resolve")
        if av:
            try:
                r = subprocess.run([av, "-a", ip], capture_output=True, text=True, timeout=3)
                m = re.search(r"\S+\s+(\S+)", r.stdout)
                if m:
                    hn = m.group(1).rstrip(".")
            except Exception:
                pass
        if not hn:
            try:
                hn = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

        # Last resort: nmap grab
        if not hn:
            try:
                r = subprocess.run(["nmap", "-sn", ip], capture_output=True, text=True, timeout=5)
                m = re.search(r"Nmap scan report for (\S+)", r.stdout)
                if m:
                    candidate = m.group(1)
                    if not re.match(r"\d+\.\d+\.\d+\.\d+", candidate):
                        hn = candidate
            except Exception:
                pass

        # NOTE: no port-probe fallback here. A synthetic string like
        # "Device (Port:80 Open)" is not a hostname and must not land in the
        # hostname cache — port-based *identity* hints are handled separately
        # by guess_identity_from_ports()/flush_hostnames().

        with _hn_lock:
            _hn_cache[ip] = hn
        return hn

    _hn_pool.submit(_do)
    return ""


def guess_identity_from_ports(ip: str) -> str:
    """
    Quickly probe signature ports to guess device type when hostname/vendor are hidden.
    """
    signatures = [
        (62078, "Apple Device (iPhone/iPad)"),
        (445, "Windows PC / Server"),
        (139, "Windows / Samba"),
        (8008, "Google Home / Chromecast"),
        (5000, "Synology NAS"),
        (8080, "Web Console"),
        (22, "Linux / SSH Server"),
        (23, "Telnet Device (Legacy/IoT)"),
    ]
    for port, label in signatures:
        try:
            with socket.create_connection((ip, port), timeout=0.3):
                return label
        except Exception:
            continue
    return ""


_guess_pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix="id_guess")
_upnp_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="upnp_fetch")

# ── UPnP FriendlyName async fetcher ───────────────────────────────────────────
_upnp_cache: dict[str, str] = {}  # ip → friendlyName


def _fetch_upnp_friendly(ip: str, location_url: str):
    """Fetch UPnP description XML and extract <friendlyName>."""
    if ip in _upnp_cache:
        return  # Already fetched
    # LOCATION comes from an untrusted SSDP packet — only fetch http(s). Never
    # file:// (local-file read) or other schemes, which urllib would honour.
    if urlparse(location_url).scheme not in ("http", "https"):
        return
    try:
        import urllib.request

        req = urllib.request.Request(location_url, headers={"User-Agent": "Lanwarden/1.0 UPnP/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = resp.read(8192).decode(errors="ignore")

        # Parse friendlyName
        m = re.search(r"<friendlyName>(.*?)</friendlyName>", data, re.IGNORECASE)
        if m:
            friendly = m.group(1).strip()
            if friendly and friendly.lower() not in ("upnp", "unknown", "root device"):
                _upnp_cache[ip] = friendly
                with _hn_lock:
                    # UPnP FriendlyName is high quality — overwrite junk
                    existing = _hn_cache.get(ip, "")
                    if not existing or _is_junk_hostname(existing):
                        _hn_cache[ip] = friendly
                return

        # Fallback: try modelDescription or modelName
        for tag in ("modelDescription", "modelName"):
            m = re.search(rf"<{tag}>(.*?)</{tag}>", data, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val and len(val) > 2:
                    _upnp_cache[ip] = val
                    with _hn_lock:
                        existing = _hn_cache.get(ip, "")
                        if not existing or _is_junk_hostname(existing):
                            _hn_cache[ip] = val
                    return
    except Exception:
        pass


def flush_hostnames(devices: dict):
    """Copy resolved hostnames from cache into device objects (call before render)."""
    with _hn_lock:
        for ip, dev in devices.items():
            if _hn_cache.get(ip):
                cached = _hn_cache[ip]
                # Sanitize before applying — strip mDNS/Bonjour noise
                clean = sanitize_mdns_name(cached)
                if clean and not _is_junk_hostname(clean):
                    # Only overwrite if the new name is better quality
                    if not dev.hostname or _is_junk_hostname(dev.hostname):
                        dev.hostname = clean

            # If still unknown, try a light port probe (Async)
            if not dev.hostname and not dev.identity:

                def _probe_and_set(d, address):
                    g = guess_identity_from_ports(address)
                    if g:
                        d.identity = f"Guess: {g}"

                _guess_pool.submit(_probe_and_set, dev, ip)


# ── Scanner ────────────────────────────────────────────────────────────────────


class Scanner:
    def __init__(self, subnet: str = "192.168.1.0/24"):
        self.subnet = subnet
        self._hn_cache: dict[str, str] = {}
        self._running = False
        self._passive_thread: threading.Thread | None = None

    def start_passive_discovery(self, iface: str):
        """Start listening for mDNS/SSDP/NBNS to discover identities without scanning."""
        if self._running:
            return
        self._running = True
        self._passive_thread = threading.Thread(
            target=self._passive_sniff, args=(iface,), daemon=True, name="passive_discovery"
        )
        self._passive_thread.start()

    def stop_passive_discovery(self):
        self._running = False

    def _passive_sniff(self, iface: str):
        from scapy.all import DNS, IP, UDP, IPv6, NBNSQueryRequest, sniff

        def _get_ip(pkt):
            if pkt.haslayer(IP):
                return pkt[IP].src
            if pkt.haslayer(IPv6):
                return pkt[IPv6].src
            return None

        def _cb(pkt):
            # 1. mDNS (UDP 5353) — sanitize before caching
            if pkt.haslayer(UDP) and pkt[UDP].dport == 5353:
                if pkt.haslayer(DNS) and pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname.decode(errors="ignore").strip(".")
                    if ".local" in qname:
                        name = sanitize_mdns_name(qname)
                        ip = _get_ip(pkt)
                        if ip and name and not _is_junk_hostname(name):
                            with _hn_lock:
                                _hn_cache[ip] = name

            # 2. SSDP (UDP 1900) — extract LOCATION for UPnP, fallback to SERVER
            if pkt.haslayer(UDP) and pkt[UDP].dport == 1900:
                payload = bytes(pkt[UDP].payload).decode(errors="ignore")
                import re

                # Try LOCATION header first (for async UPnP XML fetch)
                loc = re.search(r"LOCATION:\s*(\S+)", payload, re.IGNORECASE)
                if loc:
                    ip = _get_ip(pkt)
                    if ip:
                        _upnp_pool.submit(_fetch_upnp_friendly, ip, loc.group(1))
                # Fallback: SERVER header
                m = re.search(r"SERVER:\s*(.*)", payload, re.IGNORECASE)
                if m:
                    name = m.group(1).split("/")[0].strip()
                    # Don't cache generic OS strings as names
                    if name and name.lower() not in ("upnp", "linux", "windows", "unix"):
                        ip = _get_ip(pkt)
                        if ip:
                            with _hn_lock:
                                # Only set if we don't already have something better
                                if ip not in _hn_cache or _is_junk_hostname(_hn_cache[ip]):
                                    _hn_cache[ip] = name

            # 3. NBNS (UDP 137) - Windows names
            if pkt.haslayer(NBNSQueryRequest):
                name = pkt[NBNSQueryRequest].QUESTION_NAME.decode(errors="ignore").strip()
                ip = _get_ip(pkt)
                if ip and name:
                    with _hn_lock:
                        _hn_cache[ip] = name

            # 4. LLMNR (UDP 5355)
            if pkt.haslayer(UDP) and pkt[UDP].dport == 5355:
                if pkt.haslayer(DNS) and pkt[DNS].qd:
                    name = pkt[DNS].qd.qname.decode(errors="ignore").strip(".")
                    ip = _get_ip(pkt)
                    if ip and name and not _is_junk_hostname(name):
                        with _hn_lock:
                            _hn_cache[ip] = name

            # 5. DHCP (UDP 67/68) — extract Option 12 hostname
            try:
                from scapy.all import BOOTP, DHCP

                if pkt.haslayer(DHCP):
                    requested_ip = ""
                    bootp_ip = ""
                    if pkt.haslayer(BOOTP):
                        bootp = pkt[BOOTP]
                        bootp_ip = bootp.ciaddr or bootp.yiaddr or ""
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] in (
                            "requested_addr",
                            "requested_ip_address",
                        ):
                            requested_ip = str(opt[1]).strip()
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            raw_hn = opt[1]
                            if isinstance(raw_hn, bytes):
                                raw_hn = raw_hn.decode(errors="ignore")
                            hn = str(raw_hn).strip()
                            ip = requested_ip or bootp_ip or _get_ip(pkt)
                            if ip == "0.0.0.0":
                                ip = ""
                            if ip and hn and not _is_junk_hostname(hn):
                                with _hn_lock:
                                    _hn_cache[ip] = hn
            except Exception:
                pass

        while self._running:
            try:
                sniff(
                    filter="udp port 5353 or udp port 1900 or udp port 137 or udp port 5355 or udp port 67 or udp port 68",
                    prn=_cb,
                    iface=iface,
                    store=0,
                    timeout=10,
                )
            except Exception:
                if self._running:
                    import time

                    time.sleep(2)

    def scan(self, iface: str = "", timeout_s: int = 45, spoof_mac: str = "") -> dict[str, Device]:
        """
        Returns a dict of ip → Device.
        Tries nmap → Scapy ARP → arp table, in that order.
        """
        found: dict[str, Device] = {}

        # ── Layer 1: nmap -sn ──────────────────────────────────────────────
        nmap = shutil.which("nmap")
        if nmap:
            try:
                args = [
                    nmap,
                    "-sn",
                    "--host-timeout",
                    "3s",
                    "-T4",
                    "--min-parallelism",
                    "50",
                    "--min-rate",
                    "1000",
                    "--max-retries",
                    "1",
                ]
                if spoof_mac:
                    args += ["--spoof-mac", spoof_mac]
                args.append(self.subnet)

                r = subprocess.run(args, capture_output=True, text=True, timeout=timeout_s)
                cur = ""
                for line in r.stdout.splitlines():
                    if "Nmap scan report" in line:
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if m:
                            cur = m.group(1)
                            hn = ""
                            hm = re.search(r"for (\S+) \(", line)
                            if hm:
                                hn = hm.group(1)
                            found[cur] = Device(cur, hostname=hn)
                    elif "MAC Address:" in line and cur:
                        mm = re.search(r"MAC Address: ([\w:]+)(?:\s+\(([^)]+)\))?", line)
                        if mm:
                            mac = mm.group(1)
                            vendor = mm.group(2) or lookup_oui(mac)
                            found[cur].mac = mac
                            found[cur].vendor = vendor
            except Exception:
                pass

        # ── Layer 1b: lightweight script scan for names & OS hints ────────
        # Runs nbstat + mdns-dns-sd on discovered hosts — no TCP ports needed.
        # This populates hostname / os_guess so Identity column isn't blank.
        if found and nmap:
            try:
                targets = list(found.keys())
                os_args = [
                    nmap,
                    "-sn",
                    "-T4",
                    "--script",
                    "nbstat,mdns-dns-sd",
                    "--host-timeout",
                    "5s",
                ] + targets
                ro = subprocess.run(
                    os_args, capture_output=True, text=True, timeout=min(timeout_s, 30)
                )
                cur_ip = ""
                for line in ro.stdout.splitlines():
                    # Track which host we are parsing
                    m_ip = re.search(
                        r"Nmap scan report for (?:\S+ \((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))",
                        line,
                    )
                    if m_ip:
                        cur_ip = m_ip.group(1) or m_ip.group(2)
                    if not cur_ip or cur_ip not in found:
                        continue
                    dev = found[cur_ip]
                    # NetBIOS / NBSTAT name → hostname
                    m_nb = re.search(r"NetBIOS name:\s*(\S+)", line, re.IGNORECASE)
                    if m_nb and not dev.hostname:
                        dev.hostname = m_nb.group(1).strip("\x00").strip()
                    # mDNS .local name → hostname
                    m_md = re.search(r"(?:Hostname|Name):\s*(\S+\.local)", line, re.IGNORECASE)
                    if m_md and not dev.hostname:
                        dev.hostname = m_md.group(1).rstrip(".")
                    # Rough OS hints from any output line
                    ls = line.lower()
                    if not dev.os_guess:
                        if "windows" in ls:
                            dev.os_guess = "Windows"
                        elif "android" in ls:
                            dev.os_guess = "Android"
                        elif "linux" in ls:
                            dev.os_guess = "Linux"
                        elif "ios" in ls or "iphone" in ls:
                            dev.os_guess = "iOS"
                        elif "macos" in ls or "mac os" in ls:
                            dev.os_guess = "macOS"
            except Exception:
                pass

        # ── Layer 2: Scapy ARP sweep (ALWAYS run and merge) ───────────────
        # nmap -sn with a tight host-timeout misses devices that answer slowly
        # (WiFi power-save, sleeping phones). An ARP sweep with retries is the
        # most reliable way to enumerate a LAN, so we merge it into *every*
        # scan instead of only using it when nmap found nothing. This is what
        # makes a single scan return the full device list rather than filling
        # it in across several passes.
        try:
            from scapy.all import ARP, Ether, srp

            kwargs: dict[str, object] = {"timeout": 2, "retry": 2, "verbose": False}
            if iface:
                kwargs["iface"] = iface
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet),
                filter="arp",
                **kwargs,  # type: ignore[arg-type]
            )
            for _, rcv in answered:
                self._merge_host(found, rcv.psrc, rcv.hwsrc)
        except Exception:
            pass

        # ── Layer 3: arp table (cross-platform, ALWAYS run and merge) ─────
        # Catches hosts the broadcast sweep missed but that the kernel has
        # already talked to. Read-only and cheap.
        try:
            import sys as _sys

            if _sys.platform == "win32":
                # Windows: `arp -a` — format is different from Linux `arp -n`
                # Lines look like:  "  192.168.1.1    88-c2-27-01-ff-74    dynamic"
                # Also has "Interface: x.x.x.x --- 0xN" header lines to skip
                r = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    line = line.strip()
                    # Skip blank lines, Interface: headers, and column headers
                    if not line or line.startswith("Interface:") or "Internet Address" in line:
                        continue
                    pts = line.split()
                    if len(pts) < 3:
                        continue
                    # _merge_host validates the IP and filters broadcast MACs.
                    self._merge_host(found, pts[0], pts[1])
            else:
                # Linux: `arp -n` — format: IP  HWtype  MAC  Flags  Iface
                r = subprocess.run(["arp", "-n"], capture_output=True, text=True)
                for line in r.stdout.splitlines()[1:]:
                    pts = line.split()
                    if len(pts) >= 3 and pts[2] != "(incomplete)":
                        self._merge_host(found, pts[0], pts[2])
        except Exception:
            pass

        return found

    @staticmethod
    def _merge_host(found: dict[str, Device], ip: str, mac: str) -> None:
        """Add a discovered host to ``found``, or fill in a missing MAC/vendor.

        Never clobbers data already gathered by a richer layer (e.g. nmap's
        vendor string): it only sets the MAC/vendor when the existing entry
        has none. Skips non-IPv4, multicast/broadcast, and all-FF MACs.
        """
        if not ip:
            return
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        # IPv4 unicast only (the scanner's Device model is IPv4). Reject IPv6,
        # multicast/broadcast (first octet >= 224), and the unspecified address.
        if addr.version != 4 or addr.is_unspecified or int(ip.split(".")[0]) >= 224:
            return
        mac = (mac or "").replace("-", ":").upper()
        if mac in ("FF:FF:FF:FF:FF:FF", ""):
            mac = ""
        if ip in found:
            dev = found[ip]
            if mac and not dev.mac:
                dev.mac = mac
                if not dev.vendor:
                    dev.vendor = lookup_oui(mac)
        else:
            found[ip] = Device(ip, mac=mac, vendor=lookup_oui(mac) if mac else "")
