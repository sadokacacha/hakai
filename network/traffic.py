"""
network/traffic.py — Three-layer per-IP traffic counter.

Layer 1: iptables FORWARD byte counters  (most reliable, always works as root)
Layer 2: Scapy per-packet AsyncSniffer   (real-time speed, MITM scenarios)
Layer 3: /proc/net/dev interface speed   (interface-level sanity check)

Direction (iptables):
  FORWARD -s <ip>  → upload   (TX — device sending to internet)
  FORWARD -d <ip>  → download (RX — device receiving from internet)
"""
from __future__ import annotations

try:
    from scapy.all import IP, AsyncSniffer, Ether, IPv6, sniff
    SCAPY_OK = True
except ImportError:
    AsyncSniffer = IP = Ether = sniff = None  # type: ignore[assignment,misc]
    SCAPY_OK = False


import collections
import logging
import subprocess
import sys
import threading
import time

_IS_WINDOWS = sys.platform == "win32"
_log = logging.getLogger(__name__)


class TrafficCounter:
    WINDOW    = 5    # sliding speed window in seconds (wider = smoother on sparse data)
    IPT_POLL  = 1.0  # iptables counter poll interval
    PROC_POLL = 1.0  # /proc/net/dev poll interval

    def __init__(self):
        self._lock    = threading.Lock()
        self._running = False
        self._iface   = ""
        self._my_ip   = ""
        self._my_mac  = ""

        # Per-IP sliding speed queues: deque of (timestamp, bytes)
        self._rx: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._tx: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # Per-IP cumulative totals (from iptables — authoritative when in MITM position)
        self._rx_tot: dict[str, int] = collections.defaultdict(int)
        self._tx_tot: dict[str, int] = collections.defaultdict(int)

        # Per-IP Scapy-observed byte totals (fallback when NOT in MITM/forwarding position)
        # iptables FORWARD only counts bytes routed *through* us; Scapy sees all wire traffic.
        self._pkt_rx_acc: dict[str, int] = collections.defaultdict(int)
        self._pkt_tx_acc: dict[str, int] = collections.defaultdict(int)

        # Usage offsets — let us "reset" counters without touching kernel state
        self._rx_off:     dict[str, int] = collections.defaultdict(int)
        self._tx_off:     dict[str, int] = collections.defaultdict(int)
        self._pkt_rx_off: dict[str, int] = collections.defaultdict(int)
        self._pkt_tx_off: dict[str, int] = collections.defaultdict(int)

        # iptables previous byte counts (for delta calculation)
        self._ipt_prev: dict[str, list] = collections.defaultdict(lambda: [0, 0])

        # Registered IPs and MACs
        self._known_ips: set[str]       = set()
        self._mac_to_ip: dict[str, str] = {}
        self._cut_ips:   set[str]       = set()
        self._last_scapy: dict[str, float] = {}  # ip -> last scapy packet timestamp

        # Per-IP data source tracking: True = iptables/MITM active, False = passive only
        self._mitm_active: dict[str, bool] = collections.defaultdict(bool)

        # Interface-level (from /proc/net/dev)
        self._iface_rx_prev:  int   = 0
        self._iface_tx_prev:  int   = 0
        self._proc_ts:        float = 0.0
        self._iface_rx_speed: float = 0.0
        self._iface_tx_speed: float = 0.0
        self._iface_rx_total: int   = 0
        self._iface_tx_total: int   = 0

    # ── Device registration ─────────────────────────────────────────────────

    def register_device(self, ip: str, mac: str):
        with self._lock:
            self._known_ips.add(ip)
            if mac:
                self._mac_to_ip[mac.lower()] = ip


    def mark_cut(self, ip: str):
        with self._lock:
            self._cut_ips.add(ip)
            self._rx[ip] = collections.deque()
            self._tx[ip] = collections.deque()

    def unmark_cut(self, ip: str):
        with self._lock:
            self._cut_ips.discard(ip)

    # ── Start / stop ────────────────────────────────────────────────────────

    def start(self, iface: str, my_ip: str, my_mac: str = ""):
        if self._running:
            return
        self._iface  = iface
        self._my_ip  = my_ip
        self._my_mac = my_mac.lower()

        # Force IP Forwarding (Linux only)
        if not _IS_WINDOWS:
            try:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            except Exception:
                pass

        rx0, tx0 = self._read_proc(iface)
        self._iface_rx_prev = rx0
        self._iface_tx_prev = tx0
        self._proc_ts = time.time()

        self._running = True
        threading.Thread(target=self._proc_loop,  daemon=True, name="tc_proc").start()
        threading.Thread(target=self._ipt_loop,   daemon=True, name="tc_ipt").start()
        if SCAPY_OK:
            threading.Thread(target=self._scapy_loop, daemon=True, name="tc_scapy").start()

    def stop(self):
        self._running = False

    # ── Layer 1: iptables byte counter poll ─────────────────────────────────

    def _ipt_loop(self):
        """Poll iptables byte counters (Linux only)."""
        if _IS_WINDOWS:
            return  # iptables not available on Windows
        while self._running:
            time.sleep(self.IPT_POLL)
            with self._lock:
                ips = list(self._known_ips)
            if not ips:
                continue
            try:
                r = subprocess.run(
                    ["iptables", "-L", "FORWARD", "-v", "-n", "-x"],
                    capture_output=True, text=True, timeout=5)
                if r.returncode != 0:
                    continue
            except Exception:
                continue

            rx_now: dict[str, int] = {}
            tx_now: dict[str, int] = {}

            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 9:
                    continue
                try:
                    bc = int(parts[1])
                except ValueError:
                    continue
                
                # Strip potential /32 or other masks from iptables output
                src = parts[7].split('/')[0]
                dst = parts[8].split('/')[0]

                with self._lock:
                    known = self._known_ips
                
                if src in known and src != self._my_ip:
                    tx_now[src] = tx_now.get(src, 0) + bc
                if dst in known and dst != self._my_ip:
                    rx_now[dst] = rx_now.get(dst, 0) + bc

            now = time.time()
            with self._lock:
                for ip in ips:
                    if ip in self._cut_ips:
                        continue
                    rx_cur = rx_now.get(ip, 0)
                    tx_cur = tx_now.get(ip, 0)
                    prev   = self._ipt_prev[ip]
                    
                    rx_d = rx_cur - prev[0] if rx_cur >= prev[0] else rx_cur
                    tx_d = tx_cur - prev[1] if tx_cur >= prev[1] else tx_cur
                    self._ipt_prev[ip] = [rx_cur, tx_cur]

                    if rx_d > 0:
                        self._rx_tot[ip] += rx_d
                        self._mitm_active[ip] = True   # iptables saw real forwarded bytes
                        if now - self._last_scapy.get(ip, 0) > 1.5:
                            self._rx[ip].append((now, rx_d))
                    if tx_d > 0:
                        self._tx_tot[ip] += tx_d
                        self._mitm_active[ip] = True
                        if now - self._last_scapy.get(ip, 0) > 1.5:
                            self._tx[ip].append((now, tx_d))

    # ── Layer 2: /proc/net/dev interface speed ──────────────────────────────

    @staticmethod
    def _read_proc(iface: str) -> tuple[int, int]:
        """Read interface byte counters from /proc/net/dev (Linux only)."""
        if _IS_WINDOWS:
            return 0, 0
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if iface in line:
                        parts = line.split(":")[-1].split()
                        if len(parts) >= 9:
                            return int(parts[0]), int(parts[8])
        except Exception:
            pass
        return 0, 0

    def _proc_loop(self):
        while self._running:
            time.sleep(self.PROC_POLL)
            now = time.time()
            rx, tx = self._read_proc(self._iface)
            elapsed = now - self._proc_ts
            if elapsed <= 0:
                continue
            rx_d = rx - self._iface_rx_prev
            tx_d = tx - self._iface_tx_prev
            if rx_d < 0: rx_d += 2**32
            if tx_d < 0: tx_d += 2**32
            with self._lock:
                self._iface_rx_speed = (rx_d / elapsed) * 8 / 1_000_000
                self._iface_tx_speed = (tx_d / elapsed) * 8 / 1_000_000
                self._iface_rx_total += rx_d
                self._iface_tx_total += tx_d

            self._iface_rx_prev = rx
            self._iface_tx_prev = tx
            self._proc_ts = now

    # ── Layer 3: Scapy per-packet sniffer ───────────────────────────────────

    def _scapy_loop(self):
        if not SCAPY_OK: return
        _log.info("Traffic sniffer started on %s", self._iface)
        while self._running:
            try:
                # Use a small timeout to allow checking self._running
                sniff(iface=self._iface, filter="ip or ip6", prn=self._pkt, 
                      store=0, timeout=2)
            except Exception as e:
                if "Network is down" in str(e):
                    time.sleep(5)
                time.sleep(1)

    def _pkt(self, pkt):
        """
        Greedy packet identification (L2 MAC -> L3 IP).
        Supports IPv4 and IPv6.
        """
        try:
            now  = time.time()
            size = len(pkt)
            if size < 60: return

            src_ip, dst_ip = None, None
            if pkt.haslayer(IP):
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

            s_mac, d_mac = None, None
            if pkt.haslayer(Ether):
                s_mac, d_mac = pkt[Ether].src.lower(), pkt[Ether].dst.lower()

            with self._lock:
                # 1. Identify by MAC (Highest Precision)
                if s_mac and s_mac in self._mac_to_ip:
                    ip = self._mac_to_ip[s_mac]
                    # Skip our own machine — its traffic is not a "device" to track
                    if ip not in self._cut_ips and ip != self._my_ip:
                        self._tx[ip].append((now, size))
                        self._pkt_tx_acc[ip] += size
                        self._last_scapy[ip] = now
                        src_ip = None  # Done with source

                if d_mac and d_mac in self._mac_to_ip:
                    ip = self._mac_to_ip[d_mac]
                    # Skip our own machine
                    if ip not in self._cut_ips and ip != self._my_ip:
                        self._rx[ip].append((now, size))
                        self._pkt_rx_acc[ip] += size
                        self._last_scapy[ip] = now
                        dst_ip = None  # Done with destination

                # 2. Fallback to IP (if not already identified by MAC)
                if src_ip and src_ip in self._known_ips and src_ip != self._my_ip:
                    if src_ip not in self._cut_ips:
                        self._tx[src_ip].append((now, size))
                        self._pkt_tx_acc[src_ip] += size
                        self._last_scapy[src_ip] = now

                if dst_ip and dst_ip in self._known_ips and dst_ip != self._my_ip:
                    if dst_ip not in self._cut_ips:
                        self._rx[dst_ip].append((now, size))
                        self._pkt_rx_acc[dst_ip] += size
                        self._last_scapy[dst_ip] = now
        except Exception:
            pass

    # ── Speed calculation ───────────────────────────────────────────────────

    def _spd(self, dq: collections.deque) -> float:
        """Calculates speed in Mbps over a fixed sliding WINDOW.

        Uses WINDOW seconds as the denominator (not packet-span), so bursty
        traffic (e.g. one big chunk then silence) averages correctly.
        """
        now      = time.time()
        lookback = float(self.WINDOW)   # 3 s default
        cut      = now - lookback

        # NOTE: Lock is held by the caller
        while dq and dq[0][0] < cut:
            dq.popleft()

        if not dq:
            return 0.0

        total_bytes = sum(item[1] for item in dq)

        # Divide by the *window* width — this gives the correct sustained rate
        # even when packets are bursty / sparse.
        return (total_bytes / lookback) * 8 / 1_000_000

    # ── Public API ──────────────────────────────────────────────────────────

    def get(self, ip: str) -> tuple[float, float, int, int]:
        """Returns (rx_speed_mbps, tx_speed_mbps, rx_total_bytes, tx_total_bytes)."""
        with self._lock:
            rx_tot = max(0, self._rx_tot[ip] - self._rx_off[ip])
            tx_tot = max(0, self._tx_tot[ip] - self._tx_off[ip])
            
            if ip in self._cut_ips:
                return (0.0, 0.0, rx_tot, tx_tot)

            rx_spd = self._spd(self._rx[ip])
            tx_spd = self._spd(self._tx[ip])
            
        return (rx_spd, tx_spd, rx_tot, tx_tot)

    def get_iface_speed(self) -> tuple[float, float, int, int]:
        with self._lock:
            return (self._iface_rx_speed, self._iface_tx_speed,
                    self._iface_rx_total, self._iface_tx_total)

    def get_mode(self, ip: str) -> str:
        """
        Returns 'MITM' if iptables FORWARD has counted bytes for this IP
        (meaning traffic is actually passing through us via ARP poisoning),
        or 'PASSIVE' if we are only seeing broadcast/multicast packets.
        On a switched network, PASSIVE data is unreliable for individual devices.
        """
        return "MITM" if self._mitm_active.get(ip, False) else "PASSIVE"

    def get_usage(self, ip: str) -> tuple[int, int]:
        """
        Returns (rx_bytes, tx_bytes) for the current session.

        Source priority:
          1. iptables FORWARD counters  — accurate when we are in MITM position.
          2. Scapy per-packet accumulator — active when NOT in MITM position.

        We take the MAX of both so that partial data from either source
        doesn't cause the total to appear as zero.
        """
        with self._lock:
            # iptables-based totals (offset-adjusted)
            ipt_rx = max(0, self._rx_tot.get(ip, 0) - self._rx_off.get(ip, 0))
            ipt_tx = max(0, self._tx_tot.get(ip, 0) - self._tx_off.get(ip, 0))
            # Scapy-based totals (offset-adjusted)
            pkt_rx = max(0, self._pkt_rx_acc.get(ip, 0) - self._pkt_rx_off.get(ip, 0))
            pkt_tx = max(0, self._pkt_tx_acc.get(ip, 0) - self._pkt_tx_off.get(ip, 0))

        # Use the larger value from each source — one may be zero depending
        # on whether ARP-MITM / iptables forwarding is active.
        rx = max(ipt_rx, pkt_rx)
        tx = max(ipt_tx, pkt_tx)
        return (rx, tx)

    def reset_usage(self, ip: str):
        """Snapshot current counters as the new zero-point for this IP."""
        with self._lock:
            self._rx_off[ip]     = self._rx_tot[ip]
            self._tx_off[ip]     = self._tx_tot[ip]
            self._pkt_rx_off[ip] = self._pkt_rx_acc[ip]
            self._pkt_tx_off[ip] = self._pkt_tx_acc[ip]
            self._rx[ip] = collections.deque()
            self._tx[ip] = collections.deque()

    def reset_all_usage(self):
        """Reset session counters for all known IPs."""
        with self._lock:
            for ip in self._known_ips:
                self._rx_off[ip]     = self._rx_tot[ip]
                self._tx_off[ip]     = self._tx_tot[ip]
                self._pkt_rx_off[ip] = self._pkt_rx_acc.get(ip, 0)
                self._pkt_tx_off[ip] = self._pkt_tx_acc.get(ip, 0)
            self._rx.clear()
            self._tx.clear()