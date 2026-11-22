#!/usr/bin/env python3
"""
tools/bench_send.py — STEP 4 send-path benchmark (ROOT + a real iface required).

Compares scapy ``sendp`` vs the raw AF_PACKET sender over the same pre-built
frame, so the keep/revert decision for the raw send path can be made on real
packets/sec numbers (which cannot be measured without CAP_NET_RAW).

Usage:
    sudo python3 tools/bench_send.py <iface> [count]

It sends harmless gratuitous-ARP frames for a link-local (169.254/16) address on
the given interface. Run only on an authorized, isolated lab network.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sudo python3 tools/bench_send.py <iface> [count]")
        return 2
    iface = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    from scapy.all import ARP, Ether, sendp

    from network.rawsock import RawL2Sender

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="169.254.0.1", pdst="169.254.0.1")
    frame = bytes(pkt)

    t0 = time.perf_counter()
    for _ in range(count):
        sendp(pkt, iface=iface, verbose=False)
    scapy_pps = count / (time.perf_counter() - t0)

    raw = RawL2Sender(iface)
    if not raw.available:
        print("raw AF_PACKET socket unavailable — run as root (CAP_NET_RAW).")
        return 1
    t0 = time.perf_counter()
    for _ in range(count):
        raw.send(frame)
    raw_pps = count / (time.perf_counter() - t0)
    raw.close()

    print(f"frames:         {count:,}")
    print(f"scapy sendp:    {scapy_pps:,.0f} pps")
    print(f"raw AF_PACKET:  {raw_pps:,.0f} pps")
    print(f"speedup:        {raw_pps / scapy_pps:.1f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
