"""
network/dhcp_sniffer.py — Surgical DHCP Fingerprinting.

Extracts two things from DHCP packets:
  1. OS guess   — from the parameter-request-list (option 55)
  2. Hostname   — from option 12 (client hostname field)

Both are passed to the controller via callbacks so devices with
randomised MACs still get named/classified correctly.
"""
from __future__ import annotations

from scapy.all import BOOTP, DHCP, IP, Ether


def sniff_dhcp_os(pkt, os_cb, hostname_cb=None):
    """
    Analyses DHCP for OS identity and client hostname.

    os_cb(mac, os_guess)       — called when option 55 yields an OS match.
    hostname_cb(ip, hostname, mac) — called when option 12 yields a hostname.
    """
    if not pkt.haslayer(DHCP):
        return

    opts = pkt[DHCP].options
    mac  = pkt[Ether].src if pkt.haslayer(Ether) else None
    ip   = pkt[IP].src   if pkt.haslayer(IP)    else None

    # DHCP Discover/Request packets often use 0.0.0.0 as the source before the
    # lease is assigned. Prefer the requested/assigned address when available,
    # and always pass MAC so the controller can match the device after scanning.
    bootp_ip = ""
    if pkt.haslayer(BOOTP):
        bootp = pkt[BOOTP]
        bootp_ip = bootp.ciaddr or bootp.yiaddr or ""
    requested_ip = ""

    for opt in opts:
        if not isinstance(opt, tuple):
            continue

        if opt[0] in ("requested_addr", "requested_ip_address"):
            requested_ip = str(opt[1]).strip()

        # Option 55 — parameter request list → OS fingerprint
        if opt[0] == "param_req_list" or opt[0] == "parameter_request_list":
            signature = list(opt[1]) if hasattr(opt[1], "__iter__") else []
            os_guess  = infer_os(signature)
            if mac and os_guess and os_cb:
                os_cb(mac, os_guess)

        # Option 12 — client hostname (the device's self-reported name)
        if opt[0] == "hostname":
            raw = opt[1]
            if isinstance(raw, bytes):
                raw = raw.decode(errors="ignore")
            hostname = str(raw).strip()
            best_ip = requested_ip or bootp_ip or ip or ""
            if best_ip == "0.0.0.0":
                best_ip = ""
            if hostname and hostname_cb:
                hostname_cb(best_ip, hostname, mac)

        # Option 60 — vendor class ID (sometimes reveals OS/device class)
        if opt[0] == "vendor_class_id":
            raw = opt[1]
            if isinstance(raw, bytes):
                raw = raw.decode(errors="ignore")
            vc = str(raw).lower()
            if mac and os_cb:
                if "android" in vc:             os_cb(mac, "Android")
                elif "iphone" in vc or "ipad" in vc: os_cb(mac, "Apple/iOS")
                elif "msft" in vc:              os_cb(mac, "Windows")
                elif "linux" in vc:             os_cb(mac, "Linux")
                elif "huawei" in vc:            os_cb(mac, "Huawei Device")
                elif "nokia" in vc:             os_cb(mac, "Nokia Modem")
                elif "sagem" in vc:             os_cb(mac, "Sagemcom Router")
                elif "cisco" in vc:             os_cb(mac, "Cisco Infrastructure")
                elif "hpe" in vc:               os_cb(mac, "HP/Aruba Node")



def infer_os(sig: list[int]) -> str:
    """
    High-precision OS mapping via DHCP parameter-request-list signature.
    """
    sig_tuple = tuple(sig)

    # ── Exact surgical signatures ─────────────────────────────────────────────
    if sig_tuple == (1, 3, 6, 15, 119, 252):              return "Apple/iOS (Modern)"
    if sig_tuple == (1, 3, 6, 15, 119):                    return "Apple Device"
    if sig_tuple == (1, 3, 6, 15, 31, 33, 43, 44, 46,
                     47, 119, 121, 249, 252):               return "Windows 11"
    if sig_tuple == (1, 3, 6, 15, 31, 33, 43, 44, 46,
                     47, 121, 249, 252):                    return "Windows 10"
    if sig_tuple == (1, 3, 6, 15, 31, 33, 43, 44, 46,
                     47, 121, 249):                         return "Windows 10/8"
    if sig_tuple == (1, 3, 6, 15, 44, 46, 47, 31, 33,
                     121, 249, 43):                         return "Windows 7"
    if 121 in sig and 43 in sig and 12 in sig:             return "Android Device"
    if 12 in sig and 15 in sig and 28 in sig:              return "Linux System"
    if sig_tuple == (1, 28, 2, 3, 15, 6, 119, 12, 44,
                     47, 26, 121, 42):                      return "macOS"

    # ── Broad heuristics ─────────────────────────────────────────────────────
    if 119 in sig and 252 in sig and 95 in sig:            return "Apple/iOS"
    if 119 in sig and 252 in sig:                          return "Apple Device"
    if 43 in sig and 60 in sig:                            return "Android Device"
    if 121 in sig and 249 in sig and 43 in sig:            return "Windows"
    if 26 in sig and 121 in sig and 42 in sig:             return "macOS/BSD"

    return "Generic Device"
