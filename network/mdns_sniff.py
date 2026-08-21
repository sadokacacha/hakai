"""
network/mdns_sniff.py — Advanced mDNS / DNS-SD Social Unmasker.

Extracts both device names and device-class hints from mDNS traffic.
Covers Apple, Google, Microsoft, Amazon, Sonos, Roku, smart-home and
Linux Avahi announcements so most modern devices get identified without
needing a full port scan.
"""
from __future__ import annotations
from scapy.all import DNS, DNSRR, IP
from core.persistence import sanitize_mdns_name as _sanitize


# Maps service-type substrings to human-readable OS/class labels
_SERVICE_MAP = [
    # Apple ecosystem
    ("_apple-mobdev2",   "iPhone/iOS"),
    ("_apple-mobdev",    "iPhone/iOS"),
    ("_googlecast",      "Chromecast/Google"),
    ("_spotify-connect", "Spotify Device"),
    ("_homekit",         "HomeKit/Apple"),
    ("_smb",             "macOS / Samba"),
    ("_afp",             "macOS"),
    ("_ssh._tcp",        "macOS / Linux SSH"),
    ("_rdp",             "Windows RDP"),

    # Google / Android
    ("_googlecast",      "Chromecast / Google TV"),
    ("_googlerpc",       "Android / Google"),
    ("_androidtvremote", "Android TV"),
    ("_googlezone",      "Google Nest Hub"),

    # Amazon
    ("_amzn-wplay",      "Amazon Echo / Fire TV"),
    ("_amazon",          "Amazon Device"),

    # Sonos
    ("_sonos",           "Sonos Speaker"),

    # Roku
    ("_roku",            "Roku Device"),

    # Microsoft / Windows
    ("_smb._tcp",        "Windows / Samba"),
    ("_microsoft-ds",    "Windows"),
    ("_nvstream",        "NVIDIA Shield / GeForce"),

    # Printers
    ("_ipp",             "Printer (IPP)"),
    ("_pdl-datastream",  "Printer (HP JetDirect)"),
    ("_printer",         "Printer"),

    # NAS / servers
    ("_nfs",             "NAS / Linux Server"),
    ("_ftp",             "FTP Server"),
    ("_http._tcp",       "Web Server / IoT"),

    # Smart home / IoT
    ("_hap",             "HomeKit Accessory"),
    ("_matter",          "Matter IoT Device"),
    ("_miio",            "Xiaomi Mi Device"),
    ("_tuya",            "Tuya Smart Plug/Bulb"),
    ("_philipshue",      "Philips Hue"),
    ("_elg",             "Elgato Device"),
    ("_espressif",       "ESP8266/ESP32 IoT"),
    ("_wyze",            "Wyze Camera"),
    ("_lg",              "LG Smart TV"),
    ("_samsung",         "Samsung Smart TV"),

    # Generic
    ("_workstation",     "Linux Workstation (Avahi)"),
    ("_device-info",     "Apple / Generic Device"),
]


def sniff_mdns_name(pkt, callback):
    """
    Analyses a single mDNS packet and fires callback(ip, name, os_class).

    name     — device hostname extracted from .local query (can be None)
    os_class — device-class label from service type (can be None)
    """
    if not pkt.haslayer(DNS):
        return

    ip = pkt[IP].src if pkt.haslayer(IP) else None
    if not ip:
        return

    dns = pkt.getlayer(DNS)

    # ── Scan question records (QD) ──────────────────────────────────────────
    for i in range(dns.qdcount or 0):
        try:
            qname_raw = dns.qd[i].qname.decode(errors="ignore").rstrip(".")
            qname = qname_raw.lower()

            # 1. Extract hostname from  <name>.local queries
            if ".local" in qname and not qname.startswith("_"):
                name = _sanitize(qname_raw)
                if name:
                    callback(ip, name, None)

            # 2. Extract device class from service-type strings
            for svc_key, label in _SERVICE_MAP:
                if svc_key in qname:
                    callback(ip, None, label)
                    break
        except Exception:
            pass

    # ── Scan answer records (AN / AR) — richer info in announcements ────────
    for section in (dns.an, dns.ar, dns.ns):
        record = section
        while record and record != 0:
            try:
                rname = getattr(record, "rrname", b"")
                if isinstance(rname, bytes):
                    rname = rname.decode(errors="ignore").rstrip(".")
                rname_l = rname.lower()

                # Hostname from PTR / A record names
                if ".local" in rname_l and not rname_l.startswith("_"):
                    name = _sanitize(rname)
                    if name:
                        callback(ip, name, None)

                # Service class from service record name
                for svc_key, label in _SERVICE_MAP:
                    if svc_key in rname_l:
                        callback(ip, None, label)
                        break

                # TXT records sometimes contain model / OS info
                rdata = getattr(record, "rdata", b"")
                if isinstance(rdata, bytes):
                    txt = rdata.decode(errors="ignore").lower()
                    if "model=iphone" in txt or "model=ipad" in txt:
                        callback(ip, None, "iPhone/iPad")
                    elif "model=appletv" in txt:
                        callback(ip, None, "Apple TV")
                    elif "model=macbook" in txt or "model=imac" in txt or "model=mac" in txt:
                        callback(ip, None, "Mac")

                record = record.payload if hasattr(record, "payload") else None
                if record and not hasattr(record, "rrname"):
                    break
            except Exception:
                break
