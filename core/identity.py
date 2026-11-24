"""
core/identity.py — Device identity: name/vendor sanitization + classification.

Split out of core/persistence.py, which had grown to ~1200 lines by carrying
this whole identity engine alongside the sqlite store. This is pure logic (no
storage, no I/O): it turns raw mDNS/DHCP/UPnP/recon signals into a clean,
confidence-scored device label. Imports only stdlib + core.netutil, so it stays
a leaf in the `core` layer.
"""

from __future__ import annotations

import re as _re

from core.netutil import randomized_mac

# Vendor categories for classify_device
MOBILE_VENDORS = {
    "Apple",
    "Samsung",
    "Huawei",
    "Xiaomi",
    "LG",
    "Sony",
    "Nokia",
    "OnePlus",
    "Oppo",
    "Vivo",
    "Motorola",
    "HTC",
    "ZTE",
    "Realme",
}
ROUTER_VENDORS = {
    "Cisco",
    "TP-Link",
    "Netgear",
    "Asus",
    "D-Link",
    "Linksys",
    "Ubiquiti",
    "MikroTik",
    "Juniper",
    "Huawei",
    "Zyxel",
    "Aruba",
    "Ruckus",
    "Meraki",
}
VM_VENDORS = {"VMware", "VirtualBox", "QEMU/KVM", "Parallels", "Xen"}


def is_stealth_mac(mac: str) -> bool:
    """Checks if a MAC address is locally administered (randomized)."""
    return randomized_mac(mac)


# ── OS keyword → device type label ────────────────────────────────────────────
_OS_TYPE_MAP = [
    (["windows 11", "windows 10", "windows 7", "windows xp", "windows server"], "PC/Windows"),
    (["linux", "ubuntu", "debian", "fedora", "centos", "arch"], "Linux PC"),
    (["macos", "mac os", "os x"], "Mac"),
    (["android"], "Android"),
    (["ios", "iphone", "ipad"], "iOS Device"),
    (["router", "routeros", "dd-wrt", "openwrt", "pfsense", "vyos"], "Router"),
    (["printer", "jetdirect"], "Printer"),
    (["freebsd", "openbsd", "netbsd"], "BSD Server"),
    (["nas", "synology", "qnap"], "NAS"),
]
_PC_PORTS = {135, 139, 445, 3389, 22, 5900}
_SERVER_PORTS = {21, 25, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017}
_IOT_PORTS = {1883, 8883, 5683}
_MEDIA_PORTS = {8008, 8009, 8060, 9080}
_PRINT_PORTS = {515, 631, 9100}


# ── Protocol noise patterns to strip from mDNS / Bonjour names ────────────────
_MDNS_NOISE = _re.compile(
    r"[._]("
    r"_airplay|_raop|_apple-mobdev2?|_googlecast|_spotify-connect|"
    r"_homekit|_smb|_afp|_ssh|_rdp|_googlerpc|_androidtvremote|"
    r"_googlezone|_amzn-wplay|_amazon|_sonos|_roku|_microsoft-ds|"
    r"_nvstream|_ipp|_pdl-datastream|_printer|_nfs|_ftp|_http|"
    r"_hap|_matter|_miio|_tuya|_philipshue|_elg|_espressif|_wyze|"
    r"_lg|_samsung|_workstation|_device-info|_tcp|_udp"
    r").*",
    _re.IGNORECASE,
)

# Obscure OUI vendor strings that should NOT be used as identity labels
# NOTE: Must NOT match well-known brands (Samsung, LG, Sony, Apple, etc.)
_JUNK_VENDORS = _re.compile(
    r"(sichuan|shenzhen|guangdong|jiangsu|zhejiang|beijing|shanghai|"
    r"dongguan|hangzhou|chongqing|private mac|technology co\.|"
    r"communications co\.|semiconductor|chipset|"
    r"ieee registration|hon hai|foxconn|quanta|pegatron|wistron|"
    r"liteon|azurewave|murata|mitsumi|rivet networks|"
    r"routerboard|ai-link|espressif inc|tuya inc|"
    r"realtek semi|mediatek|qualcomm|broadcom|marvell|ralink)",
    _re.IGNORECASE,
)


def _strip_noise_tokens(s: str) -> str:
    """Remove protocol suffixes and transport labels from discovered names."""
    s = s.strip().strip("\x00").strip()
    s = s.replace("\\032", " ")
    s = s.replace("%20", " ")
    s = _MDNS_NOISE.sub("", s)
    s = _re.sub(r"\.(local|lan|home|arpa)$", "", s, flags=_re.IGNORECASE)
    s = _re.sub(r"\._[a-z0-9-]+$", "", s, flags=_re.IGNORECASE)
    s = s.rstrip("._- ")
    return " ".join(s.split())


def _looks_like_windows_host(s: str) -> bool:
    return bool(_re.match(r"^(DESKTOP|LAPTOP|PC|WIN|SERVER)-[A-Z0-9]{3,}$", s, _re.IGNORECASE))


def _looks_like_noise_id(s: str) -> bool:
    return bool(
        _re.match(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", s, _re.IGNORECASE)
        or _re.match(r"^[0-9a-f]{8,}$", s, _re.IGNORECASE)
    )


def _smart_title(s: str) -> str:
    """Human-friendly casing without mangling common device model names."""
    if not s:
        return ""
    if _looks_like_windows_host(s):
        return s.upper()
    if s.isupper() and len(s) <= 18:
        return s

    replacements = {
        "iphone": "iPhone",
        "ipad": "iPad",
        "ipod": "iPod",
        "macbook": "MacBook",
        "imac": "iMac",
        "macmini": "Mac mini",
        "appletv": "Apple TV",
        "chromecast": "Chromecast",
        "androidtv": "Android TV",
        "playstation": "PlayStation",
        "raspberrypi": "Raspberry Pi",
    }

    words = []
    for word in s.split():
        key = _re.sub(r"[^a-z0-9]", "", word.lower())
        if key in replacements:
            words.append(replacements[key])
        elif word.islower() and len(word) > 2:
            words.append(word[:1].upper() + word[1:])
        else:
            words.append(word)
    return " ".join(words)


def sanitize_mdns_name(raw: str) -> str:
    """
    Strips mDNS/Bonjour protocol noise from a hostname.

    "Iheb's-iPhone._apple-mobdev2._tcp.local" → "Iheb's iPhone"
    "_airplay._tcp.local"                     → ""  (pure noise)
    "DESKTOP-AB12CD.local"                    → "DESKTOP-AB12CD"
    """
    if not raw:
        return ""

    s = raw.strip().rstrip(".")

    # Remove .local suffix
    if s.lower().endswith(".local"):
        s = s[:-6]

    # If the entire string starts with underscore, it's pure service noise
    if s.startswith("_"):
        return ""

    # Strip everything from the first service-type token onward.
    s = _strip_noise_tokens(s)

    # Replace hyphens with spaces for readability
    # but keep common patterns like "DESKTOP-XXXXX" intact
    if not _looks_like_windows_host(s):
        s = s.replace("-", " ")

    # Collapse whitespace
    s = " ".join(s.split())

    s = s.strip()
    if _looks_like_noise_id(s):
        return ""
    return _smart_title(s)


def sanitize_vendor(vendor: str) -> str:
    """
    Cleans obscure OUI vendor strings into useful labels or empty string.

    "Sichuan AI-Link Technology Co.,Ltd." → ""  (junk, let other sources name it)
    "Apple, Inc."                         → "Apple"
    "Samsung Electronics Co.,Ltd."        → "Samsung"
    """
    if not vendor:
        return ""
    if vendor.strip().lower() in (
        "unknown",
        "unknown device",
        "private mac",
        "[private_mac]",
        "🎭 [private_mac]",
    ):
        return ""

    # If it matches junk patterns, discard it entirely
    if _JUNK_VENDORS.search(vendor):
        return ""

    alias = {
        "apple": "Apple",
        "samsung": "Samsung",
        "google": "Google",
        "amazon": "Amazon",
        "microsoft": "Microsoft",
        "lg": "LG",
        "sony": "Sony",
        "xiaomi": "Xiaomi",
        "huawei": "Huawei",
        "raspberry pi": "Raspberry Pi",
        "dell": "Dell",
        "hewlett packard": "HP",
        "hp inc": "HP",
        "tp-link": "TP-Link",
        "tplink": "TP-Link",
        "asustek": "Asus",
        "asus": "Asus",
        "netgear": "Netgear",
        "roku": "Roku",
        "nintendo": "Nintendo",
        "ubiquiti": "Ubiquiti",
        "mikrotik": "MikroTik",
        "synology": "Synology",
        "qnap": "QNAP",
    }
    low_vendor = vendor.lower()
    for key, value in alias.items():
        if key in low_vendor:
            return value

    # Clean up common suffixes. Repeat because vendor strings often stack them.
    clean = vendor
    suffixes = [
        ", Inc.",
        ", Inc",
        " Inc.",
        " Inc",
        " LLC",
        ", LLC",
        " Co.,Ltd.",
        " Co.,Ltd",
        " Co., Ltd.",
        " Co., Ltd",
        " Corporation",
        " Corp.",
        " Corp",
        " Ltd.",
        " Ltd",
        " Limited",
        " Electronics",
        " Electric",
        " International",
        " Group",
        " Technology",
        " Technologies",
    ]
    changed = True
    while changed:
        changed = False
        for suffix in suffixes:
            if clean.endswith(suffix):
                clean = clean[: -len(suffix)].strip()
                changed = True

    return clean.strip()


def _is_junk_hostname(name: str) -> bool:
    """Returns True if the hostname is pure protocol noise, not a real name."""
    if not name:
        return True
    low = name.lower().strip()
    # Pure service-type strings
    if low.startswith("_"):
        return True
    # Extremely short or generic
    if low in ("localhost", "unknown", "unknown device", "?", "-", "generic device", "upnp"):
        return True
    # IP-address-only
    if _re.match(r"^\d+\.\d+\.\d+\.\d+$", low):
        return True
    if _looks_like_noise_id(low):
        return True
    if low in ("unix", "upnp device"):
        return True
    # UUID / long hex blob — a UPnP UDN or Cast GUID, not a human name, e.g.
    # "6dd60a51 4531 c5bb bdf8 5f6283e45d04" (sanitiser turns dashes to spaces).
    if _re.fullmatch(
        r"[0-9a-f]{8}[\s-][0-9a-f]{4}[\s-][0-9a-f]{4}[\s-][0-9a-f]{4}[\s-][0-9a-f]{12}", low
    ):
        return True
    # A bare 32-hex blob with no separators (same UDN without grouping).
    if _re.fullmatch(r"[0-9a-f]{32}", low):
        return True
    return False


# Identity labels that are placeholders, not a real device class — they must
# never bury a real hostname in the device-name column.
_PLACEHOLDER_IDENTITIES = frozenset(
    {"", "?", "-", "unknown", "unknown device", "❓ scanning...", "scanning...", "generic device"}
)


def display_name(nickname: str, hostname: str, identity: str, vendor: str = "") -> str:
    """Best human label for a device row — most device-identifying first.

    A user nickname wins; then the real hostname (mDNS/DHCP/friendly service name)
    — this is what tells devices apart, so it must beat the generic class label;
    then the ``classify_device`` label ("Windows System") as a fallback; then the
    vendor; else a placeholder. Junk hostnames (UUIDs, protocol noise) and
    placeholder/"Scanning…" identities are skipped so they never win over a real
    name. The IP/MAC columns remain the unique key; this is only the label.
    """
    nickname = (nickname or "").strip()
    if nickname:
        return nickname
    hostname = (hostname or "").strip()
    if hostname and not _is_junk_hostname(hostname):
        return hostname
    identity = (identity or "").strip()
    if identity and identity.lower() not in _PLACEHOLDER_IDENTITIES:
        return identity
    vendor = (vendor or "").strip()
    if vendor:
        return vendor
    return identity or "?"  # last resort: a placeholder like "❓ Scanning…", or "?"


# Service types whose *instance* label is an app/generic name rather than a
# device identity: it collides across devices (every Spotify client advertises
# "Spotify Desktop"), so its instance must never be used as a hostname.
_NON_IDENTIFYING_SERVICES = ("_spotify-connect", "_spotify")


def is_identifying_mdns_name(raw: str) -> bool:
    """True if an mDNS record name is usable as a *device* label.

    Accepts:
      - a bare ``<host>.local`` A/AAAA record (``Johns-Laptop.local``), and
      - a service-*instance* name whose service identifies the device — the
        friendly name its owner set. For cast / AirPlay / Sonos / HomeKit that
        instance is the ONLY place the name is published (the A-record is an
        opaque GUID), e.g. ``Living Room TV._googlecast._tcp.local`` →
        "Living Room TV", ``Office Sonos._sonos._tcp.local`` → "Office Sonos".
    Rejects:
      - pure service-type records (``_spotify-connect._tcp.local``), and
      - instances of app/generic services (``Spotify Desktop._spotify-connect.
        _tcp.local``) whose label collides across devices and names no device.

    ``sanitize_mdns_name`` extracts the friendly label; downstream
    ``_is_junk_hostname`` still drops opaque/noise labels. Gate every
    mDNS-derived hostname on this.
    """
    if not raw:
        return False
    s = raw.strip().rstrip(".").lower()
    if not s.endswith(".local"):
        return False
    s = s[:-6]  # drop the ".local" suffix
    if not s or s.startswith("_"):
        return False  # empty or a pure service-type record
    if "._tcp" in s or "._udp" in s:  # a service-instance name
        return not any(svc in s for svc in _NON_IDENTIFYING_SERVICES)
    return "." not in s  # a bare single-label host record


def _clean_identity_candidate(label: str) -> str:
    if not label:
        return ""
    label = sanitize_mdns_name(str(label))
    label = _re.sub(r"\s*\(\d+%\)\s*$", "", label).strip()
    label = _re.sub(r"\s+", " ", label).strip(" -_/")
    if _is_junk_hostname(label):
        return ""
    return _smart_title(label)


def _class_from_services(services: dict[int, str] | list | tuple | None) -> str:
    if not services:
        return ""
    items: list[tuple[int, str]] = []
    if isinstance(services, dict):
        items = list(services.items())
        ports = set(services.keys())
        text = " ".join(str(v) for v in services.values()).lower()
    else:
        ports = set()
        text = " ".join(str(v) for v in services).lower()

    if any(p in ports for p in _PRINT_PORTS) or "printer" in text or "ipp" in text:
        return "Printer"
    if 62078 in ports or "iphone" in text or "ipad" in text:
        return "Apple Mobile Device"
    if 445 in ports or 139 in ports or "microsoft-ds" in text or "netbios" in text:
        return "Windows / Samba Device"
    if 3389 in ports:
        return "Windows Remote Desktop"
    if 22 in ports and any(p in ports for p in _SERVER_PORTS):
        return "Linux / Server"
    if any(p in ports for p in _MEDIA_PORTS) or "googlecast" in text or "roku" in text:
        return "Media / Cast Device"
    if any(p in ports for p in _IOT_PORTS) or "mqtt" in text or "coap" in text:
        return "IoT Device"
    for port, svc in items:
        svc_l = str(svc).lower()
        if port in (80, 443, 8080, 8443) and any(
            x in svc_l for x in ("router", "gateway", "modem")
        ):
            return "Router / Gateway"
    return ""


def get_device_icon(identity: str, vendor: str, os_g: str) -> str:
    """Maps device identification to a visual category emoji."""
    id_lower = identity.lower()
    ven_lower = (vendor or "").lower()
    os_lower = (os_g or "").lower()

    if "apple" in id_lower or "iphone" in id_lower or "ipad" in id_lower:
        return "🍏"
    if "android" in id_lower or "mobile" in id_lower or "samsung" in id_lower:
        return "📱"
    if "galaxy" in id_lower or "pixel" in id_lower:
        return "📱"
    if (
        "windows" in id_lower
        or "pc" in id_lower
        or "workstation" in id_lower
        or "msi" in id_lower
        or "dell" in id_lower
    ):
        return "💻"
    if "desktop" in id_lower or "laptop" in id_lower:
        return "💻"
    if "router" in id_lower or "gateway" in id_lower or "modem" in id_lower:
        return "🌐"
    if "linux" in id_lower or "server" in id_lower:
        return "🐧"
    if "tv" in id_lower or "cast" in id_lower or "roku" in id_lower:
        return "📺"
    if "iot" in id_lower or "plug" in id_lower or "bulb" in id_lower:
        return "📡"
    if "echo" in id_lower or "alexa" in id_lower or "home" in id_lower:
        return "🔊"
    if "nintendo" in id_lower or "playstation" in id_lower or "xbox" in id_lower:
        return "🎮"
    if "camera" in id_lower or "cam" in id_lower:
        return "📹"
    if "printer" in id_lower:
        return "🖨️"

    # Fallback to vendor
    if "apple" in ven_lower:
        return "🍏"
    if "google" in ven_lower or "samsung" in ven_lower:
        return "📱"
    if "microsoft" in ven_lower:
        return "💻"

    # Fallback to OS guess
    if "ios" in os_lower or "iphone" in os_lower:
        return "🍏"
    if "android" in os_lower:
        return "📱"
    if "windows" in os_lower:
        return "💻"
    if "linux" in os_lower:
        return "🐧"
    if "mac" in os_lower:
        return "🍏"

    return "🔌"


def classify_device(dev) -> str:
    """
    Lanwarden Sovereign Identity Engine — Strict Confidence Scoring.

    Scoring tiers (highest wins, never overwritten by lower):
      100 — DHCP Option 12 self-reported hostname
       95 — UPnP <FriendlyName> from XML
       90 — Sanitized mDNS/Bonjour instance name
       80 — NetBIOS computer name
       70 — Passive DNS correlation / SSL CN
       60 — PTR record
       40 — TCP port-probe guess
       30 — MAC OUI vendor fallback (skip if private MAC)

    Returns: "[Emoji] CleanName"
    """
    # ── Nickname always wins ──
    if dev.nickname:
        dev.confidence = 100
        return f"👤 {dev.nickname}"

    vendor = sanitize_vendor(dev.vendor or "")
    ven_lower = vendor.lower()
    os_g = (dev.os_guess or "").lower()
    hn_raw = dev.hostname or ""
    recon = dev.recon_data or {}

    # Sanitize the hostname immediately
    hn = sanitize_mdns_name(hn_raw)

    # Candidates: list of (score, label) — we pick the highest
    candidates: list[tuple[int, str]] = []

    # ── Score 100: DHCP hostname (raw self-declaration) ──
    # DHCP hostnames are stored directly in dev.hostname by the DHCP sniffer.
    # They're typically clean strings like "Galaxy-S23" or "DESKTOP-IHEB".
    # We detect them by checking if the raw hostname has NO protocol noise.
    if hn and not _is_junk_hostname(hn) and hn not in ("YOU", "GATEWAY"):
        # If the raw hostname had no .local / no underscores, it's likely DHCP
        if "_" not in hn_raw and ".local" not in hn_raw.lower():
            candidates.append((100, _clean_identity_candidate(hn)))
        else:
            # It's an mDNS name — score 90 after sanitization
            if hn:
                candidates.append((90, _clean_identity_candidate(hn)))

    # ── Score 95: UPnP FriendlyName ──
    upnp = recon.get("upnp_model", "")
    if upnp and upnp.lower() not in ("upnp", "unknown", ""):
        candidates.append((95, _clean_identity_candidate(upnp)))

    # ── Score 80: NetBIOS computer name ──
    netbios = recon.get("netbios", "")
    if netbios and not _is_junk_hostname(netbios):
        candidates.append((80, _clean_identity_candidate(netbios)))

    # ── Score 70: SSL CN / Passive DNS ──
    ssl_cn = recon.get("ssl_cn", "")
    if ssl_cn and not _is_junk_hostname(ssl_cn):
        candidates.append((70, _clean_identity_candidate(ssl_cn)))

    dns_class = recon.get("dns_class", "")
    if dns_class:
        candidates.append((70, _clean_identity_candidate(dns_class)))

    # ── Score 60: PTR record ──
    ptr = recon.get("ptr_name", "")
    if ptr and not _is_junk_hostname(ptr):
        # Sanitize PTR too (often has .local or ISP noise)
        ptr_clean = sanitize_mdns_name(ptr)
        if ptr_clean:
            candidates.append((60, _clean_identity_candidate(ptr_clean)))

    # ── Score 65: OS fingerprint ──
    for keys, label in _OS_TYPE_MAP:
        if any(k in os_g for k in keys):
            candidates.append((65, label))
            break

    # ── Score 55: Service / open-port signature ──
    svc_label = _class_from_services(getattr(dev, "services", None))
    if svc_label:
        candidates.append((55, svc_label))

    ports = set(getattr(dev, "open_ports", []) or [])
    if ports:
        if ports & _PRINT_PORTS:
            candidates.append((50, "Printer"))
        elif ports & _IOT_PORTS:
            candidates.append((45, "IoT Device"))
        elif ports & _PC_PORTS:
            candidates.append((45, "Computer / Workstation"))
        elif ports & _SERVER_PORTS:
            candidates.append((42, "Server / Web Device"))

    # ── Score 50: Vendor-specific known labels ──
    if "dell" in ven_lower:
        candidates.append((50, "Dell Machine"))
    elif "msi" in ven_lower or "micro-star" in ven_lower:
        candidates.append((50, "MSI Gaming PC"))
    elif "raspberry" in ven_lower:
        candidates.append((50, "Raspberry Pi"))

    # ── Score 40: TCP TTL fingerprinting ──
    if dev.tcp_ttl > 0:
        ttl = dev.tcp_ttl
        if ttl >= 120:
            candidates.append((40, "Windows System"))
        elif ttl <= 64:
            candidates.append((40, "Linux/Mobile Node"))
        elif 65 <= ttl <= 128:
            candidates.append((40, "Network Infrastructure"))

    # ── Score 30: Vendor fallback (ONLY if not private/randomized MAC) ──
    if vendor and not is_stealth_mac(dev.mac):
        candidates.append((30, vendor))

    # ── Score 20: Privacy MAC / reachable fallback ──
    if not candidates and is_stealth_mac(dev.mac):
        candidates.append((20, "Private Device"))

    # ── Pick the winner ──
    if candidates:
        candidates = [(s, c) for s, c in candidates if c and not _is_junk_hostname(c)]
        candidates.sort(key=lambda x: x[0], reverse=True)
    if candidates:
        score, dtype = candidates[0]
    else:
        score, dtype = 0, ""

    dev.confidence = score
    icon = get_device_icon(dtype or "", vendor or "", os_g or "")

    if not dtype or dtype == "Unknown" or _is_junk_hostname(dtype):
        return "❓ Scanning..."

    return f"{icon} {dtype}"
