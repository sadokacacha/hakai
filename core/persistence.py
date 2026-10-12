"""
core/persistence.py — Config, state, nicknames, OUI DB, format helpers.
All data stored in ~/.sadok_hakai/
"""
from __future__ import annotations

import json
from pathlib import Path

# ── Storage paths ──────────────────────────────────────────────────────────────
CONFIG_DIR  = Path.home() / ".sadok_hakai"
CONFIG_FILE = CONFIG_DIR / "config.json"
STATE_FILE  = CONFIG_DIR / "state.json"
NICK_FILE   = CONFIG_DIR / "nicknames.json"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_CFG: dict = {
    "iface":            "auto",
    "gateway":          "",
    "scan_timeout":     45,
    "refresh_ms":       1200,
    "default_limit_kb": 500,
    "arp_interval":     0.3,
    "watchdog_interval":0.5,
}

def _load(path: Path, default):
    try:
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return default

def _save(path: Path, data):
    try:
        path.write_text(json.dumps(data, indent=2))
    except Exception:
        pass

class Persistence:
    def __init__(self):
        self.cfg       = _load(CONFIG_FILE, dict(DEFAULT_CFG))
        self.nicknames = _load(NICK_FILE,   {})
        self.state     = _load(STATE_FILE,  {})

    def save_config(self, iface: str = "", gateway: str = ""):
        if iface:   self.cfg["iface"]   = iface
        if gateway: self.cfg["gateway"] = gateway
        _save(CONFIG_FILE, self.cfg)

    def save_state(self, devices: dict):
        data = {ip: dev.to_state() for ip, dev in devices.items()}
        _save(STATE_FILE, data)

    def get_nickname(self, mac: str) -> str:
        return self.nicknames.get(mac, "")

    def set_nickname(self, mac: str, name: str):
        self.nicknames[mac] = name
        _save(NICK_FILE, self.nicknames)

    def get(self, key: str, default=None):
        return self.cfg.get(key, DEFAULT_CFG.get(key, default))

# Global singleton
db = Persistence()

# ── Format helpers ─────────────────────────────────────────────────────────────
def fmt_speed(bps: float) -> str:
    if bps <= 0:      return "0 B/s"
    if bps < 1024:    return f"{bps:.0f} B/s"
    if bps < 1048576: return f"{bps/1024:.1f} KB/s"
    return f"{bps/1048576:.2f} MB/s"

def fmt_mbps(mbps: float) -> str:
    if mbps <= 0:   return "0.00 Mbps"
    if mbps < 1.0:  return f"{mbps * 1000:.0f} Kbps"
    return f"{mbps:.2f} Mbps"


def fmt_total(b: int) -> str:
    if b <= 0:            return "0 B"
    if b < 1024:          return f"{b} B"
    if b < 1048576:       return f"{b/1024:.1f} KB"
    if b < 1073741824:    return f"{b/1048576:.1f} MB"
    return f"{b/1073741824:.2f} GB"

# ── OUI Database (35 k+ prefix-to-vendor) ─────────────────────────────────────
# First try mac-vendor-lookup library (most complete). Fall back to the
# static dict below.
try:
    from mac_vendor_lookup import MacLookup as _MacLookupCls
    _mlookup = _MacLookupCls()
    _MAC_VENDOR_LIB = True
except ImportError:
    _mlookup = None
    _MAC_VENDOR_LIB = False

# Static fallback dict (top vendors — good enough without the library)
_OUI_DB: dict[str, str] = {
    # Virtualisation
    "00:50:56":"VMware","00:0C:29":"VMware","00:1C:42":"Parallels",
    "08:00:27":"VirtualBox","52:54:00":"QEMU/KVM","00:16:3E":"Xen",
    # Apple
    "AC:BC:32":"Apple","F8:FF:C2":"Apple","00:1B:63":"Apple",
    "3C:07:54":"Apple","A4:C3:F0":"Apple","DC:A9:04":"Apple",
    "04:15:52":"Apple","04:69:F8":"Apple","0C:74:C2":"Apple",
    "18:65:90":"Apple","1C:1A:C0":"Apple","34:15:9E":"Apple",
    "60:69:44":"Apple","70:14:A6":"Apple","80:00:6E":"Apple",
    "A8:66:7F":"Apple","B4:18:D1":"Apple","D8:00:4D":"Apple",
    "F4:37:B7":"Apple","FC:FC:48":"Apple",
    # Samsung
    "FC:AA:14":"Samsung","00:12:FB":"Samsung","18:3A:2D":"Samsung",
    "34:23:87":"Samsung","50:01:BB":"Samsung","78:1F:DB":"Samsung",
    "9C:02:98":"Samsung","B0:47:BF":"Samsung","D0:22:BE":"Samsung",
    "E0:99:71":"Samsung","F4:42:8F":"Samsung",
    # Huawei
    "00:18:82":"Huawei","04:02:1F":"Huawei","18:C5:8A":"Huawei",
    "28:31:52":"Huawei","40:4D:8E":"Huawei","68:A8:28":"Huawei",
    "90:67:1C":"Huawei","B8:BC:1B":"Huawei","DC:D2:FC":"Huawei",
    # Dell
    "00:14:22":"Dell","F8:DB:88":"Dell","18:66:DA":"Dell",
    "28:F1:0E":"Dell","4C:ED:FB":"Dell","78:2B:CB":"Dell",
    "B8:AC:6F":"Dell","F4:8E:38":"Dell",
    # HP
    "3C:D9:2B":"HP","E0:CB:4E":"HP","24:BE:05":"HP",
    "54:E1:AD":"HP","88:51:FB":"HP","BC:EA:FA":"HP",
    # Intel
    "8C:8D:28":"Intel","00:1A:4B":"Intel","00:23:14":"Intel",
    "18:5E:0F":"Intel","48:2C:6A":"Intel","64:5D:86":"Intel",
    "80:86:F2":"Intel","9C:4E:36":"Intel","B8:8A:60":"Intel",
    # Microsoft
    "00:15:5D":"Microsoft","28:18:78":"Microsoft","DC:46:28":"Microsoft",
    # Raspberry Pi
    "28:D2:44":"Raspberry Pi","B8:27:EB":"Raspberry Pi",
    "DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    # TP-Link
    "00:13:77":"TP-Link","54:AF:97":"TP-Link","98:DA:C4":"TP-Link",
    "50:C7:BF":"TP-Link","64:70:02":"TP-Link","B4:B0:24":"TP-Link",
    "DC:FE:18":"TP-Link","F4:F2:6D":"TP-Link",
    # Cisco
    "00:18:E7":"Cisco","00:1A:A2":"Cisco","E0:2F:6D":"Cisco",
    "00:00:0C":"Cisco","58:AC:78":"Cisco","68:EF:BD":"Cisco",
    # Asus
    "C4:AD:34":"Asus","10:BF:48":"Asus","50:EB:71":"Asus",
    "14:DA:E9":"Asus","90:E6:BA":"Asus","DC:9F:DB":"Asus",
    # Netgear
    "A0:21:B7":"Netgear","20:4E:7F":"Netgear","84:1B:5E":"Netgear",
    # Xiaomi
    "58:6D:8F":"Xiaomi","64:09:80":"Xiaomi","F4:8E:92":"Xiaomi",
    "68:DF:DD":"Xiaomi","B0:E2:35":"Xiaomi",
    # Amazon
    "B0:BE:76":"Amazon","44:65:0D":"Amazon","FC:65:DE":"Amazon",
    "40:B4:CD":"Amazon","AC:63:BE":"Amazon","F0:27:2D":"Amazon",
    # Google / Nest
    "68:A4:0E":"Google","54:60:09":"Google","F4:F5:D8":"Google",
    "70:3A:CB":"Google","B4:CE:F6":"Google","F8:8F:CA":"Google",
    # Roku
    "00:1D:72":"Roku","B8:3E:59":"Roku","CC:6D:A0":"Roku",
    # LG
    "00:1E:75":"LG","40:B8:37":"LG","78:5D:C8":"LG","E8:5B:5B":"LG",
    # Sony
    "00:01:4A":"Sony","28:0D:FC":"Sony","84:C7:EA":"Sony","CC:F9:57":"Sony",
    # Nintendo
    "00:09:BF":"Nintendo","40:F4:07":"Nintendo","9C:E6:35":"Nintendo",
    # Lenovo
    "20:7C:8F":"Lenovo","40:8D:5C":"Lenovo","88:70:8C":"Lenovo",
    # Realtek
    "00:E0:4C":"Realtek","00:0B:6C":"Realtek",
}

# Vendor categories for classify_device
MOBILE_VENDORS  = {"Apple","Samsung","Huawei","Xiaomi","LG","Sony","Nokia",
                   "OnePlus","Oppo","Vivo","Motorola","HTC","ZTE","Realme"}
ROUTER_VENDORS  = {"Cisco","TP-Link","Netgear","Asus","D-Link","Linksys",
                   "Ubiquiti","MikroTik","Juniper","Huawei","Zyxel","Aruba",
                   "Ruckus","Meraki"}
VM_VENDORS      = {"VMware","VirtualBox","QEMU/KVM","Parallels","Xen"}

def is_private_mac(mac: str) -> bool:
    """Detects if a MAC is randomized/private (Locally Administered bit set)."""
    if len(mac) < 2: return False
    # Second hex character: 2, 6, A, or E
    return mac[1].upper() in ("2", "6", "A", "E")

def lookup_oui(mac: str) -> str:
    if not mac:
        return ""

    if _MAC_VENDOR_LIB and _mlookup is not None:
        try:
            return _mlookup.lookup(mac)
        except Exception:
            pass

    # Local static fallback only. The previous online lookup
    # (https://api.macvendors.com) was removed: it leaked every LAN MAC to a
    # third party and blocked the calling thread for up to 2 s per unknown
    # device — and lookup_oui runs on the scan hot path and in Device.__init__.
    return _OUI_DB.get(mac.upper()[:8], "")

def sync_vendor_db_bg():
    """Call in a daemon thread — refreshes mac-vendor-lookup OUI DB from the internet."""
    if _MAC_VENDOR_LIB and _mlookup is not None:
        try:
            _mlookup.update_vendors()
        except Exception:
            pass

# ── OS keyword → device type label ────────────────────────────────────────────
_OS_TYPE_MAP = [
    (["windows 11","windows 10","windows 7","windows xp","windows server"], "PC/Windows"),
    (["linux","ubuntu","debian","fedora","centos","arch"],                  "Linux PC"),
    (["macos","mac os","os x"],                                             "Mac"),
    (["android"],                                                            "Android"),
    (["ios","iphone","ipad"],                                                "iOS Device"),
    (["router","routeros","dd-wrt","openwrt","pfsense","vyos"],             "Router"),
    (["printer","jetdirect"],                                                "Printer"),
    (["freebsd","openbsd","netbsd"],                                         "BSD Server"),
    (["nas","synology","qnap"],                                              "NAS"),
]
_PC_PORTS     = {135, 139, 445, 3389, 22, 5900}
_SERVER_PORTS = {21, 25, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017}
_IOT_PORTS    = {1883, 8883, 5683}
_MEDIA_PORTS  = {8008, 8009, 8060, 9080}
_PRINT_PORTS  = {515, 631, 9100}

def is_stealth_mac(mac: str) -> bool:
    """Checks if a MAC address is locally administered (randomized)."""
    if not mac or len(mac) < 2: return False
    return mac[1].upper() in ("2", "6", "A", "E")

# ── Protocol noise patterns to strip from mDNS / Bonjour names ────────────────
import re as _re

_MDNS_NOISE = _re.compile(
    r'[._]('
    r'_airplay|_raop|_apple-mobdev2?|_googlecast|_spotify-connect|'
    r'_homekit|_smb|_afp|_ssh|_rdp|_googlerpc|_androidtvremote|'
    r'_googlezone|_amzn-wplay|_amazon|_sonos|_roku|_microsoft-ds|'
    r'_nvstream|_ipp|_pdl-datastream|_printer|_nfs|_ftp|_http|'
    r'_hap|_matter|_miio|_tuya|_philipshue|_elg|_espressif|_wyze|'
    r'_lg|_samsung|_workstation|_device-info|_tcp|_udp'
    r').*',
    _re.IGNORECASE
)

# Obscure OUI vendor strings that should NOT be used as identity labels
# NOTE: Must NOT match well-known brands (Samsung, LG, Sony, Apple, etc.)
_JUNK_VENDORS = _re.compile(
    r'(sichuan|shenzhen|guangdong|jiangsu|zhejiang|beijing|shanghai|'
    r'dongguan|hangzhou|chongqing|private mac|technology co\.|'
    r'communications co\.|semiconductor|chipset|'
    r'ieee registration|hon hai|foxconn|quanta|pegatron|wistron|'
    r'liteon|azurewave|murata|mitsumi|rivet networks|'
    r'routerboard|ai-link|espressif inc|tuya inc|'
    r'realtek semi|mediatek|qualcomm|broadcom|marvell|ralink)',
    _re.IGNORECASE
)


def _strip_noise_tokens(s: str) -> str:
    """Remove protocol suffixes and transport labels from discovered names."""
    s = s.strip().strip("\x00").strip()
    s = s.replace("\\032", " ")
    s = s.replace("%20", " ")
    s = _MDNS_NOISE.sub("", s)
    s = _re.sub(r'\.(local|lan|home|arpa)$', "", s, flags=_re.IGNORECASE)
    s = _re.sub(r'\._[a-z0-9-]+$', "", s, flags=_re.IGNORECASE)
    s = s.rstrip("._- ")
    return " ".join(s.split())


def _looks_like_windows_host(s: str) -> bool:
    return bool(_re.match(r'^(DESKTOP|LAPTOP|PC|WIN|SERVER)-[A-Z0-9]{3,}$', s, _re.IGNORECASE))


def _looks_like_noise_id(s: str) -> bool:
    return bool(
        _re.match(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', s, _re.IGNORECASE)
        or _re.match(r'^[0-9a-f]{8,}$', s, _re.IGNORECASE)
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
        "iphone": "iPhone", "ipad": "iPad", "ipod": "iPod",
        "macbook": "MacBook", "imac": "iMac", "macmini": "Mac mini",
        "appletv": "Apple TV", "chromecast": "Chromecast",
        "androidtv": "Android TV", "playstation": "PlayStation",
        "raspberrypi": "Raspberry Pi",
    }

    words = []
    for word in s.split():
        key = _re.sub(r'[^a-z0-9]', "", word.lower())
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
    if vendor.strip().lower() in ("unknown", "unknown device", "private mac", "[private_mac]", "🎭 [private_mac]"):
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
    suffixes = [", Inc.", ", Inc", " Inc.", " Inc", " LLC", ", LLC",
                " Co.,Ltd.", " Co.,Ltd", " Co., Ltd.", " Co., Ltd",
                " Corporation", " Corp.", " Corp",
                " Ltd.", " Ltd", " Limited",
                " Electronics", " Electric",
                " International", " Group", " Technology", " Technologies"]
    changed = True
    while changed:
        changed = False
        for suffix in suffixes:
            if clean.endswith(suffix):
                clean = clean[:-len(suffix)].strip()
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
    if _re.match(r'^\d+\.\d+\.\d+\.\d+$', low):
        return True
    if _looks_like_noise_id(low):
        return True
    if low in ("unix", "upnp device"):
        return True
    return False


def _clean_identity_candidate(label: str) -> str:
    if not label:
        return ""
    label = sanitize_mdns_name(str(label))
    label = _re.sub(r'\s*\(\d+%\)\s*$', "", label).strip()
    label = _re.sub(r'\s+', " ", label).strip(" -_/")
    if _is_junk_hostname(label):
        return ""
    return _smart_title(label)


def _class_from_services(services: dict[int, str] | list | tuple | None) -> str:
    if not services:
        return ""
    if isinstance(services, dict):
        items = services.items()
        ports = set(services.keys())
        text = " ".join(str(v) for v in services.values()).lower()
    else:
        ports = set()
        text = " ".join(str(v) for v in services).lower()
        items = []

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
        if port in (80, 443, 8080, 8443) and any(x in svc_l for x in ("router", "gateway", "modem")):
            return "Router / Gateway"
    return ""


def get_device_icon(identity: str, vendor: str, os_g: str) -> str:
    """Maps device identification to a visual category emoji."""
    id_lower = identity.lower()
    ven_lower = (vendor or "").lower()
    os_lower = (os_g or "").lower()

    if "apple" in id_lower or "iphone" in id_lower or "ipad" in id_lower: return "🍏"
    if "android" in id_lower or "mobile" in id_lower or "samsung" in id_lower: return "📱"
    if "galaxy" in id_lower or "pixel" in id_lower: return "📱"
    if "windows" in id_lower or "pc" in id_lower or "workstation" in id_lower or "msi" in id_lower or "dell" in id_lower: return "💻"
    if "desktop" in id_lower or "laptop" in id_lower: return "💻"
    if "router" in id_lower or "gateway" in id_lower or "modem" in id_lower: return "🌐"
    if "linux" in id_lower or "server" in id_lower: return "🐧"
    if "tv" in id_lower or "cast" in id_lower or "roku" in id_lower: return "📺"
    if "iot" in id_lower or "plug" in id_lower or "bulb" in id_lower: return "📡"
    if "echo" in id_lower or "alexa" in id_lower or "home" in id_lower: return "🔊"
    if "nintendo" in id_lower or "playstation" in id_lower or "xbox" in id_lower: return "🎮"
    if "camera" in id_lower or "cam" in id_lower: return "📹"
    if "printer" in id_lower: return "🖨️"
    
    # Fallback to vendor
    if "apple" in ven_lower: return "🍏"
    if "google" in ven_lower or "samsung" in ven_lower: return "📱"
    if "microsoft" in ven_lower: return "💻"
    
    # Fallback to OS guess
    if "ios" in os_lower or "iphone" in os_lower: return "🍏"
    if "android" in os_lower: return "📱"
    if "windows" in os_lower: return "💻"
    if "linux" in os_lower: return "🐧"
    if "mac" in os_lower: return "🍏"
    
    return "🔌"


def classify_device(dev) -> str:
    """
    Hakai v3 Sovereign Identity Engine — Strict Confidence Scoring.
    
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

    vendor    = sanitize_vendor(dev.vendor or "")
    ven_lower = vendor.lower()
    os_g      = (dev.os_guess or "").lower()
    hn_raw    = dev.hostname or ""
    recon     = dev.recon_data or {}
    
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
        if ttl >= 120:         candidates.append((40, "Windows System"))
        elif ttl <= 64:        candidates.append((40, "Linux/Mobile Node"))
        elif 65 <= ttl <= 128: candidates.append((40, "Network Infrastructure"))
    
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

