"""
network/oui_lookup.py — Hardened OUI Database with Sovereign Fallback.
"""
from __future__ import annotations

# Sovereign Fallback: Common OUI prefixes
FALLBACK_OUI = {
    "00:03:93": "Apple Inc.", "00:05:02": "Apple Inc.", "00:0a:27": "Apple Inc.", 
    "00:0d:93": "Apple Inc.", "00:10:fa": "Apple Inc.", "00:16:cb": "Apple Inc.",
    "00:17:f2": "Apple Inc.", "00:19:e3": "Apple Inc.", "00:1c:b3": "Apple Inc.",
    "00:1d:4f": "Apple Inc.", "00:1e:52": "Apple Inc.", "00:1f:5b": "Apple Inc.",
    "00:21:e9": "Apple Inc.", "00:22:41": "Apple Inc.", "00:23:12": "Apple Inc.",
    "00:23:32": "Apple Inc.", "00:23:6c": "Apple Inc.", "00:24:36": "Apple Inc.",
    "00:25:00": "Apple Inc.", "00:25:4b": "Apple Inc.", "00:26:08": "Apple Inc.",
    "00:26:4a": "Apple Inc.", "00:26:b0": "Apple Inc.", "00:26:bb": "Apple Inc.",
    "28:cf:e9": "Apple Inc.", "34:15:9e": "Apple Inc.", "34:a3:95": "Apple Inc.",
    "40:a6:d9": "Apple Inc.", "44:d8:84": "Apple Inc.", "58:55:ca": "Apple Inc.",
    "60:c5:47": "Apple Inc.", "64:a3:cb": "Apple Inc.", "68:a8:6d": "Apple Inc.",
    "70:3e:ac": "Apple Inc.", "7c:d1:c3": "Apple Inc.", "80:ea:96": "Apple Inc.",
    "84:38:35": "Apple Inc.", "88:1f:a1": "Apple Inc.", "8c:2d:aa": "Apple Inc.",
    "90:72:40": "Apple Inc.", "90:b2:1f": "Apple Inc.", "a4:5e:60": "Apple Inc.",
    "b8:17:c2": "Apple Inc.", "c8:6f:1d": "Apple Inc.", "d4:9a:20": "Apple Inc.",
    "dc:2b:61": "Apple Inc.", "f0:d1:a9": "Apple Inc.", "f4:f1:5a": "Apple Inc.",
    "f8:27:93": "Apple Inc.", "fc:25:3f": "Apple Inc.",
    
    "00:15:99": "Samsung", "00:16:32": "Samsung", "00:17:d4": "Samsung",
    "00:1a:8a": "Samsung", "00:1b:98": "Samsung", "00:1c:43": "Samsung",
    "00:1d:25": "Samsung", "00:1e:7d": "Samsung", "1c:62:b8": "Samsung",
    "24:4b:03": "Samsung", "30:07:4d": "Samsung", "38:aa:3c": "Samsung",
    "40:f3:08": "Samsung", "48:44:f7": "Samsung", "50:85:69": "Samsung",
    "5c:a3:9d": "Samsung", "64:b3:10": "Samsung", "78:47:1d": "Samsung",
    "84:25:db": "Samsung", "8c:71:f4": "Samsung", "94:63:d1": "Samsung",
    "a4:70:d6": "Samsung", "b0:05:94": "Samsung", "c8:72:75": "Samsung",
    "d0:59:e4": "Samsung", "e4:12:1d": "Samsung", "f4:7b:5e": "Samsung",
    
    "00:03:ff": "Microsoft", "00:0d:3a": "Microsoft", "00:12:5a": "Microsoft",
    "00:15:5d": "Microsoft", "00:17:fa": "Microsoft", "00:22:48": "Microsoft",
    "00:25:ae": "Microsoft", "00:50:f2": "Microsoft", "28:18:78": "Microsoft",
    "30:59:b7": "Microsoft", "48:50:73": "Microsoft", "50:1a:c5": "Microsoft",
    "58:82:a8": "Microsoft", "60:45:bd": "Microsoft", "7c:1e:52": "Microsoft",
    "94:f6:65": "Microsoft", "a4:cf:99": "Microsoft", "b8:31:b5": "Microsoft",
    "c0:33:5e": "Microsoft", "dc:b3:19": "Microsoft", "f4:39:09": "Microsoft",

    "00:08:ca": "Intel", "00:13:e8": "Intel", "00:15:00": "Intel",
    "00:16:76": "Intel", "00:18:de": "Intel", "00:19:d1": "Intel",
    "00:1b:77": "Intel", "00:1c:bf": "Intel", "00:1d:e0": "Intel",
    "00:21:5c": "Intel", "00:21:6a": "Intel", "00:22:fb": "Intel",
    "00:23:14": "Intel", "00:24:d6": "Intel", "00:24:d7": "Intel",
    "34:13:e8": "Intel", "48:45:20": "Intel", "64:4b:f0": "Intel",
    "68:5d:43": "Intel", "80:00:0b": "Intel", "88:53:2e": "Intel",
    "a4:17:31": "Intel", "b4:b6:86": "Intel", "c8:5b:76": "Intel",
    "d4:3d:7e": "Intel", "f4:8c:50": "Intel",
    
    "00:22:6b": "Huawei", "00:25:9e": "Huawei", "0c:37:dc": "Huawei",
    "24:db:ac": "Huawei", "28:31:52": "Huawei", "34:6b:d3": "Huawei",
    "40:4d:8e": "Huawei", "4c:8b:ef": "Huawei", "54:89:98": "Huawei",
    "64:16:f0": "Huawei", "78:1d:4a": "Huawei", "80:38:bc": "Huawei",
    "88:53:d4": "Huawei", "9c:28:bf": "Huawei", "ac:e8:7b": "Huawei",
    "bc:76:70": "Huawei", "cc:96:a0": "Huawei", "e0:24:7f": "Huawei",
}

try:
    from ouilookup import OuiLookup
    _OUI_LOADED = True
except ImportError:
    _OUI_LOADED = False

def is_randomized(mac: str) -> bool:
    """Checks the Locally Administered bit (second character of MAC)."""
    if len(mac) < 2: return False
    return mac[1].upper() in ['2', '6', 'A', 'E']

def get_vendor(mac: str) -> str:
    """
    Identifies manufacturer with multiple fallbacks and Privacy-Bit check.
    """
    mac = mac.replace("-", ":").lower()
    
    # 1. Fallback Dictionary check
    prefix = ":".join(mac.split(":")[:3])
    if prefix in FALLBACK_OUI:
        return FALLBACK_OUI[prefix]

    # 2. Library check
    if _OUI_LOADED:
        try:
            res = OuiLookup().query(mac)
            for entry in res:
                for m, vendor in entry.items():
                    if vendor: return vendor
        except Exception: pass
    
    # 3. Privacy-Bit Check
    if is_randomized(mac):
        return "🎭 [PRIVATE_MAC]"
        
    return "Unknown Device"
