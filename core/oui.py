"""
core/oui.py — MAC OUI → vendor lookup (static tables + optional library).

Split out of core/persistence.py: the storage module had no business carrying a
35 k-prefix vendor database. This stays in the `core` layer because core/device
and the scanner resolve vendors, and `core` must not import `network`.

Lookup order: the mac-vendor-lookup IEEE OUI table (~40 k prefixes) if its data
file has been downloaded, else the two static tables below. The previous online
lookup (api.macvendors.com) was removed — it leaked every LAN MAC to a third
party and blocked the calling thread for up to 2 s per unknown device, and lookup
runs on the scan hot path.

IMPORTANT: we do NOT call ``mac_vendor_lookup``'s own ``lookup()`` — it is async
(asyncio + aiofiles + a thread pool spun up per call) and, on a cache miss,
downloads from the IEEE site on the *calling* thread. That would block the UI/scan
thread for seconds on first use (or hang offline), and deadlocks under the
synchronous Thread test doubles. Instead the library is used only as a downloader
(``sync_vendor_db_bg`` → ``update_vendors``), and we read its cached data file
(``PREFIX:Vendor`` lines) once, synchronously, into a plain dict for O(1) lookups.
"""

from __future__ import annotations

import logging
import os
import threading

_log = logging.getLogger(__name__)

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
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3E": "Xen",
    # Apple
    "AC:BC:32": "Apple",
    "F8:FF:C2": "Apple",
    "00:1B:63": "Apple",
    "3C:07:54": "Apple",
    "A4:C3:F0": "Apple",
    "DC:A9:04": "Apple",
    "04:15:52": "Apple",
    "04:69:F8": "Apple",
    "0C:74:C2": "Apple",
    "18:65:90": "Apple",
    "1C:1A:C0": "Apple",
    "34:15:9E": "Apple",
    "60:69:44": "Apple",
    "70:14:A6": "Apple",
    "80:00:6E": "Apple",
    "A8:66:7F": "Apple",
    "B4:18:D1": "Apple",
    "D8:00:4D": "Apple",
    "F4:37:B7": "Apple",
    "FC:FC:48": "Apple",
    # Samsung
    "FC:AA:14": "Samsung",
    "00:12:FB": "Samsung",
    "18:3A:2D": "Samsung",
    "34:23:87": "Samsung",
    "50:01:BB": "Samsung",
    "78:1F:DB": "Samsung",
    "9C:02:98": "Samsung",
    "B0:47:BF": "Samsung",
    "D0:22:BE": "Samsung",
    "E0:99:71": "Samsung",
    "F4:42:8F": "Samsung",
    # Huawei
    "00:18:82": "Huawei",
    "04:02:1F": "Huawei",
    "18:C5:8A": "Huawei",
    "28:31:52": "Huawei",
    "40:4D:8E": "Huawei",
    "68:A8:28": "Huawei",
    "90:67:1C": "Huawei",
    "B8:BC:1B": "Huawei",
    "DC:D2:FC": "Huawei",
    # Dell
    "00:14:22": "Dell",
    "F8:DB:88": "Dell",
    "18:66:DA": "Dell",
    "28:F1:0E": "Dell",
    "4C:ED:FB": "Dell",
    "78:2B:CB": "Dell",
    "B8:AC:6F": "Dell",
    "F4:8E:38": "Dell",
    # HP
    "3C:D9:2B": "HP",
    "E0:CB:4E": "HP",
    "24:BE:05": "HP",
    "54:E1:AD": "HP",
    "88:51:FB": "HP",
    "BC:EA:FA": "HP",
    # Intel
    "8C:8D:28": "Intel",
    "00:1A:4B": "Intel",
    "00:23:14": "Intel",
    "18:5E:0F": "Intel",
    "48:2C:6A": "Intel",
    "64:5D:86": "Intel",
    "80:86:F2": "Intel",
    "9C:4E:36": "Intel",
    "B8:8A:60": "Intel",
    # Microsoft
    "00:15:5D": "Microsoft",
    "28:18:78": "Microsoft",
    "DC:46:28": "Microsoft",
    # Raspberry Pi
    "28:D2:44": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # TP-Link
    "00:13:77": "TP-Link",
    "54:AF:97": "TP-Link",
    "98:DA:C4": "TP-Link",
    "50:C7:BF": "TP-Link",
    "64:70:02": "TP-Link",
    "B4:B0:24": "TP-Link",
    "DC:FE:18": "TP-Link",
    "F4:F2:6D": "TP-Link",
    # Cisco
    "00:18:E7": "Cisco",
    "00:1A:A2": "Cisco",
    "E0:2F:6D": "Cisco",
    "00:00:0C": "Cisco",
    "58:AC:78": "Cisco",
    "68:EF:BD": "Cisco",
    # Asus
    "C4:AD:34": "Asus",
    "10:BF:48": "Asus",
    "50:EB:71": "Asus",
    "14:DA:E9": "Asus",
    "90:E6:BA": "Asus",
    "DC:9F:DB": "Asus",
    # Netgear
    "A0:21:B7": "Netgear",
    "20:4E:7F": "Netgear",
    "84:1B:5E": "Netgear",
    # Xiaomi
    "58:6D:8F": "Xiaomi",
    "64:09:80": "Xiaomi",
    "F4:8E:92": "Xiaomi",
    "68:DF:DD": "Xiaomi",
    "B0:E2:35": "Xiaomi",
    # Amazon
    "B0:BE:76": "Amazon",
    "44:65:0D": "Amazon",
    "FC:65:DE": "Amazon",
    "40:B4:CD": "Amazon",
    "AC:63:BE": "Amazon",
    "F0:27:2D": "Amazon",
    # Google / Nest
    "68:A4:0E": "Google",
    "54:60:09": "Google",
    "F4:F5:D8": "Google",
    "70:3A:CB": "Google",
    "B4:CE:F6": "Google",
    "F8:8F:CA": "Google",
    # Roku
    "00:1D:72": "Roku",
    "B8:3E:59": "Roku",
    "CC:6D:A0": "Roku",
    # LG
    "00:1E:75": "LG",
    "40:B8:37": "LG",
    "78:5D:C8": "LG",
    "E8:5B:5B": "LG",
    # Sony
    "00:01:4A": "Sony",
    "28:0D:FC": "Sony",
    "84:C7:EA": "Sony",
    "CC:F9:57": "Sony",
    # Nintendo
    "00:09:BF": "Nintendo",
    "40:F4:07": "Nintendo",
    "9C:E6:35": "Nintendo",
    # Lenovo
    "20:7C:8F": "Lenovo",
    "40:8D:5C": "Lenovo",
    "88:70:8C": "Lenovo",
    # Realtek
    "00:E0:4C": "Realtek",
    "00:0B:6C": "Realtek",
}

# Moved verbatim from the former network/oui_lookup.FALLBACK_OUI (P4-2):
# a second static vendor table, consulted by lookup_oui alongside _OUI_DB.
_FALLBACK_OUI = {
    "00:03:93": "Apple Inc.",
    "00:05:02": "Apple Inc.",
    "00:0a:27": "Apple Inc.",
    "00:0d:93": "Apple Inc.",
    "00:10:fa": "Apple Inc.",
    "00:16:cb": "Apple Inc.",
    "00:17:f2": "Apple Inc.",
    "00:19:e3": "Apple Inc.",
    "00:1c:b3": "Apple Inc.",
    "00:1d:4f": "Apple Inc.",
    "00:1e:52": "Apple Inc.",
    "00:1f:5b": "Apple Inc.",
    "00:21:e9": "Apple Inc.",
    "00:22:41": "Apple Inc.",
    "00:23:12": "Apple Inc.",
    "00:23:32": "Apple Inc.",
    "00:23:6c": "Apple Inc.",
    "00:24:36": "Apple Inc.",
    "00:25:00": "Apple Inc.",
    "00:25:4b": "Apple Inc.",
    "00:26:08": "Apple Inc.",
    "00:26:4a": "Apple Inc.",
    "00:26:b0": "Apple Inc.",
    "00:26:bb": "Apple Inc.",
    "28:cf:e9": "Apple Inc.",
    "34:15:9e": "Apple Inc.",
    "34:a3:95": "Apple Inc.",
    "40:a6:d9": "Apple Inc.",
    "44:d8:84": "Apple Inc.",
    "58:55:ca": "Apple Inc.",
    "60:c5:47": "Apple Inc.",
    "64:a3:cb": "Apple Inc.",
    "68:a8:6d": "Apple Inc.",
    "70:3e:ac": "Apple Inc.",
    "7c:d1:c3": "Apple Inc.",
    "80:ea:96": "Apple Inc.",
    "84:38:35": "Apple Inc.",
    "88:1f:a1": "Apple Inc.",
    "8c:2d:aa": "Apple Inc.",
    "90:72:40": "Apple Inc.",
    "90:b2:1f": "Apple Inc.",
    "a4:5e:60": "Apple Inc.",
    "b8:17:c2": "Apple Inc.",
    "c8:6f:1d": "Apple Inc.",
    "d4:9a:20": "Apple Inc.",
    "dc:2b:61": "Apple Inc.",
    "f0:d1:a9": "Apple Inc.",
    "f4:f1:5a": "Apple Inc.",
    "f8:27:93": "Apple Inc.",
    "fc:25:3f": "Apple Inc.",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:17:d4": "Samsung",
    "00:1a:8a": "Samsung",
    "00:1b:98": "Samsung",
    "00:1c:43": "Samsung",
    "00:1d:25": "Samsung",
    "00:1e:7d": "Samsung",
    "1c:62:b8": "Samsung",
    "24:4b:03": "Samsung",
    "30:07:4d": "Samsung",
    "38:aa:3c": "Samsung",
    "40:f3:08": "Samsung",
    "48:44:f7": "Samsung",
    "50:85:69": "Samsung",
    "5c:a3:9d": "Samsung",
    "64:b3:10": "Samsung",
    "78:47:1d": "Samsung",
    "84:25:db": "Samsung",
    "8c:71:f4": "Samsung",
    "94:63:d1": "Samsung",
    "a4:70:d6": "Samsung",
    "b0:05:94": "Samsung",
    "c8:72:75": "Samsung",
    "d0:59:e4": "Samsung",
    "e4:12:1d": "Samsung",
    "f4:7b:5e": "Samsung",
    "00:03:ff": "Microsoft",
    "00:0d:3a": "Microsoft",
    "00:12:5a": "Microsoft",
    "00:15:5d": "Microsoft",
    "00:17:fa": "Microsoft",
    "00:22:48": "Microsoft",
    "00:25:ae": "Microsoft",
    "00:50:f2": "Microsoft",
    "28:18:78": "Microsoft",
    "30:59:b7": "Microsoft",
    "48:50:73": "Microsoft",
    "50:1a:c5": "Microsoft",
    "58:82:a8": "Microsoft",
    "60:45:bd": "Microsoft",
    "7c:1e:52": "Microsoft",
    "94:f6:65": "Microsoft",
    "a4:cf:99": "Microsoft",
    "b8:31:b5": "Microsoft",
    "c0:33:5e": "Microsoft",
    "dc:b3:19": "Microsoft",
    "f4:39:09": "Microsoft",
    "00:08:ca": "Intel",
    "00:13:e8": "Intel",
    "00:15:00": "Intel",
    "00:16:76": "Intel",
    "00:18:de": "Intel",
    "00:19:d1": "Intel",
    "00:1b:77": "Intel",
    "00:1c:bf": "Intel",
    "00:1d:e0": "Intel",
    "00:21:5c": "Intel",
    "00:21:6a": "Intel",
    "00:22:fb": "Intel",
    "00:23:14": "Intel",
    "00:24:d6": "Intel",
    "00:24:d7": "Intel",
    "34:13:e8": "Intel",
    "48:45:20": "Intel",
    "64:4b:f0": "Intel",
    "68:5d:43": "Intel",
    "80:00:0b": "Intel",
    "88:53:2e": "Intel",
    "a4:17:31": "Intel",
    "b4:b6:86": "Intel",
    "c8:5b:76": "Intel",
    "d4:3d:7e": "Intel",
    "f4:8c:50": "Intel",
    "00:22:6b": "Huawei",
    "00:25:9e": "Huawei",
    "0c:37:dc": "Huawei",
    "24:db:ac": "Huawei",
    "28:31:52": "Huawei",
    "34:6b:d3": "Huawei",
    "40:4d:8e": "Huawei",
    "4c:8b:ef": "Huawei",
    "54:89:98": "Huawei",
    "64:16:f0": "Huawei",
    "78:1d:4a": "Huawei",
    "80:38:bc": "Huawei",
    "88:53:d4": "Huawei",
    "9c:28:bf": "Huawei",
    "ac:e8:7b": "Huawei",
    "bc:76:70": "Huawei",
    "cc:96:a0": "Huawei",
    "e0:24:7f": "Huawei",
}


# Lazily-loaded IEEE OUI table from the mac-vendor-lookup data file, keyed by the
# uppercase hex prefix (no separators). None = not loaded yet.
_LIB_PREFIXES: dict[str, str] | None = None
_LIB_LOCK = threading.Lock()


def _lib_prefixes() -> dict[str, str]:
    """Load the mac-vendor-lookup OUI file once, synchronously, into a dict.

    Returns ``{}`` (static-fallback-only) when the file is absent (not yet
    downloaded by ``sync_vendor_db_bg``) or unreadable, so lookups degrade
    gracefully offline. Never triggers a download or the library's async path.
    """
    global _LIB_PREFIXES
    if _LIB_PREFIXES is not None:
        return _LIB_PREFIXES
    with _LIB_LOCK:
        if _LIB_PREFIXES is not None:  # filled while we waited for the lock
            return _LIB_PREFIXES
        prefixes: dict[str, str] = {}
        path = getattr(_mlookup, "cache_path", "") if _mlookup is not None else ""
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        prefix, sep, vendor = line.partition(":")
                        vendor = vendor.strip()
                        if sep and vendor:
                            prefixes[prefix.strip().upper()] = vendor
            except OSError as e:
                _log.warning("oui: could not read vendor db %s: %s", path, e)
        _LIB_PREFIXES = prefixes
        return _LIB_PREFIXES


def lookup_oui(mac: str) -> str:
    if not mac:
        return ""

    # IEEE table (downloaded file) — try /36, /28, /24 assignment prefixes.
    lib = _lib_prefixes()
    if lib:
        hexstr = "".join(c for c in mac if c in "0123456789abcdefABCDEF").upper()
        for n in (9, 7, 6):
            vendor = lib.get(hexstr[:n])
            if vendor:
                return vendor

    # Local static fallback. Two static tables (P4-2): _OUI_DB uses upper-case
    # keys, _FALLBACK_OUI lower-case. Checking both resolves the union.
    return _OUI_DB.get(mac.upper()[:8]) or _FALLBACK_OUI.get(mac.lower()[:8], "")


def sync_vendor_db_bg():
    """Call in a daemon thread — downloads/refreshes the mac-vendor-lookup OUI
    data file from the internet, then drops the in-memory cache so the next
    lookup reloads the refreshed file."""
    global _LIB_PREFIXES
    if _MAC_VENDOR_LIB and _mlookup is not None:
        try:
            _mlookup.update_vendors()
            with _LIB_LOCK:
                _LIB_PREFIXES = None  # force reload from the refreshed file
        except Exception:
            _log.debug("oui: vendor DB refresh failed", exc_info=True)
