"""
main.py — Hakai v3 entry point.

Run with:  sudo python3 main.py
"""
import os
import sys
import shutil
import threading

def _fix_sys_path():
    sudo_user = os.getenv("SUDO_USER")
    if sudo_user:
        import pwd
        user_home = pwd.getpwnam(sudo_user).pw_dir
        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        user_site = os.path.join(user_home, f".local/lib/python{version}/site-packages")
        if user_site not in sys.path:
            sys.path.insert(0, user_site)

_fix_sys_path()

def _check_root():
    if os.geteuid() != 0:
        print("[!] Hakai must run as root.  Use: sudo python3 main.py")
        sys.exit(1)

def _check_deps():
    deps = {
        "nmap":     "For fast network scanning and fingerprinting.",
        "arpspoof": "Fallback ARP engine (apt install dsniff).",
        "tc":       "For bandwidth limiting (iproute2).",
        "iw":       "For WiFi deauth / monitor mode management.",
    }
    missing = [name for name in deps if not shutil.which(name)]
    if missing:
        print("\n[!] WARNING: Missing recommended dependencies:")
        for m in missing:
            print(f"    - {m:8} : {deps[m]}")
        print("")

_check_root()
_check_deps()

import tkinter as tk

from system.netinfo import detect_network
from core.controller import Controller
from core.persistence import db, sync_vendor_db_bg
from ui.dashboard import Dashboard


def main():
    # ── Auto-detect network ───────────────────────────────────────────────────
    preferred = db.get("iface", "auto")
    net = detect_network(preferred_iface=preferred)

    # ── Set up WiFi deauth if wireless iface detected ─────────────────────────
    if net.is_wifi and net.iface:
        try:
            from network.deauth import DeauthManager
            from scapy.all import Dot11   # probe scapy wifi support
            # Try to detect AP BSSID from default gateway
            import subprocess
            r = subprocess.run(
                ["iw", "dev", net.iface, "link"],
                capture_output=True, text=True)
            import re
            m = re.search(r"Connected to ([\w:]+)", r.stdout)
            bssid = m.group(1) if m else ""
            deauth_mgr = DeauthManager(bssid=bssid, iface=net.iface)
        except Exception:
            deauth_mgr = None
    else:
        deauth_mgr = None

    # ── Build controller ──────────────────────────────────────────────────────
    ctrl = Controller(net)
    ctrl.deauth = deauth_mgr
    if deauth_mgr:
        ctrl.arp.deauth_mgr = deauth_mgr
    ctrl.start()

    # ── Sync vendor DB in background ──────────────────────────────────────────
    threading.Thread(target=sync_vendor_db_bg, daemon=True,
                     name="vendor_db_sync").start()

    # ── UI ────────────────────────────────────────────────────────────────────
    import customtkinter as ctk
    app  = Dashboard(ctrl)

    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()