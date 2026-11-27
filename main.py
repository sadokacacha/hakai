"""
main.py — Lanwarden entry point.

Run with:  sudo python3 main.py
"""

import os
import shutil
import sys
import threading


def _fix_sys_path():
    # Linux-only: fix site-packages path when running under sudo
    if sys.platform != "win32":
        sudo_user = os.getenv("SUDO_USER")
        if sudo_user:
            try:
                import pwd

                user_home = pwd.getpwnam(sudo_user).pw_dir
                version = f"{sys.version_info.major}.{sys.version_info.minor}"
                user_site = os.path.join(user_home, f".local/lib/python{version}/site-packages")
                if user_site not in sys.path:
                    sys.path.insert(0, user_site)
            except Exception:
                pass


_fix_sys_path()


def _check_root():
    if sys.platform == "win32":
        # Windows: check for Administrator privileges via ctypes
        try:
            import ctypes

            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        if not is_admin:
            print("[!] WARNING: Lanwarden is not running as Administrator.")
            print("    Network features (ARP, packet capture) require elevated privileges.")
            print(
                "    Right-click run.bat and select 'Run as Administrator' for full functionality."
            )
    else:
        # Linux/macOS: check for root via euid
        if os.geteuid() != 0:
            print("[!] Lanwarden must run as root.  Use: sudo python3 main.py")
            sys.exit(1)


def _check_deps():
    # Core capabilities Lanwarden relies on. nft and tc are required for the
    # firewall/shaping engine; bpftool for the optional XDP drop; the rest are
    # recommended. Missing ones are reported explicitly so a degraded run is
    # never silent.
    required = {
        "nft": "REQUIRED: nftables — firewall / cut / stealth engine.",
        "tc": "REQUIRED: iproute2 tc — bandwidth limiting.",
    }
    recommended = {
        "bpftool": "Optional: XDP/eBPF drop management (also needs BCC + clang).",
        "nmap": "For fast network scanning and fingerprinting.",
        "arpspoof": "Fallback ARP engine (apt install dsniff).",
        "iw": "For WiFi deauth / monitor mode management.",
    }
    missing_required = [n for n in required if not shutil.which(n)]
    missing_recommended = [n for n in recommended if not shutil.which(n)]
    if missing_required:
        print("\n[!] ERROR: Missing REQUIRED capabilities — core features will fail:")
        for m in missing_required:
            print(f"    - {m:8} : {required[m]}")
    if missing_recommended:
        print("\n[!] WARNING: Missing recommended dependencies:")
        for m in missing_recommended:
            print(f"    - {m:8} : {recommended[m]}")
    if missing_required or missing_recommended:
        print("")


_check_root()
_check_deps()

from core.controller import Controller
from core.oui import sync_vendor_db_bg
from core.persistence import db
from system.netinfo import detect_network
from ui.main_window import LanwardenWindow


def main():
    # ── Auto-detect network ───────────────────────────────────────────────────
    preferred = db.get("iface", "auto")
    net = detect_network(preferred_iface=preferred)

    # ── Set up WiFi deauth if wireless iface detected ─────────────────────────
    if net.is_wifi and net.iface:
        try:
            # Try to detect AP BSSID from default gateway
            import subprocess

            from network.deauth import DeauthManager

            r = subprocess.run(["iw", "dev", net.iface, "link"], capture_output=True, text=True)
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

    # Restore network state on Ctrl+C / kill / interpreter exit, not only the
    # GUI close button (WM_DELETE_WINDOW). ctrl.stop() is idempotent.
    from core.shutdown import install_shutdown_hooks

    install_shutdown_hooks(ctrl)

    # ── Sync vendor DB in background ──────────────────────────────────────────
    threading.Thread(target=sync_vendor_db_bg, daemon=True, name="vendor_db_sync").start()

    # ── UI (PySide6) ──────────────────────────────────────────────────────────
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    win = LanwardenWindow(ctrl)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
