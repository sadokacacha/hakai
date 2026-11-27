"""
main.py — Lanwarden entry point.

Run with:  sudo python3 main.py
"""

import os
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
    # Report capability availability for the current OS, honestly and without
    # pretending a Windows box is a broken Linux one. The capability registry
    # (core/capabilities.py) knows which features are OS-supported, which need a
    # missing dependency, and which need elevation — so interception features
    # (nft/tc/ARP) are flagged "Linux-only" on Windows rather than "missing".
    from core.capabilities import INTERCEPTION, MONITOR, get_capabilities

    caps = get_capabilities()

    # Actionable here: capabilities that COULD work on this OS but are blocked by
    # a missing dependency or missing elevation.
    blocked_here = [
        c
        for c in caps.values()
        if not c.available and c.supported_on_this_os and (c.missing_dep or c.needs_elevation)
    ]
    mon_blocked = [c for c in blocked_here if c.category in (MONITOR, "diagnostic")]
    engine_blocked = [c for c in blocked_here if c.category == INTERCEPTION]

    if mon_blocked:
        print("\n[!] Some monitoring features are limited on this system:")
        for c in mon_blocked:
            print(f"    - {c.title:28} : {c.reason}  → {c.remedy}")
    if engine_blocked:
        print("\n[!] Interception engine features need attention:")
        for c in engine_blocked:
            print(f"    - {c.title:28} : {c.reason}  → {c.remedy}")

    # Interception is Linux-only by design; say so once on other platforms.
    os_unsupported_engine = [
        c for c in caps.values() if c.category == INTERCEPTION and not c.supported_on_this_os
    ]
    if os_unsupported_engine:
        print(
            "\n[i] Active interception (cut / firewall / shaping) is Linux-only; "
            "monitoring & diagnostics run on this platform."
        )
    if mon_blocked or engine_blocked or os_unsupported_engine:
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
