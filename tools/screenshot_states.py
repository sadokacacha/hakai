#!/usr/bin/env python3
"""
tools/screenshot_states.py — render each LanwardenWindow UI state to a PNG.

Runs the real window offscreen (no display, no root) against a controller whose
device list is stubbed, driving every documented state and grabbing a screenshot.

    QT_QPA_PLATFORM=offscreen python3 tools/screenshot_states.py [out_dir]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

STATES = [
    "empty",
    "loading",
    "normal",
    "error",
    "degraded",
    "disconnected",
    "permission_denied",
    "running",
    "stopping",
    "restoring",
    "restore_failed",
]


def _fake_devices():
    from core.device import Device

    rows = [
        ("192.168.1.10", "a4:83:e7:11:22:33", "Living-Room-TV", "Samsung", "online", 820000, 24000),
        ("192.168.1.23", "3c:22:fb:aa:bb:cc", "Alice-iPhone", "Apple", "limited", 120000, 9000),
        ("192.168.1.42", "dc:a6:32:de:ad:be", "pi-hole", "Raspberry Pi", "cut", 0, 0),
        ("192.168.1.50", "00:11:22:33:44:55", "This-Host", "Intel", "self", 50000, 50000),
    ]
    out = []
    for ip, mac, nick, vendor, status, rx, tx in rows:
        d = Device(ip, mac=mac, vendor=vendor)
        d.nickname = nick
        d.identity = nick
        d.status = status
        d.rx_speed = rx
        d.tx_speed = tx
        d.cut = status == "cut"
        d.limited = status == "limited"
        d.open_ports = [22, 80, 443] if status != "self" else []
        d.os_guess = "Linux" if "pi" in nick else ""
        out.append(d)
    return out


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)

    from PySide6.QtWidgets import QApplication

    from core.controller import Controller
    from system.netinfo import NetInfo
    from ui.main_window import LanwardenWindow

    app = QApplication.instance() or QApplication([])
    ctrl = Controller(NetInfo(iface="wlan0", gateway="192.168.1.1", my_ip="192.168.1.50"))
    devices = _fake_devices()
    # Stub the live engine reads so the window renders deterministic data offscreen.
    ctrl.update_device_speeds = lambda: None  # type: ignore[method-assign]
    ctrl.snapshot_devices = lambda: devices  # type: ignore[method-assign]

    win = LanwardenWindow(ctrl)
    win._timer.stop()
    win.resize(1180, 720)
    win.show()

    for state in STATES:
        detail = {
            "error": "nft: command failed (rc=1)",
            "degraded": "tc not installed",
            "disconnected": "no gateway detected",
            "permission_denied": "AF_PACKET EPERM",
            "restore_failed": "iptables -D left 1 rule",
        }.get(state, "")
        # Empty state shows no rows; everything else shows the device table.
        ctrl.snapshot_devices = (lambda: []) if state == "empty" else (lambda: devices)  # type: ignore[method-assign]
        win._refresh()
        win.set_state(state, detail)
        app.processEvents()
        path = out_dir / f"{state}.png"
        win.grab().save(str(path))
        print(f"saved {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
