"""
Headless (offscreen) smoke tests for the PySide6 UI (STEP 5).

No display or root needed — QT_QPA_PLATFORM=offscreen. These assert the window
builds, every documented state renders, the device table populates, and the
controller feature surface is reachable from the window (nothing was dropped in
the rebuild).
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from core.controller import Controller
from core.device import Device
from system.netinfo import NetInfo
from ui.main_window import LanwardenWindow
from ui.theme import STATE_STYLES


@pytest.fixture(scope="module")
def _app():
    return QApplication.instance() or QApplication([])


def _win(_app):
    ctrl = Controller(NetInfo(iface="eth0", gateway="192.168.1.1", my_ip="192.168.1.50"))
    ctrl.update_device_speeds = lambda: None
    win = LanwardenWindow(ctrl)
    win._timer.stop()
    return win


def test_window_builds(_app):
    win = _win(_app)
    assert win.table.columnCount() == 7
    assert win.windowTitle() == "Lanwarden"


def test_all_states_render(_app):
    win = _win(_app)
    for state in STATE_STYLES:
        win.set_state(state, "detail")
        assert win.banner.text(), f"state {state} produced no banner text"


def test_table_populates_and_status_counts(_app):
    win = _win(_app)
    devs = [Device("192.168.1.9", mac="aa:bb"), Device("192.168.1.8", mac="cc:dd")]
    win.ctrl.snapshot_devices = lambda: devs
    win._refresh()
    assert win.table.rowCount() == 2
    assert "devices: 2" in win.sb_count.text()
    assert win._state == "normal"


def test_empty_state_when_no_devices(_app):
    win = _win(_app)
    win.ctrl.snapshot_devices = lambda: []
    win._refresh()
    assert win.table.rowCount() == 0
    assert win._state == "empty"


def test_feature_surface_reachable(_app):
    # Every preserved action has a handler on the window.
    for attr in (
        "_do_scan",
        "_do_limit",
        "_do_rename",
        "_do_restore_all",
        "_toggle_arp",
        "_toggle_ks",
        "_do_static",
        "_do_dhcp",
        "_do_ping",
        "_do_traceroute",
        "_do_fingerprint",
        "_do_dns",
        "_do_monitor",
    ):
        assert callable(getattr(LanwardenWindow, attr)), attr


def test_require_ip_sets_error_when_nothing_selected(_app):
    win = _win(_app)
    assert win._require_ip() is None
    assert win._state == "error"
