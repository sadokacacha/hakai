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
        "_do_blackout",
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


def test_disconnected_state_without_gateway(_app):
    ctrl = Controller(NetInfo(iface="", gateway=""))
    ctrl.update_device_speeds = lambda: None
    win = LanwardenWindow(ctrl)
    win._timer.stop()
    assert win._state == "disconnected", "no iface/gateway must report disconnected, not normal"


def test_blackout_state_shows_distinctly(_app):
    win = _win(_app)
    win.ctrl.blackout_active = True
    win._refresh_status()
    assert "BLACKOUT" in win.sb_blackout.text(), "blackout must show distinctly in the status bar"
    assert "ON" in win.btn_blackout.text()
    win.ctrl.blackout_active = False
    win._refresh_status()
    assert win.sb_blackout.text() == ""


def test_protection_alert_is_wired_and_coalesced(_app):
    # The protector's alerts must reach the UI (controller.on_protection_alert
    # was a no-op and the window never registered a sink). The sink must be a
    # thread-safe deque append — NOT a Qt call, which crashed under an ARP storm
    # when emitted from the sniffer thread.
    win = _win(_app)
    assert win.ctrl._alert_cb is not None, "window must register an alert sink on the controller"
    assert win.ctrl._alert_cb == win._alert_q.append, (
        "sink must be the deque append (no Qt off-thread)"
    )
    # An alert queued by the (off-thread) sink shows on the next GUI-thread drain.
    win.ctrl._alert_cb("⚠️ DANGER: 192.168.1.1 is spoofing (MAC changed)!")
    win._drain_alerts()
    assert "spoofing" in win.sb_alert.text()
    # A storm coalesces: many queued alerts drain to ONE update (the latest),
    # never a flood of per-alert UI work.
    for i in range(20):
        win.ctrl._alert_cb(f"⚠️ alert {i}")
    win._drain_alerts()
    assert win.sb_alert.text().endswith("alert 19")
    assert len(win._alert_q) == 0, "drain must empty the queue"


# ── Capability surface (cross-platform mission) ────────────────────────────────


def test_caps_pill_and_report(_app):
    win = _win(_app)
    assert win.sb_caps.text().startswith("⚙ caps")
    report = win._capabilities_report()
    assert "Monitoring" in report
    assert "Interception (Linux-only)" in report


def test_interception_nav_disabled_on_windows(_app, monkeypatch):
    """On a non-Linux OS the Warden/Keeper tabs are disabled, not misleading."""
    import core.capabilities as cap

    cap._cached.cache_clear()
    monkeypatch.setattr(cap, "IS_WINDOWS", True)
    monkeypatch.setattr(cap, "_os_key", lambda: "windows")
    monkeypatch.setattr(cap, "is_elevated", lambda: True)
    monkeypatch.setattr(cap, "_has_npcap", lambda: True)
    monkeypatch.setattr(cap, "_has_module", lambda m: True)
    monkeypatch.setattr(cap.shutil, "which", lambda n: "/x/" + n)
    try:
        win = _win(_app)
        # Warden (1) and Keeper (2) must be disabled; Watch (0) stays enabled.
        assert win._nav_group.button(0).isEnabled()
        assert not win._nav_group.button(1).isEnabled()
        assert not win._nav_group.button(2).isEnabled()
    finally:
        cap._cached.cache_clear()


def test_monitoring_available_keeps_app_ready(_app, monkeypatch):
    """Interception-off on Windows does NOT mark the whole app degraded."""
    import core.capabilities as cap

    cap._cached.cache_clear()
    monkeypatch.setattr(cap, "IS_WINDOWS", True)
    monkeypatch.setattr(cap, "_os_key", lambda: "windows")
    monkeypatch.setattr(cap, "is_elevated", lambda: True)
    monkeypatch.setattr(cap, "_has_npcap", lambda: True)
    monkeypatch.setattr(cap, "_has_module", lambda m: True)
    monkeypatch.setattr(cap.shutil, "which", lambda n: "/x/" + n)
    try:
        win = _win(_app)
        # All monitoring caps available → state is not 'degraded'.
        assert win._state != "degraded"
    finally:
        cap._cached.cache_clear()
