"""Regression tests for the 2026-10-13 re-audit fixes.

These guard the specific defects fixed in that pass so they cannot silently
come back. They are platform-safe (no root, no live networking) and do not touch
the UI (which now lives behind PySide6 — see test_ui_qt.py).
"""

from network.deauth import SCAPY_WIFI_OK, DeauthManager


# ── N3: deauth scapy-availability guard ─────────────────────────────────────
def test_scapy_wifi_ok_reflects_real_import():
    """The guard used to wrap a bare `SCAPY_WIFI_OK = True`, so it could never
    be False. With scapy installed it must now be True because the Dot11 import
    actually succeeds."""
    assert SCAPY_WIFI_OK is True


def test_deauth_available_requires_bssid_and_iface():
    assert DeauthManager("AA:BB:CC:DD:EE:FF", "wlan0").is_available is True
    assert DeauthManager("", "wlan0").is_available is False
    assert DeauthManager("AA:BB:CC:DD:EE:FF", "").is_available is False


# (The former ctk Dashboard wiring regressions moved to test_ui_qt.py when the
# UI was rebuilt in PySide6 — the feature-reachability assertions live there now.)


# ── /wire: dormant interception features remain reachable on the controller ──
def test_controller_exposes_interception_methods():
    from core.controller import Controller

    assert callable(Controller.monitor_device)
    assert callable(Controller.toggle_dns_spoof)


# ── on_protection_alert forwards to the registered sink (was a silent no-op) ──
def test_on_protection_alert_forwards_to_registered_sink():
    from core.controller import Controller
    from system.netinfo import NetInfo

    ctrl = Controller(NetInfo(iface="eth0", gateway="192.168.1.1", my_ip="192.168.1.5"))
    seen: list[str] = []
    ctrl.set_alert_callback(seen.append)
    ctrl.on_protection_alert("⚠️ DANGER: spoofer detected")
    assert seen == ["⚠️ DANGER: spoofer detected"]

    # Safe (no raise) with no sink, and a raising sink must not propagate.
    ctrl.set_alert_callback(None)
    ctrl.on_protection_alert("ignored")

    def _boom(_msg: str) -> None:
        raise RuntimeError("sink failure")

    ctrl.set_alert_callback(_boom)
    ctrl.on_protection_alert("handled")  # must be swallowed, not raised
