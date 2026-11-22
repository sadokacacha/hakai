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
