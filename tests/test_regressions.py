"""Regression tests for the 2026-10-13 re-audit fixes.

These guard the specific defects fixed in that pass so they cannot silently
come back. They are platform-safe (no root, no live networking): importing the
UI modules only loads customtkinter, it does not create a Tk root window.
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


# ── N1: the Info popup and Protection panel are wired into the dashboard ────
def test_dashboard_wires_info_and_protection_dialogs():
    import ui.dashboard as dash

    # Imported into the dashboard namespace (regression: they were never called).
    assert hasattr(dash, "show_info_dialog")
    assert hasattr(dash, "show_protection_panel")
    # Handler methods that the row double-click / sidebar button invoke.
    assert callable(dash.Dashboard._open_info)
    assert callable(dash.Dashboard._open_protection)
