"""
Regression test — device-name column shows the most identifying label (IDENT-2).

From a live screenshot: rows showed "Windows System" (a class label) repeated,
"❓ Scanning..." stuck, and a UUID blob "6dd60a51 4531 C5bb Bdf8 5f6283e45d04".
Root causes:
  - the UI built the name as nickname OR identity OR hostname, so the generic
    classify_device label buried the real hostname;
  - _is_junk_hostname didn't reject UUID/UDN blobs, so they showed as names.
"""

from __future__ import annotations

import pytest

from core.identity import _is_junk_hostname, display_name


def test_real_hostname_beats_class_label():
    # The device has a real name AND a class label — the name must win.
    assert display_name("", "Living Room TV", "Windows System") == "Living Room TV"
    assert display_name("", "Johns-Laptop", "Linux/Mobile Node") == "Johns-Laptop"


def test_nickname_wins_over_everything():
    assert display_name("Dad's PC", "Johns-Laptop", "Windows System") == "Dad's PC"


def test_class_label_used_only_when_no_hostname():
    assert display_name("", "", "Windows System") == "Windows System"


def test_scanning_placeholder_never_buries_a_hostname():
    assert display_name("", "Living Room TV", "❓ Scanning...") == "Living Room TV"


def test_vendor_fallback_before_placeholder():
    # No nickname/hostname, identity is just the scanning placeholder → use vendor.
    assert display_name("", "", "❓ Scanning...", "Samsung") == "Samsung"


def test_placeholder_is_last_resort():
    assert display_name("", "", "❓ Scanning...") == "❓ Scanning..."
    assert display_name("", "", "") == "?"


def test_uuid_blob_is_not_a_hostname():
    # The exact shape seen in the screenshot (sanitiser turned dashes to spaces).
    assert display_name("", "6dd60a51 4531 C5bb Bdf8 5f6283e45d04", "Private Device") == (
        "Private Device"
    )


@pytest.mark.parametrize(
    "name",
    [
        "6dd60a51 4531 c5bb bdf8 5f6283e45d04",
        "6dd60a51-4531-c5bb-bdf8-5f6283e45d04",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",  # 32-hex, no separators
    ],
)
def test_is_junk_hostname_rejects_uuid_blobs(name):
    assert _is_junk_hostname(name) is True


@pytest.mark.parametrize("name", ["Living Room TV", "Johns-Laptop", "DESKTOP-AB12CD"])
def test_is_junk_hostname_keeps_real_names(name):
    assert _is_junk_hostname(name) is False
