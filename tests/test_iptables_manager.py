"""Tests for IPTManager bookkeeping.

`_ipt` is stubbed so these run deterministically and never touch the real host's
iptables (previously they issued real `iptables` commands on Linux and only
passed because non-root made them fail harmlessly)."""

import subprocess

import pytest

from system import iptables_manager as ipt_mod
from system.iptables_manager import IPTManager


@pytest.fixture(autouse=True)
def _stub_ipt(monkeypatch):
    # rc=0 → `-C` reports the rule already present, so no real -A/-I is attempted.
    monkeypatch.setattr(
        ipt_mod,
        "_ipt",
        lambda *a, **k: subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    )


def test_accounting_bookkeeping():
    m = IPTManager()
    m.add_accounting("10.0.0.5")
    assert "10.0.0.5" in m._accounting
    # Idempotent: re-adding doesn't duplicate.
    m.add_accounting("10.0.0.5")
    assert list(m._accounting).count("10.0.0.5") == 1
    m.remove_accounting("10.0.0.5")
    assert "10.0.0.5" not in m._accounting


def test_cleanup_clears_all():
    m = IPTManager()
    m.add_accounting("10.0.0.1")
    m.cleanup()
    assert not m._accounting
