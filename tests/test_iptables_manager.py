"""Tests for IPTManager bookkeeping (platform-safe: _ipt is a no-op off Linux)."""
from system.iptables_manager import IPTManager


def test_accounting_bookkeeping():
    m = IPTManager()
    m.add_accounting("10.0.0.5")
    assert "10.0.0.5" in m._accounting
    # Idempotent: re-adding doesn't duplicate.
    m.add_accounting("10.0.0.5")
    assert list(m._accounting).count("10.0.0.5") == 1
    m.remove_accounting("10.0.0.5")
    assert "10.0.0.5" not in m._accounting


def test_drop_bookkeeping():
    m = IPTManager()
    assert m.is_dropped("10.0.0.9") is False
    m.add_drop("10.0.0.9")
    assert m.is_dropped("10.0.0.9") is True
    m.remove_drop("10.0.0.9")
    assert m.is_dropped("10.0.0.9") is False


def test_cleanup_clears_all():
    m = IPTManager()
    m.add_accounting("10.0.0.1")
    m.add_drop("10.0.0.2")
    m.cleanup()
    assert not m._accounting
    assert not m._dropped
