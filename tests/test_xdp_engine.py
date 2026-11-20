"""
Regression tests for network/xdp_engine.py (Phase-2 hunt).

Offensive module — cleanup/validation only, not drop effectiveness.

XDP-1  unload() called remove_xdp() unwrapped and set _loaded=False only
       afterwards, so a raising remove_xdp propagated and left _loaded True (the
       XDP program stuck on the NIC, unload not idempotent).
XDP-2  add_drop/remove_drop used socket.inet_aton, which accepts non-dotted-quad
       forms like "1.2.3", producing a wrong map key.

No BCC/kernel involved: the BPF object is a fake.
"""

from __future__ import annotations

import ipaddress

from network.xdp_engine import XDPEngine


class _FakeBpf:
    def __init__(self, raise_on_remove=False):
        self.maps = {"drop_ips": {}}
        self._raise = raise_on_remove
        self.removed = False

    def __getitem__(self, name):
        return self.maps[name]

    def remove_xdp(self, iface, flags):
        if self._raise:
            raise RuntimeError("remove_xdp boom")
        self.removed = True


def test_unload_is_safe_and_idempotent_when_remove_raises():
    e = XDPEngine("eth0")
    e._loaded = True
    e._bpf = _FakeBpf(raise_on_remove=True)

    e.unload()  # must not raise
    assert e._loaded is False, "state must be cleared even when remove_xdp fails"

    e.unload()  # second call is a no-op, must not raise


def test_unload_clears_state_on_success():
    e = XDPEngine("eth0")
    e._loaded = True
    bpf = _FakeBpf()
    e._bpf = bpf
    e.unload()
    assert bpf.removed is True
    assert e._loaded is False and e._bpf is None


def test_add_drop_rejects_non_dotted_quad():
    e = XDPEngine("eth0")
    e._loaded = True
    e._bpf = _FakeBpf()
    e.add_drop("1.2.3")  # inet_aton would accept this; a proper IPv4 parse must not
    assert e._bpf.maps["drop_ips"] == {}, "non-dotted-quad must be rejected"


def test_add_drop_valid_ipv4_uses_packed_key():
    e = XDPEngine("eth0")
    e._loaded = True
    e._bpf = _FakeBpf()
    e.add_drop("192.168.1.5")
    assert ipaddress.IPv4Address("192.168.1.5").packed in e._bpf.maps["drop_ips"]


def test_add_drop_noop_when_not_loaded():
    e = XDPEngine("eth0")  # _loaded False, _bpf None
    e.add_drop("192.168.1.5")  # must not raise
