"""
Regression tests for core/shutdown.install_shutdown_hooks (P9).

main.py only restored network state via the GUI close button
(WM_DELETE_WINDOW -> ctrl.stop()). Ctrl+C (SIGINT) or `kill` (SIGTERM) on a
`sudo python3 main.py` run bypassed it, leaving ip_forward / iptables / nft / tc
rules and sysctl state behind. install_shutdown_hooks wires atexit + SIGINT +
SIGTERM to the idempotent ctrl.stop().
"""

from __future__ import annotations

import pytest

from core import shutdown as sd


class _Ctrl:
    def __init__(self):
        self.stops = 0

    def stop(self):
        self.stops += 1


def _patch_registry(monkeypatch):
    atexit_cbs: list = []
    signals: dict = {}
    monkeypatch.setattr(sd.atexit, "register", lambda f: atexit_cbs.append(f))
    monkeypatch.setattr(sd.signal, "signal", lambda sig, h: signals.__setitem__(sig, h))
    return atexit_cbs, signals


def test_registers_atexit_and_both_signals(monkeypatch):
    atexit_cbs, signals = _patch_registry(monkeypatch)
    ctrl = _Ctrl()

    sd.install_shutdown_hooks(ctrl)

    assert len(atexit_cbs) == 1
    assert sd.signal.SIGINT in signals
    assert sd.signal.SIGTERM in signals
    # The atexit callback restores the network.
    atexit_cbs[0]()
    assert ctrl.stops == 1


def test_signal_handler_stops_then_exits(monkeypatch):
    _atexit, signals = _patch_registry(monkeypatch)
    ctrl = _Ctrl()
    sd.install_shutdown_hooks(ctrl)

    handler = signals[sd.signal.SIGTERM]
    with pytest.raises(SystemExit):
        handler(sd.signal.SIGTERM, None)
    assert ctrl.stops == 1


def test_survives_registration_off_main_thread(monkeypatch):
    # signal.signal() raises ValueError when not on the main thread; the atexit
    # fallback must still be registered and no exception may escape.
    atexit_cbs: list = []
    monkeypatch.setattr(sd.atexit, "register", lambda f: atexit_cbs.append(f))

    def boom(sig, handler):
        raise ValueError("signal only works in main thread")

    monkeypatch.setattr(sd.signal, "signal", boom)

    sd.install_shutdown_hooks(_Ctrl())  # must not raise
    assert len(atexit_cbs) == 1


def test_stop_exception_does_not_escape(monkeypatch):
    atexit_cbs, _signals = _patch_registry(monkeypatch)

    class _Bad:
        def stop(self):
            raise RuntimeError("stop boom")

    sd.install_shutdown_hooks(_Bad())
    atexit_cbs[0]()  # guarded — must not raise out of the atexit hook
