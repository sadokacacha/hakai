"""
core/shutdown.py — restore network state however the process ends.

main.py only wired ``WM_DELETE_WINDOW -> Dashboard.on_close -> ctrl.stop()``. A
``sudo python3 main.py`` run stopped with Ctrl+C (SIGINT) or ``kill`` (SIGTERM)
bypassed that path, so ``restore_network`` never ran and the host was left with
``ip_forward=1``, live iptables/nft/tc rules, a poisoned ARP cache and
unrestored sysctl/MTU/MAC state — violating the project rule "restore original
state on exit, including on crash; never leave networking rules behind."

``install_shutdown_hooks`` registers an ``atexit`` callback plus SIGINT/SIGTERM
handlers that all call ``ctrl.stop()``. ``Controller.stop()`` is idempotent
(guarded by ``self._stopped``), so overlapping triggers — a signal, then the Tk
close button, then interpreter exit — collapse into a single real teardown.
"""

from __future__ import annotations

import atexit
import logging
import signal
from typing import Protocol

_log = logging.getLogger(__name__)


class _Stoppable(Protocol):
    def stop(self) -> None: ...


def install_shutdown_hooks(ctrl: _Stoppable) -> None:
    """Ensure ctrl.stop() runs on terminal signals and interpreter exit.

    Safe to call once from main() after the controller is started. signal.signal
    only works on the main thread; if that is not the case the registration is
    skipped (logged), leaving the atexit hook as the fallback.
    """

    def _safe_stop() -> None:
        try:
            ctrl.stop()
        except Exception:
            # stop() is already step-isolated; guard anyway so an atexit/signal
            # path never dies with a bare traceback.
            _log.exception("shutdown hook: ctrl.stop() raised")

    atexit.register(_safe_stop)

    def _handler(signum: int, _frame: object) -> None:
        _log.info("signal %s received — restoring network and exiting", signum)
        _safe_stop()
        # Re-raise the default behaviour via a clean exit so atexit also runs
        # (it is now a no-op because stop() is idempotent).
        raise SystemExit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError) as e:
            _log.debug("could not install handler for signal %s: %s", sig, e)
