"""
ui/async_util.py — run a blocking UI handler off the Tk thread (P4-6).

The dashboard's engine toggles call controller methods that run subprocesses
(ip/nft/sysctl) synchronously, which froze the Tk event loop. `run_async` moves
that work onto a daemon thread. The handler must read any Tk *widget* state on the
UI thread first and marshal any widget *writes* back itself — the dashboard log
(`log_tactical`) is already thread-safe, so logging from the worker is fine.
"""

from __future__ import annotations

import threading


def run_async(func, name: str = "ui_worker"):
    """Run func() on a daemon thread so a subprocess-heavy UI handler doesn't
    freeze the Tk event loop."""
    threading.Thread(target=func, daemon=True, name=name).start()
