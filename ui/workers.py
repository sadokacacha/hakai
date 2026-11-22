"""
ui/workers.py — run blocking controller/subprocess work off the Qt thread.

Qt is single-threaded for widgets; privileged engine calls (ip/nft/tc/scapy) must
not run on the GUI thread. ``submit`` runs a callable on the global QThreadPool
and marshals the result/error/done back to the UI thread via queued signals, so
slots touch widgets safely.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot


class _Signals(QObject):
    result = Signal(object)
    error = Signal(str)
    done = Signal()


class _Task(QRunnable):
    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.signals = _Signals()

    @Slot()
    def run(self) -> None:
        try:
            out = self._fn(*self._args, **self._kwargs)
            self.signals.result.emit(out)
        except Exception as e:  # report to the UI, never crash the pool thread
            self.signals.error.emit(f"{type(e).__name__}: {e}")
        finally:
            self.signals.done.emit()


def submit(
    fn: Callable,
    *args,
    on_result: Callable | None = None,
    on_error: Callable | None = None,
    on_done: Callable | None = None,
    pool: QThreadPool | None = None,
    **kwargs,
) -> _Task:
    task = _Task(fn, *args, **kwargs)
    if on_result:
        task.signals.result.connect(on_result)
    if on_error:
        task.signals.error.connect(on_error)
    if on_done:
        task.signals.done.connect(on_done)
    (pool or QThreadPool.globalInstance()).start(task)
    return task
