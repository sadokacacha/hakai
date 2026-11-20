"""
Regression test for ui/dashboard.py cross-thread logging (Phase-2 hunt).

DASH-1  log_tactical() wrote straight to the Tk status_box, but it is called from
        background threads (the scan worker, the cut `_do` threads via log=, and
        the protector sniffer via on_protection_alert). Tkinter is not
        thread-safe. It now enqueues; _drain_log_queue() does the widget write on
        the UI thread.

No Tk display or CTk instance is created: the methods are called unbound with a
plain fake `self` carrying only the attributes they touch.
"""

from __future__ import annotations

import queue
from unittest.mock import MagicMock

import ui.dashboard as dash


class _FakeSelf:
    """A stand-in for the Dashboard instance with just the attrs these methods use."""

    def __init__(self):
        self._log_queue: queue.Queue = queue.Queue()
        self.status_box = MagicMock()
        self.after = MagicMock()
        # _drain_log_queue reschedules via after(200, self._drain_log_queue);
        # the attribute just needs to resolve (after is mocked, nothing runs).
        self._drain_log_queue = MagicMock()


def test_log_tactical_enqueues_and_does_not_touch_widget():
    fs = _FakeSelf()
    dash.Dashboard.log_tactical(fs, "hello", "danger")
    # Must NOT write to the widget directly (not thread-safe from a worker thread).
    fs.status_box.insert.assert_not_called()
    assert fs._log_queue.qsize() == 1


def test_drain_log_queue_writes_on_ui_thread_and_reschedules():
    fs = _FakeSelf()
    dash.Dashboard.log_tactical(fs, "one")
    dash.Dashboard.log_tactical(fs, "two")
    dash.Dashboard._drain_log_queue(fs)
    # Both queued messages are written to the widget by the drain (UI-thread) call.
    assert fs.status_box.insert.call_count == 2
    fs.status_box.see.assert_called()
    # The drain reschedules itself and empties the queue.
    fs.after.assert_called()
    assert fs._log_queue.qsize() == 0
