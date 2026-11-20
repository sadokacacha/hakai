"""
Regression test for ui/async_util.run_async (P4-6).

The dashboard's engine toggles used to run subprocesses synchronously on the Tk
thread, freezing the UI. run_async offloads the work to a daemon thread; the
handler must not run on the calling (UI) thread.
"""

from __future__ import annotations

from ui import async_util
from ui.async_util import run_async


def test_run_async_offloads_to_a_daemon_thread(monkeypatch):
    captured: dict = {}

    class _FakeThread:
        def __init__(self, target, daemon, name):
            captured["target"] = target
            captured["daemon"] = daemon
            captured["name"] = name
            captured["started"] = False

        def start(self):
            captured["started"] = True

    monkeypatch.setattr(async_util.threading, "Thread", _FakeThread)

    ran: list = []
    run_async(lambda: ran.append("work"), name="toggle_x")

    # The work is NOT executed on the calling (UI) thread — only scheduled.
    assert ran == []
    assert captured["daemon"] is True
    assert captured["name"] == "toggle_x"
    assert captured["started"] is True

    # Running the scheduled target executes the work (what the real thread does).
    captured["target"]()
    assert ran == ["work"]
