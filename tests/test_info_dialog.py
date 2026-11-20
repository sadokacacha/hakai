"""
Regression tests for ui/info_dialog.py cross-thread marshalling (Phase-2 hunt).

INFO-3  do_fingerprint's done-callback runs on the fingerprint worker thread. It
        marshalled its own dialog-label update via dlg.after(0, ...) but called
        fingerprint_done_cb(ip, dev) (the dashboard row refresh) DIRECTLY — a Tk
        widget update off the UI thread. It is now marshalled onto the parent
        window's Tk thread too.

Importing ui.info_dialog only loads tkinter + theme constants (no Tk root), so
the module-level helpers are callable with mocks — no display needed.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import ui.info_dialog as info_mod


def test_marshal_schedules_on_widget_and_not_directly():
    widget = MagicMock()
    fn = MagicMock()
    info_mod._marshal(widget, fn)
    fn.assert_not_called()
    widget.after.assert_called_once_with(0, fn)


def test_marshal_survives_destroyed_widget():
    widget = MagicMock()
    widget.after.side_effect = info_mod.tk.TclError("bad window path name")
    info_mod._marshal(widget, MagicMock())  # must not raise


def test_fingerprint_done_marshals_callback_not_direct():
    dlg, parent, rl, cb = MagicMock(), MagicMock(), MagicMock(), MagicMock()
    done = info_mod._make_fingerprint_done(dlg, parent, rl, cb)
    dev = SimpleNamespace(identity="iPhone", os_guess="iOS")

    done("10.0.0.5", dev)

    # The dashboard row-refresh callback must NOT run on this (worker) thread.
    cb.assert_not_called()
    parent.after.assert_called_once()  # scheduled on the parent UI thread
    dlg.after.assert_called_once()  # dialog label update scheduled on the dialog

    # Running the scheduled parent callback invokes the real callback.
    parent.after.call_args[0][1]()
    cb.assert_called_once_with("10.0.0.5", dev)


def test_fingerprint_done_without_callback_is_safe():
    dlg, parent, rl = MagicMock(), MagicMock(), MagicMock()
    done = info_mod._make_fingerprint_done(dlg, parent, rl, None)
    done("10.0.0.5", SimpleNamespace(identity="x", os_guess=""))
    parent.after.assert_not_called()  # no callback to schedule
    dlg.after.assert_called_once()  # label still updated
