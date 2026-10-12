"""
ui/limit_dialog.py — Per-device bandwidth limit slider dialog.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ui.theme import *


def show_limit_dialog(parent, ip: str, dev, apply_cb, extra_ips: list = None):
    """
    Opens a modal dialog with an entry to set bandwidth limit (KB/s).
    apply_cb(ip, kb) is called when the user clicks APPLY.
    extra_ips: additional IPs that will receive the same limit.
    """
    dlg = tk.Toplevel(parent)
    dlg.title(f"⚡ Limit — {ip}")
    dlg.geometry("440x340")
    dlg.resizable(False, False)
    dlg.configure(bg=PANEL)
    dlg.transient(parent)          # keep on top of parent
    dlg.update_idletasks()         # ensure window is actually mapped
    dlg.after(50, dlg.grab_set)   # defer grab until window is viewable
    dlg.focus_force()

    tk.Label(dlg, text="⚡  BANDWIDTH LIMIT",
             bg=PANEL, fg=ACCENT, font=FONT_HEADER).pack(pady=(22, 4))
    # Show which devices will be affected
    targets = [ip] + (extra_ips or [])
    if len(targets) > 1:
        target_txt = f"{ip}  (+{len(targets)-1} more)"
        tk.Label(dlg, text=target_txt,
                 bg=PANEL, fg=AMBER, font=FONT_SMALL).pack()
    else:
        tk.Label(dlg, text=f"{ip}   {dev.display_name()}",
                 bg=PANEL, fg=MUTED, font=FONT_SMALL).pack()

    sep = tk.Frame(dlg, bg=BORDER, height=1)
    sep.pack(fill="x", padx=30, pady=12)

    tk.Label(dlg, text="Speed Limit (Up + Down):",
             bg=PANEL, fg=TEXT, font=FONT_BODY).pack(pady=(0, 6))

    sv = tk.IntVar(value=dev.limit_kb)
    
    entry_frame = tk.Frame(dlg, bg=PANEL)
    entry_frame.pack(pady=20)

    entry = tk.Entry(entry_frame, textvariable=sv, justify="center",
                     bg=BG, fg=ACCENT, insertbackground=ACCENT,
                     font=("Courier New", 28, "bold"), width=7,
                     relief="flat", highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=GLOW)
    entry.pack(side="left")
    entry.focus_set()
    entry.select_range(0, tk.END)

    tk.Label(entry_frame, text="KB/s", bg=PANEL, fg=MUTED,
             font=FONT_HEADER).pack(side="left", padx=12)

    btn_row = tk.Frame(dlg, bg=PANEL)
    btn_row.pack(pady=14)

    def _apply():
        # IntVar.get() raises TclError on non-numeric input; also reject <= 0
        # so a blank/garbage/negative value can't be passed to `tc` as a rate.
        try:
            kb = int(sv.get())
        except (tk.TclError, ValueError):
            kb = 0
        if kb <= 0:
            entry.configure(highlightbackground=RED, highlightcolor=RED)
            return
        apply_cb(ip, kb)
        dlg.destroy()

    tk.Button(btn_row, text="APPLY", command=_apply,
              bg=AMBER, fg=BG, font=FONT_HEADER,
              relief="flat", bd=0, padx=28, pady=8,
              cursor="hand2", activebackground=AMBER).pack(side="left", padx=6)

    tk.Button(btn_row, text="CANCEL", command=dlg.destroy,
              bg=MUTED, fg=BG, font=FONT_SMALL,
              relief="flat", bd=0, padx=18, pady=8,
              cursor="hand2").pack(side="left", padx=6)
