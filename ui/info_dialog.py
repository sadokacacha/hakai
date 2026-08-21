"""
ui/info_dialog.py — Per-device info popup with ping, traceroute, fingerprint and reset.
"""
from __future__ import annotations

import shutil
import subprocess
import tkinter as tk

from core.persistence import fmt_speed, fmt_total
from ui.theme import *


def show_info_dialog(parent, ip: str, dev, controller, fingerprint_done_cb=None):
    dlg = tk.Toplevel(parent)
    dlg.title(f"ℹ  Info — {ip}")
    dlg.geometry("500x680")
    dlg.resizable(False, False)
    dlg.configure(bg=PANEL)
    dlg.grab_set()
    dlg.focus_force()

    tk.Label(dlg, text="ℹ  DEVICE INFO",
             bg=PANEL, fg=BLUE, font=FONT_HEADER).pack(pady=(20, 6))

    inf = tk.Frame(dlg, bg=CARD, padx=20, pady=14)
    inf.pack(fill="x", padx=20, pady=6)

    rx_s, tx_s, rx_t, tx_t = controller.traffic.get(ip)
    usage_rx, usage_tx     = controller.traffic.get_usage(ip)
    cut_txt = ("LOCKED (watchdog active)" if dev.cut
               else ("LIMITED" if dev.limited else "ONLINE"))

    rows = [
        ("IP Address",   dev.ip),
        ("Identity",     dev.identity or "—"),
        ("MAC Address",  dev.mac or "—"),
        ("Nickname",     dev.nickname or "—"),
        ("Hostname",     dev.hostname or "—"),
        ("Vendor",       dev.vendor or "—"),
        ("OS Guess",     dev.os_guess or "—"),
        ("Open Ports",   ", ".join(str(p) for p in dev.open_ports) or "—"),
        ("Services",     "; ".join(f"{p}:{s[:18]}"
                                   for p, s in list(dev.services.items())[:4]) or "—"),
        ("Status",       cut_txt),
        ("Limit",        f"{dev.limit_kb} KB/s" if dev.limited else "—"),
        ("Last Seen",    dev.last_seen),
        ("↓ DL Speed",   "BLOCKED" if dev.cut else fmt_speed(rx_s)),
        ("↑ UL Speed",   "BLOCKED" if dev.cut else fmt_speed(tx_s)),
        ("↓ Session DL", fmt_total(usage_rx)),
        ("↑ Session UL", fmt_total(usage_tx)),
        ("↓ Total RX",   fmt_total(rx_t or usage_rx)),
        ("↑ Total TX",   fmt_total(tx_t or usage_tx)),
    ]
    for k, v in rows:
        r = tk.Frame(inf, bg=CARD); r.pack(fill="x", pady=1)
        kc = GREEN if k.startswith("↓") else (CYAN if k.startswith("↑") else MUTED)
        vc = RED if ("BLOCKED" in str(v) or "LOCKED" in str(v)) else TEXT
        tk.Label(r, text=k+":", bg=CARD, fg=kc,
                 font=FONT_SMALL, width=13, anchor="w").pack(side="left")
        tk.Label(r, text=str(v), bg=CARD, fg=vc,
                 font=FONT_BODY, anchor="w").pack(side="left")

    # ── Action buttons ────────────────────────────────────────────────────────
    btn_row = tk.Frame(dlg, bg=PANEL)
    btn_row.pack(pady=(10, 4))

    rl = tk.Label(dlg, text="", bg=PANEL, fg=GREEN, font=FONT_SMALL, wraplength=460)
    rl.pack(padx=16)

    def _btn(parent, txt, cmd, bg, fg=BG):
        return tk.Button(parent, text=txt, command=cmd,
                         bg=bg, fg=fg, font=FONT_SMALL,
                         relief="flat", bd=0, padx=10, pady=6, cursor="hand2",
                         activebackground=bg)

    def do_ping():
        rl.config(text=f"Pinging {ip}…", fg=MUTED)
        def _go():
            r = subprocess.run(["ping", "-c", "4", "-W", "1", ip],
                               capture_output=True, text=True)
            lines = r.stdout.strip().split("\n")
            result = lines[-1] if lines else "No response"
            dlg.after(0, lambda: rl.config(text=result, fg=TEAL))
        import threading; threading.Thread(target=_go, daemon=True).start()

    def do_traceroute():
        cmd = shutil.which("traceroute") or shutil.which("tracepath")
        if not cmd:
            rl.config(text="traceroute not found", fg=RED); return
        rl.config(text="Running traceroute… (see log)", fg=MUTED)
        def _go():
            r = subprocess.run([cmd, ip], capture_output=True, text=True, timeout=25)
            dlg.after(0, lambda: rl.config(text="Traceroute done — see main log", fg=TEAL))
        import threading; threading.Thread(target=_go, daemon=True).start()

    def do_fingerprint():
        rl.config(text=f"Fingerprinting {ip}…", fg=AMBER)
        def _done(ip, dev):
            txt = f"{dev.identity}  OS:{dev.os_guess or '?'}"
            dlg.after(0, lambda: rl.config(text=txt, fg=GREEN))
            if fingerprint_done_cb:
                fingerprint_done_cb(ip, dev)
        controller.fingerprint(ip, done_cb=_done)

    def do_reset_usage():
        controller.reset_usage(ip)
        rl.config(text=f"Usage counters reset for {ip}", fg=GREEN)

    row2 = tk.Frame(dlg, bg=PANEL); row2.pack(pady=2)

    _btn(btn_row, "PING",         do_ping,       GLOW,    "#fff").pack(side="left", padx=3)
    _btn(btn_row, "TRACEROUTE",   do_traceroute, TEAL,    BG  ).pack(side="left", padx=3)
    _btn(btn_row, "FINGERPRINT",  do_fingerprint,BLUE,    "#fff").pack(side="left", padx=3)
    _btn(btn_row, "↺ RESET USAGE",do_reset_usage,MUTED,   TEXT ).pack(side="left", padx=3)
    _btn(row2,    "CLOSE",        dlg.destroy,   BORDER,  TEXT ).pack(pady=4)
