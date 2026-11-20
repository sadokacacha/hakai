"""
ui/protection_panel.py — Modal for Defensive & Stealth settings.

PP-1: every handler here drives ip/nft/sysctl subprocesses (directly, or via
controller toggles). Running them on the Tk thread froze the modal for seconds.
The blocking work is now offloaded to a daemon thread through `run_async`; button
state is gathered off the Tk thread by `_probe_state` and the resulting widget
writes are marshalled back onto the Tk thread with `dlg.after`.
"""
import logging
import subprocess
import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, simpledialog, ttk

from system.network_manager import apply_static_config, get_connections, set_dhcp
from system.stealth import PROFILES
from ui.async_util import run_async
from ui.theme import *

_log = logging.getLogger(__name__)


def _probe_state(
    ctrl, run: Callable[..., subprocess.CompletedProcess] = subprocess.run
) -> dict[str, bool]:
    """Gather the modal's button state. Safe to call off the Tk thread.

    Reads controller attributes and runs the two state-probe subprocesses
    (sysctl TTL as the masquerade proxy, ip-link MTU as the chameleon proxy).
    Touches no Tk widgets, so it can run on a worker thread and be unit-tested
    without a display. A failing probe degrades to ``False`` instead of
    propagating and breaking the handler.
    """
    state: dict[str, bool] = {
        "arp": bool(ctrl.protector.arp_guard_enabled),
        "ks": bool(ctrl.protector.kill_switch_enabled),
        "stealth": bool(ctrl.stealth_active),
        "fw": bool(ctrl.firewall.active),
        "mask": False,
        "cham": False,
    }
    try:
        res = run(["sysctl", "net.ipv4.ip_default_ttl"], capture_output=True, text=True)
        state["mask"] = "128" in res.stdout
    except (OSError, subprocess.SubprocessError) as e:
        _log.debug("protection_panel: sysctl TTL probe failed: %s", e)
    try:
        res = run(["ip", "link", "show", ctrl.net.iface], capture_output=True, text=True)
        state["cham"] = "mtu 1492" in res.stdout
    except (OSError, subprocess.SubprocessError) as e:
        _log.debug("protection_panel: ip-link MTU probe failed: %s", e)
    return state


def show_protection_panel(parent, ctrl, log_cb):
    dlg = tk.Toplevel(parent)
    dlg.title("🛡️ PROTECTION & STEALTH")
    dlg.geometry("540x620")
    dlg.configure(bg=PANEL)
    dlg.grab_set()

    # ── Header ────────────────────────────────────────────────────────────────
    tk.Label(dlg, text="🛡️  GUARDIAN SYSTEM", bg=PANEL, fg=ACCENT, font=FONT_HEADER).pack(pady=(20, 10))

    # ── ARP Guard & Kill-Switch ───────────────────────────────────────────────
    def toggle_arp():
        def act():
            if ctrl.protector.arp_guard_enabled:
                ctrl.protector.disable_arp_guard(log=log_cb)
            else:
                ctrl.protector.enable_arp_guard(log=log_cb)
        _offload(act, "pp_arp")

    def toggle_ks():
        def act():
            new_state = not ctrl.protector.kill_switch_enabled
            ctrl.protector.toggle_kill_switch(new_state, log=log_cb)
        _offload(act, "pp_ks")

    frame_def = tk.LabelFrame(dlg, text=" DEFENSE ", bg=PANEL, fg=MUTED, font=FONT_SMALL, padx=20, pady=15)
    frame_def.pack(fill="x", padx=30, pady=10)

    btn_arp = tk.Button(frame_def, text="🛡️ ARP GUARD: OFF", bg=CARD, fg=CYAN, relief="flat", font=FONT_SMALL, width=25, command=toggle_arp)
    btn_arp.pack(pady=4)

    btn_ks = tk.Button(frame_def, text="🚨 KILL-SWITCH: OFF", bg=CARD, fg=RED, relief="flat", font=FONT_SMALL, width=25, command=toggle_ks)
    btn_ks.pack(pady=4)

    # ── Stealth Profiles ──────────────────────────────────────────────────────
    frame_stl = tk.LabelFrame(dlg, text=" STEALTH PROFILES ", bg=PANEL, fg=MUTED, font=FONT_SMALL, padx=20, pady=15)
    frame_stl.pack(fill="x", padx=30, pady=10)

    prof_var = tk.StringVar(value="RANDOM")
    prof_list = ["RANDOM"] + [p["name"] for p in PROFILES]

    prof_cb = ttk.Combobox(frame_stl, textvariable=prof_var, values=prof_list, state="readonly", width=22)
    prof_cb.pack(pady=10)

    def apply_stealth():
        profile = prof_var.get()  # Tk var read — must happen on the UI thread.
        _offload(lambda: ctrl.toggle_stealth(True, profile=profile, log=log_cb), "pp_stealth")

    def stop_stealth():
        _offload(lambda: ctrl.toggle_stealth(False, log=log_cb), "pp_stealth_off")

    btn_stl = tk.Button(frame_stl, text="🎭 APPLY IDENTITY", bg=AMBER, fg=BG, relief="flat", font=FONT_SMALL, width=25, command=apply_stealth)
    btn_stl.pack(pady=4)

    btn_rst = tk.Button(frame_stl, text="↺ RESTORE REAL ID", bg=MUTED, fg=BG, relief="flat", font=FONT_SMALL, width=25, command=stop_stealth)
    btn_rst.pack(pady=4)

    # ── Network Config ────────────────────────────────────────────────────────
    frame_net = tk.LabelFrame(dlg, text=" STATIC IP CONFIG (NMCLI) ", bg=PANEL, fg=MUTED, font=FONT_SMALL, padx=20, pady=15)
    frame_net.pack(fill="x", padx=30, pady=10)

    conns = get_connections()
    conn_var = tk.StringVar(value=conns[0] if conns else "None")

    if conns:
        ttk.Combobox(frame_net, textvariable=conn_var, values=conns, state="readonly", width=22).pack()
    else:
        tk.Label(frame_net, text="No active NMCLI connections found", bg=PANEL, fg=RED, font=FONT_SMALL).pack()

    def set_static():
        # Modal prompts stay on the UI thread; only the nmcli apply is offloaded.
        ip = simpledialog.askstring("Static IP", "Enter IP/Prefix (e.g. 192.168.1.50/24):")
        if not ip: return
        gw = simpledialog.askstring("Gateway", "Enter Gateway IP:")
        if not gw: return
        dns = simpledialog.askstring("DNS", "Enter DNS (comma separated):", initialvalue="8.8.8.8,1.1.1.1")
        if not dns: return
        conn = conn_var.get()

        def work():
            ok, msg = apply_static_config(conn, ip, gw, dns)
            _marshal(lambda: _report_net(ok, msg))
        run_async(work, name="pp_static")

    def set_auto():
        conn = conn_var.get()

        def work():
            ok, msg = set_dhcp(conn)
            _marshal(lambda: _report_net(ok, msg))
        run_async(work, name="pp_dhcp")

    def _report_net(ok: bool, msg: str) -> None:
        # Tk thread only: dialog + log after an nmcli apply.
        if ok:
            messagebox.showinfo("Success", msg)
            log_cb(msg, "ok")
        else:
            messagebox.showerror("Error", msg)
            log_cb(msg, "err")

    btn_static = tk.Button(frame_net, text="📡 SET STATIC CONFIG", bg=CARD, fg=TEAL, relief="flat", font=FONT_SMALL, width=25, command=set_static)
    btn_static.pack(pady=(10, 4))

    btn_dhcp = tk.Button(frame_net, text="📡 REVERT TO DHCP", bg=CARD, fg=MUTED, relief="flat", font=FONT_SMALL, width=25, command=set_auto)
    btn_dhcp.pack(pady=4)

    # ── Apex Defense ──────────────────────────────────────────────────────────
    frame_apex = tk.LabelFrame(dlg, text=" SOVEREIGN APEX ", bg=PANEL, fg=GOLD, font=FONT_SMALL, padx=20, pady=15)
    frame_apex.pack(fill="x", padx=30, pady=10)

    def toggle_firewall():
        def act():
            new_state = not ctrl.firewall.active
            ctrl.toggle_ghost_firewall(new_state, log=log_cb)
        _offload(act, "pp_firewall")

    def toggle_stack():
        def act():
            # Check current TTL as a proxy for state (off the Tk thread now).
            try:
                res = subprocess.run(["sysctl", "net.ipv4.ip_default_ttl"], capture_output=True, text=True)
                is_active = "128" in res.stdout
            except (OSError, subprocess.SubprocessError):
                is_active = False
            ctrl.toggle_stack_masquerade(not is_active, log=log_cb)
        _offload(act, "pp_stack")

    btn_ghost = tk.Button(frame_apex, text="👻 GHOST FIREWALL: OFF", bg=CARD, fg=GOLD, relief="flat", font=FONT_SMALL, width=25, command=toggle_firewall)
    btn_ghost.pack(pady=4)

    btn_mask = tk.Button(frame_apex, text="🎭 STACK MASQUERADE: OFF", bg=CARD, fg=TEAL, relief="flat", font=FONT_SMALL, width=25, command=toggle_stack)
    btn_mask.pack(pady=4)

    def toggle_chameleon():
        def act():
            # Check current MTU (off the Tk thread now).
            try:
                res = subprocess.run(["ip", "link", "show", ctrl.net.iface], capture_output=True, text=True)
                is_active = "mtu 1492" in res.stdout
            except (OSError, subprocess.SubprocessError):
                is_active = False
            ctrl.toggle_chameleon(not is_active, log=log_cb)
        _offload(act, "pp_chameleon")

    btn_cham = tk.Button(frame_apex, text="🧬 CHAMELEON: OFF", bg=CARD, fg=MUTED, relief="flat", font=FONT_SMALL, width=25, command=toggle_chameleon)
    btn_cham.pack(pady=4)

    # ── Button state: gather off-thread, render on the Tk thread ──────────────
    def _render(state: dict[str, bool]) -> None:
        # Tk thread only: widget writes.
        s_arp = "ON" if state["arp"] else "OFF"
        btn_arp.config(text=f"🛡️ ARP GUARD: {s_arp}", bg=GREEN if state["arp"] else CARD, fg=BG if state["arp"] else CYAN)

        s_ks = "ON" if state["ks"] else "OFF"
        btn_ks.config(text=f"🚨 KILL-SWITCH: {s_ks}", bg=RED if state["ks"] else CARD, fg=BG if state["ks"] else RED)

        s_st = "ACTIVE" if state["stealth"] else "OFF"
        btn_stl.config(text=f"🎭 STEALTH: {s_st}", bg=GOLD if state["stealth"] else AMBER)

        s_fw = "LOCKED" if state["fw"] else "OFF"
        btn_ghost.config(text=f"👻 GHOST FW: {s_fw}", bg=GOLD if state["fw"] else CARD, fg=BG if state["fw"] else GOLD)

        s_mask = "Mimic" if state["mask"] else "OFF"
        btn_mask.config(text=f"🎭 MASQUERADE: {s_mask}", bg=TEAL if state["mask"] else CARD, fg=BG if state["mask"] else TEAL)

        s_cham = "ACTIVE" if state["cham"] else "OFF"
        btn_cham.config(text=f"🧬 CHAMELEON: {s_cham}", bg=BLUE if state["cham"] else CARD, fg=BG if state["cham"] else MUTED)

    def _marshal(fn: Callable[[], None]) -> None:
        # Schedule a Tk-thread callback; the dialog may already be closed.
        try:
            dlg.after(0, fn)
        except tk.TclError:
            _log.debug("protection_panel: dialog closed before UI refresh")

    def refresh_btns() -> None:
        def work():
            state = _probe_state(ctrl)
            _marshal(lambda: _render(state))
        run_async(work, name="pp_refresh")

    def _offload(action: Callable[[], None], name: str) -> None:
        # Run a blocking toggle off the Tk thread, then refresh the buttons.
        def work():
            action()
            state = _probe_state(ctrl)
            _marshal(lambda: _render(state))
        run_async(work, name=name)

    refresh_btns()
    tk.Button(dlg, text="CLOSE", bg=DARK_P, fg=TEXT, relief="flat", command=dlg.destroy, font=FONT_SMALL, padx=30).pack(pady=20)
