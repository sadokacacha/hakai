"""
ui/protection_panel.py — Modal for Defensive & Stealth settings.
"""
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from system.network_manager import apply_static_config, get_connections, set_dhcp
from system.stealth import PROFILES
from ui.theme import *


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
        if ctrl.protector.arp_guard_enabled:
            ctrl.protector.disable_arp_guard(log=log_cb)
        else:
            ctrl.protector.enable_arp_guard(log=log_cb)
        update_btns()

    def toggle_ks():
        new_state = not ctrl.protector.kill_switch_enabled
        ctrl.protector.toggle_kill_switch(new_state, log=log_cb)
        update_btns()

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
        ctrl.toggle_stealth(True, profile=prof_var.get(), log=log_cb)
        update_btns()
        
    def stop_stealth():
        ctrl.toggle_stealth(False, log=log_cb)
        update_btns()

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
        # Quick prompts for IP/GW/DNS
        ip = simpledialog.askstring("Static IP", "Enter IP/Prefix (e.g. 192.168.1.50/24):")
        if not ip: return
        gw = simpledialog.askstring("Gateway", "Enter Gateway IP:")
        if not gw: return
        dns = simpledialog.askstring("DNS", "Enter DNS (comma separated):", initialvalue="8.8.8.8,1.1.1.1")
        if not dns: return
        
        ok, msg = apply_static_config(conn_var.get(), ip, gw, dns)
        if ok: messagebox.showinfo("Success", msg); log_cb(msg, "ok")
        else: messagebox.showerror("Error", msg); log_cb(msg, "err")

    def set_auto():
        ok, msg = set_dhcp(conn_var.get())
        if ok: messagebox.showinfo("Success", msg); log_cb(msg, "ok")
        else: messagebox.showerror("Error", msg); log_cb(msg, "err")

    btn_static = tk.Button(frame_net, text="📡 SET STATIC CONFIG", bg=CARD, fg=TEAL, relief="flat", font=FONT_SMALL, width=25, command=set_static)
    btn_static.pack(pady=(10, 4))
    
    btn_dhcp = tk.Button(frame_net, text="📡 REVERT TO DHCP", bg=CARD, fg=MUTED, relief="flat", font=FONT_SMALL, width=25, command=set_auto)
    btn_dhcp.pack(pady=4)

    # ── Apex Defense ──────────────────────────────────────────────────────────
    frame_apex = tk.LabelFrame(dlg, text=" SOVEREIGN APEX ", bg=PANEL, fg=GOLD, font=FONT_SMALL, padx=20, pady=15)
    frame_apex.pack(fill="x", padx=30, pady=10)

    def toggle_firewall():
        new_state = not ctrl.firewall.active
        ctrl.toggle_ghost_firewall(new_state, log=log_cb)
        update_btns()

    def toggle_stack():
        # Check current TTL as a proxy for state
        import subprocess
        res = subprocess.run(["sysctl", "net.ipv4.ip_default_ttl"], capture_output=True, text=True)
        is_active = "128" in res.stdout
        ctrl.toggle_stack_masquerade(not is_active, log=log_cb)
        update_btns()

    btn_ghost = tk.Button(frame_apex, text="👻 GHOST FIREWALL: OFF", bg=CARD, fg=GOLD, relief="flat", font=FONT_SMALL, width=25, command=toggle_firewall)
    btn_ghost.pack(pady=4)

    btn_mask = tk.Button(frame_apex, text="🎭 STACK MASQUERADE: OFF", bg=CARD, fg=TEAL, relief="flat", font=FONT_SMALL, width=25, command=toggle_stack)
    btn_mask.pack(pady=4)

    def toggle_chameleon():
        # Check current MTU
        import subprocess
        res = subprocess.run(["ip", "link", "show", ctrl.net.iface], capture_output=True, text=True)
        is_active = "mtu 1492" in res.stdout
        ctrl.toggle_chameleon(not is_active, log=log_cb)
        update_btns()

    btn_cham = tk.Button(frame_apex, text="🧬 CHAMELEON: OFF", bg=CARD, fg=MUTED, relief="flat", font=FONT_SMALL, width=25, command=toggle_chameleon)
    btn_cham.pack(pady=4)

    def update_btns():
        s_arp = "ON" if ctrl.protector.arp_guard_enabled else "OFF"
        btn_arp.config(text=f"🛡️ ARP GUARD: {s_arp}", bg=GREEN if s_arp=="ON" else CARD, fg=BG if s_arp=="ON" else CYAN)
        
        s_ks = "ON" if ctrl.protector.kill_switch_enabled else "OFF"
        btn_ks.config(text=f"🚨 KILL-SWITCH: {s_ks}", bg=RED if s_ks=="ON" else CARD, fg=BG if s_ks=="ON" else RED)
        
        s_st = "ACTIVE" if ctrl.stealth_active else "OFF"
        btn_stl.config(text=f"🎭 STEALTH: {s_st}", bg=GOLD if s_st=="ACTIVE" else AMBER)

        s_fw = "LOCKED" if ctrl.firewall.active else "OFF"
        btn_ghost.config(text=f"👻 GHOST FW: {s_fw}", bg=GOLD if s_fw=="LOCKED" else CARD, fg=BG if s_fw=="LOCKED" else GOLD)

        # Quick check for TTL
        import subprocess
        res = subprocess.run(["sysctl", "net.ipv4.ip_default_ttl"], capture_output=True, text=True)
        s_mask = "Mimic" if "128" in res.stdout else "OFF"
        btn_mask.config(text=f"🎭 MASQUERADE: {s_mask}", bg=TEAL if s_mask=="Mimic" else CARD, fg=BG if s_mask=="Mimic" else TEAL)

        # Chameleon check
        import subprocess
        res = subprocess.run(["ip", "link", "show", ctrl.net.iface], capture_output=True, text=True)
        s_cham = "ACTIVE" if "mtu 1492" in res.stdout else "OFF"
        btn_cham.config(text=f"🧬 CHAMELEON: {s_cham}", bg=BLUE if s_cham=="ACTIVE" else CARD, fg=BG if s_cham=="ACTIVE" else MUTED)

    update_btns()
    tk.Button(dlg, text="CLOSE", bg=DARK_P, fg=TEXT, relief="flat", command=dlg.destroy, font=FONT_SMALL, padx=30).pack(pady=20)
