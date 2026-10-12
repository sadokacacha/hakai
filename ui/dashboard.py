"""
ui/dashboard.py — Sovereign Apex Edition (Persistent Architecture)
Framework: customtkinter
"""
from __future__ import annotations
import os
import threading
import time
import customtkinter as ctk
from datetime import datetime
from tkinter import messagebox, simpledialog

from core.persistence import fmt_speed, fmt_total, fmt_mbps, classify_device, db
from ui.theme import *
from ui.limit_dialog import show_limit_dialog

COLS = [
    ("●", 30), ("IP ADDRESS", 140), ("IDENTITY", 320),
    ("HOSTNAME", 180), ("STATUS", 120), ("TOTAL (↓/↑)", 200)
]

class Dashboard(ctk.CTk):
    def __init__(self, controller):
        super().__init__()
        self.ctrl = controller
        self._rows: dict[str, dict] = {}
        self._sel_ips: set[str] = set()

        # --- Window Config ---
        self.title("HAKAI v3 // SOVEREIGN APEX")
        self.geometry("1400x850")
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=BG)

        # --- Set Sovereign Icon ---
        try:
            from PIL import Image, ImageTk
            icon_p = os.path.join(os.path.dirname(__file__), "..", "assets", "icon.png")
            if os.path.exists(icon_p):
                icon_img = ImageTk.PhotoImage(Image.open(icon_p).resize((64, 64)))
                self.wm_iconphoto(True, icon_img)
        except Exception: pass

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        
        # --- Multi-Panel System (Persistent) ---
        self.main_container = ctk.CTkFrame(self, corner_radius=15, fg_color=BG, border_width=0)
        self.main_container.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
        
        self.off_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.aeg_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        
        self._build_offensive_view()
        self._build_aegis_view()
        
        self.show_offensive()
        self._refresh_loop()
        
        self.ctrl.on_protection_alert = lambda m: self.log_tactical(m, "danger")
        self.log_tactical("[SYSTEM: ONLINE]", "success")

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=PANEL)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(self.sidebar, text="🔱 HAKAI v3", font=FONT_TITLE, text_color=ACCENT).pack(pady=(40, 20))
        
        self.btn_sword = ctk.CTkButton(self.sidebar, text="⚔️  OFFENSIVE", font=FONT_HEADER,
                                      fg_color=SEL, text_color=TEXT, hover_color=SEL,
                                      anchor="w", height=45, command=self.show_offensive)
        self.btn_sword.pack(fill="x", padx=20, pady=5)

        self.btn_aegis = ctk.CTkButton(self.sidebar, text="🛡️  AEGIS (SAFE)", font=FONT_HEADER,
                                      fg_color="transparent", text_color=TEXT, hover_color=SEL,
                                      anchor="w", height=45, command=self.show_aegis)
        self.btn_aegis.pack(fill="x", padx=20, pady=5)

        self.status_box = ctk.CTkTextbox(self.sidebar, height=180, width=200, 
                                         font=(FONT_MONO[0], 10), fg_color="#000", border_width=0)
        self.status_box.pack(side="bottom", pady=20, padx=15)

    # ── View Persistence ────────────────────────────────────────────────────

    def show_offensive(self):
        self.aeg_frame.pack_forget()
        self.off_frame.pack(fill="both", expand=True)
        self.btn_sword.configure(fg_color=SEL)
        self.btn_aegis.configure(fg_color="transparent")

    def show_aegis(self):
        self.off_frame.pack_forget()
        self.aeg_frame.pack(fill="both", expand=True)
        self.btn_aegis.configure(fg_color=SEL)
        self.btn_sword.configure(fg_color="transparent")

    # ── Offensive Construction ──────────────────────────────────────────────

    def _build_offensive_view(self):
        bar = ctk.CTkFrame(self.off_frame, height=60, fg_color=PANEL, corner_radius=10)
        bar.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(bar, text="⟳ SCAN", width=100, fg_color=ACCENT, text_color=BG,
                      font=FONT_SMALL, command=self._start_scan).pack(side="left", padx=10)

        self.sel_lbl = ctk.CTkLabel(bar, text="NO SELECTION", font=FONT_SMALL, text_color=MUTED)
        self.sel_lbl.pack(side="left", padx=10)

        ctk.CTkButton(bar, text="✕ CLEAR", width=60, fg_color="transparent", text_color=MUTED, border_width=1, border_color=MUTED,
                      font=FONT_SMALL, command=self._cmd_clear_sel).pack(side="left", padx=5)

        # Right-side action buttons
        ctk.CTkButton(bar, text="✕ CUT", width=80, fg_color=RED, text_color=BG,
                      font=FONT_SMALL, command=self._cmd_cut).pack(side="right", padx=5)
        ctk.CTkButton(bar, text="↺ RESTORE", width=90, fg_color=GREEN, text_color=BG,
                      font=FONT_SMALL, command=self._cmd_restore).pack(side="right", padx=5)
        ctk.CTkButton(bar, text="⚡ LIMIT", width=80, fg_color=GOLD, text_color=BG,
                      font=FONT_SMALL, command=self._cmd_limit).pack(side="right", padx=5)
        ctk.CTkButton(bar, text="∞ UNLIMIT", width=90, fg_color=TEAL, text_color=BG,
                      font=FONT_SMALL, command=self._cmd_unlimit).pack(side="right", padx=5)
        ctk.CTkButton(bar, text="✏️ RENAME", width=90, fg_color=BLUE, text_color=BG,
                      font=FONT_SMALL, command=self._cmd_rename).pack(side="right", padx=5)

        # --- Table & Intel Split ---
        content_split = ctk.CTkFrame(self.off_frame, fg_color="transparent")
        content_split.pack(fill="both", expand=True)

        table_wrap = ctk.CTkScrollableFrame(content_split, fg_color=BG)
        table_wrap.pack(side="left", fill="both", expand=True, padx=(10, 5), pady=5)
        
        # Target Intel Sidebar
        self.intel_frame = ctk.CTkFrame(content_split, width=280, fg_color=PANEL, corner_radius=15)
        self.intel_frame.pack(side="right", fill="y", padx=(5, 10), pady=10)
        self.intel_frame.pack_propagate(False)

        ctk.CTkLabel(self.intel_frame, text="🛰️ TARGET INTEL", font=FONT_HEADER, text_color=ACCENT).pack(pady=20)
        
        self.intel_brand = ctk.CTkLabel(self.intel_frame, text="[BRAND: —]", font=FONT_SMALL, text_color=MUTED, anchor="w")
        self.intel_brand.pack(fill="x", padx=20, pady=5)
        
        self.intel_os = ctk.CTkLabel(self.intel_frame, text="[OS: SCANNING]", font=FONT_SMALL, text_color=MUTED, anchor="w")
        self.intel_os.pack(fill="x", padx=20, pady=5)
        
        self.intel_name = ctk.CTkLabel(self.intel_frame, text="[NAME: HIDDEN]", font=FONT_SMALL, text_color=MUTED, anchor="w")
        self.intel_name.pack(fill="x", padx=20, pady=5)

        h_row = ctk.CTkFrame(table_wrap, fg_color=PANEL, height=35)
        h_row.pack(fill="x", pady=(0, 5))
        for txt, w in COLS:
            ctk.CTkLabel(h_row, text=txt, width=w, font=FONT_SMALL, text_color=MUTED, anchor="w").pack(side="left", padx=5)

        self.table_container = table_wrap

    # ── Aegis Construction ──────────────────────────────────────────────────

    def _build_aegis_view(self):
        header = ctk.CTkLabel(self.aeg_frame, text="🛡️ SOVEREIGN AEGIS CONFIGURATION", font=FONT_HEADER, text_color=ACCENT)
        header.pack(pady=30)

        grid = ctk.CTkFrame(self.aeg_frame, fg_color="transparent")
        grid.pack(expand=True, fill="both", padx=40)

        self._create_card(grid, "GHOST FIREWALL", "Invisible to Probes", 
                         self.ctrl.firewall.active, self._toggle_ghost).grid(row=0, column=0, padx=15, pady=15)
        
        self._create_card(grid, "ARP SELF-HEALING", "Lock Gateway", 
                         self.ctrl.protector.arp_guard_enabled, self._toggle_arp).grid(row=0, column=1, padx=15, pady=15)

        self._create_card(grid, "CHAMELEON ENGINE", "Signature Evasion", 
                         False, self._toggle_chameleon).grid(row=1, column=0, padx=15, pady=15)

        self._create_card(grid, "IPv6 DARK SECTOR", "RA + DHCPv6 Spoof", 
                         False, self._toggle_ipv6).grid(row=1, column=1, padx=15, pady=15)

        # Nuclear Ghost Master Switch
        nuclear_frame = ctk.CTkFrame(grid, fg_color=SEL, corner_radius=15, border_width=2, border_color=ACCENT)
        nuclear_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=15, pady=15)
        ctk.CTkLabel(nuclear_frame, text="☢️ NUCLEAR GHOST", font=FONT_HEADER, text_color=ACCENT).pack(pady=(20, 5))
        ctk.CTkLabel(nuclear_frame, text="TOTAL INVISIBILITY MODE", font=FONT_SMALL, text_color=TEXT).pack(pady=5)
        self.nuclear_switch = ctk.CTkSwitch(nuclear_frame, text="ENGAGE", font=FONT_SMALL, 
                                           progress_color=ACCENT, command=self._toggle_nuclear)
        self.nuclear_switch.pack(pady=20)

    def _create_card(self, master, title, desc, init_state, command):
        card = ctk.CTkFrame(master, width=320, height=180, fg_color=CARD, corner_radius=15)
        card.pack_propagate(False)
        ctk.CTkLabel(card, text=title, font=FONT_HEADER).pack(pady=(25, 0))
        ctk.CTkLabel(card, text=desc, font=FONT_SMALL, text_color=MUTED).pack(pady=5)
        switch = ctk.CTkSwitch(card, text="ACTIVATE", progress_color=ACCENT, command=command)
        if init_state: switch.select()
        switch.pack(pady=20)
        return card

    # ── Refresh Loop ────────────────────────────────────────────────────────

    def _refresh_loop(self):
        from core.persistence import classify_device
        self.ctrl.update_device_speeds()
        self.ctrl.flush_hostnames()

        # Snapshot under the controller lock — sniffer threads mutate
        # self.ctrl.devices concurrently, so iterating it live can raise
        # "dictionary changed size during iteration".
        devs_snapshot = self.ctrl.snapshot_devices()

        # Re-classify any device whose identity is still weak — fingerprinting
        # and mDNS intel fill in data asynchronously; this picks it up live.
        _weak = ("", "❓ Scanning...", "❓ Unknown", "Unknown", "?")
        for dev in devs_snapshot:
            if not dev.identity or dev.identity in _weak:
                dev.identity = classify_device(dev)

        current_ips = {d.ip for d in devs_snapshot}
        for ip in list(self._rows.keys()):
            if ip not in current_ips:
                self._rows[ip]["frame"].destroy()
                del self._rows[ip]

        def _ip_sort_key(d):
            try:
                return [int(p) for p in d.ip.split(".")]
            except (ValueError, AttributeError):
                return [0, 0, 0, 0]

        devs = sorted(devs_snapshot, key=_ip_sort_key)
        for i, d in enumerate(devs):
            if d.ip not in self._rows:
                self._make_row(d.ip, d, i)
            else:
                self._update_row(d.ip)

        self.after(1200, self._refresh_loop)


    def _make_row(self, ip, dev, idx):
        bg = CARD if idx % 2 == 0 else BG
        row = ctk.CTkFrame(self.table_container, fg_color=bg, height=40, corner_radius=0)
        row.pack(fill="x", pady=1)
        row.pack_propagate(False)
        row.bind("<Button-1>", lambda e, _ip=ip: self._select(_ip, e))
        
        lbls = {}
        def _lbl(txt, w, col=TEXT):
            l = ctk.CTkLabel(row, text=str(txt), width=w, font=FONT_MONO, text_color=col, anchor="w")
            l.pack(side="left", padx=5)
            # Return "break" to stop the event from bubbling up to the row frame.
            l.bind("<Button-1>", lambda e, _ip=ip: (self._select(_ip, e), "break")[-1])
            return l

        lbls["dot"] = _lbl("●", 30, GREEN)
        lbls["ip"]  = _lbl(ip, 140)
        lbls["id"]  = _lbl(dev.identity or "Unknown", 320, TEAL)
        lbls["hn"]  = _lbl(dev.hostname or "—", 180, ACCENT)
        lbls["st"]  = _lbl("ONLINE", 120, GREEN)
        lbls["tot"] = _lbl("0 B", 200, MUTED)

        self._rows[ip] = {"frame": row, "labels": lbls, "idx": idx}

    def _update_row(self, ip):
        rd = self._rows.get(ip); dev = self.ctrl.devices.get(ip)
        if not rd or not dev: return

        try:
            if not rd["frame"].winfo_exists(): return

            row_bg = SEL if ip in self._sel_ips else (CARD if rd["idx"] % 2 == 0 else BG)
            rd["frame"].configure(fg_color=row_bg)
            for lbl in rd["labels"].values():
                if lbl.winfo_exists(): lbl.configure(fg_color=row_bg)

            rx_s, tx_s, _, _ = self.ctrl.traffic.get(ip)
            sess_rx, sess_tx  = self.ctrl.traffic.get_usage(ip)
            mode              = self.ctrl.traffic.get_mode(ip)  # 'MITM' or 'PASSIVE'

            rd["labels"]["id"].configure(text=dev.identity or "❓ Scanning...")
            rd["labels"]["hn"].configure(text=dev.hostname or "—")

            # ── Status: shows CUT / LIMIT / MITM / PASSIVE ───────────────
            if dev.cut:
                status_txt, status_col = "🔒 CUT",              RED
            elif dev.limited:
                status_txt, status_col = f"⚡ {dev.limit_kb}KB", GOLD
            elif mode == "MITM":
                status_txt, status_col = "◉ MITM",              GREEN
            else:
                status_txt, status_col = "◌ PASSIVE",           AMBER

            rd["labels"]["st"].configure(text=status_txt, text_color=status_col)

            # ── Total Usage ───────────────────────────────────────────────
            rd["labels"]["tot"].configure(text=f"↓ {fmt_total(sess_rx)}  ↑ {fmt_total(sess_tx)}")

        except (ctk.TclError, KeyError, RuntimeError):
            pass  # Widget likely destroyed during refresh

    # ── Command Proxies ─────────────────────────────────────────────────────

    def log_tactical(self, msg, type="info"):
        ts = datetime.now().strftime("%H:%M")
        self.status_box.insert("end", f"\n[{ts}] {msg}")
        self.status_box.see("end")

    def _start_scan(self):
        self.log_tactical("INITIATING SCAN...", "info")
        threading.Thread(target=self.ctrl.scan, args=(self.log_tactical,), daemon=True).start()

    def _cmd_clear_sel(self):
        self._sel_ips.clear()
        self.sel_lbl.configure(text="NO SELECTION")
        for r_ip in list(self._rows.keys()):
            self._update_row(r_ip)

    def _select(self, ip, event=None):
        multi = False
        if event and hasattr(event, 'state'):
            if event.state & 0x0004 or event.state & 0x0001:  # Ctrl or Shift
                multi = True

        if not multi:
            if ip in self._sel_ips and len(self._sel_ips) == 1:
                self._sel_ips.clear()
            else:
                self._sel_ips.clear()
                self._sel_ips.add(ip)
        else:
            if ip in self._sel_ips:
                self._sel_ips.remove(ip)
            else:
                self._sel_ips.add(ip)

        self.sel_lbl.configure(text=f"{len(self._sel_ips)} SELECTED" if self._sel_ips else "NO SELECTION")
        
        # Update all rows since selection changed
        for r_ip in list(self._rows.keys()):
            self._update_row(r_ip)
        
        # Update Intel Panel for the most recently selected device
        dev = self.ctrl.devices.get(ip)
        if dev:
            self.intel_brand.configure(text=f"[BRAND: {dev.vendor or '—'}]", text_color=GOLD if dev.vendor else MUTED)
            self.intel_os.configure(text=f"[OS: {dev.os_guess or 'SCANNING'}]", text_color=TEAL if dev.os_guess else MUTED)
            self.intel_name.configure(text=f"[NAME: {dev.hostname or 'HIDDEN'}]", text_color=BLUE if dev.hostname else MUTED)
            self.log_tactical(f"[INTEL: {ip} UNMASKED]", "info")

    def _cmd_cut(self):
        for ip in list(self._sel_ips):
            self.ctrl.cut_device(ip, log=self.log_tactical)

    def _cmd_restore(self):
        for ip in list(self._sel_ips):
            self.ctrl.restore_device(ip, log=self.log_tactical)

    def _cmd_limit(self):
        """Open limit dialog for the first selected device; apply to all selected."""
        ips = list(self._sel_ips)
        if not ips:
            self.log_tactical("No device selected — click a row first.", "warn")
            return
        # Show dialog for the first IP; extra_ips are the rest
        ip      = ips[0]
        dev     = self.ctrl.devices.get(ip)
        if not dev:
            return
        extra   = ips[1:]

        def _apply(target_ip, kb):
            # Apply to the device shown in the dialog
            ok = self.ctrl.limit_device(target_ip, kb, log=self.log_tactical)
            if not ok:
                self.log_tactical(f"✕ TC limit failed for {target_ip} — check iface", "err")
            else:
                self._update_row(target_ip)
            # Apply the same limit to every other selected device
            for extra_ip in extra:
                e_dev = self.ctrl.devices.get(extra_ip)
                if e_dev and e_dev.status not in ("self",) and extra_ip != self.ctrl.net.gateway:
                    ok2 = self.ctrl.limit_device(extra_ip, kb, log=self.log_tactical)
                    if ok2:
                        self._update_row(extra_ip)

        show_limit_dialog(self, ip, dev, _apply, extra_ips=extra)

    def _cmd_unlimit(self):
        for ip in list(self._sel_ips):
            self.ctrl.unlimit_device(ip, log=self.log_tactical)
            self._update_row(ip)

    def _cmd_rename(self):
        ips = list(self._sel_ips)
        if not ips:
            self.log_tactical("No device selected for renaming.", "warn")
            return
        ip = ips[0]
        dev = self.ctrl.devices.get(ip)
        if not dev: return
        if not dev.mac:
            self.log_tactical(f"Cannot rename {ip} — MAC address not resolved yet.", "warn")
            return
            
        new_name = simpledialog.askstring("Rename Device", f"Enter custom nickname for {ip}\n(Leave blank to clear):", initialvalue=dev.nickname or "", parent=self)
        if new_name is not None:
            dev.nickname = new_name.strip()
            dev.identity = "" # Force re-classification to update UI immediately
            self.log_tactical(f"Renamed {ip} to '{dev.nickname}'" if dev.nickname else f"Cleared nickname for {ip}", "info")
            self._update_row(ip)

    def _toggle_nuclear(self):
        state = self.nuclear_switch.get()
        status = self.ctrl.toggle_nuclear_stealth(state, log=self.log_tactical)
        if state:
            self.log_tactical(f"CLOAK ENGAGED: {status}", "atk")
        else:
            self.log_tactical("SHIELDS DISENGAGED: IDENTITY RESTORED", "info")

    def _toggle_ghost(self): self.ctrl.toggle_ghost_firewall(not self.ctrl.firewall.active, log=self.log_tactical)
    def _toggle_arp(self): 
        if self.ctrl.protector.arp_guard_enabled: self.ctrl.protector.disable_arp_guard(log=self.log_tactical)
        else: self.ctrl.protector.enable_arp_guard(log=self.log_tactical)
    def _toggle_chameleon(self):
        # Check current state via MTU
        import subprocess
        res = subprocess.run(["ip", "link", "show", self.ctrl.net.iface], capture_output=True, text=True)
        is_active = "mtu 1492" in res.stdout
        self.ctrl.toggle_chameleon(not is_active, log=self.log_tactical)
    def _toggle_ipv6(self):
        # Toggle based on the hijacker's current running state so the switch
        # can turn the feature off as well as on.
        new_state = not self.ctrl.ipv6._running
        self.ctrl.toggle_ipv6_hijack(new_state, log=self.log_tactical)
    def _on_ttl_change(self, v): self.ctrl.toggle_stack_masquerade(v > 100, log=self.log_tactical)

    def on_close(self):
        self.ctrl.stop()
        self.destroy()