"""
ui/main_window.py — Lanwarden PySide6 main window.

Layout: left sidebar (Warden / Keeper / Watch / Scope sections) | central device
table | right detail pane (device info + live pyqtgraph traffic) | bottom status
bar. Dark, dense, flat. Every privileged action runs off the Qt thread via
ui.workers.submit and marshals back through signals; the GUI thread never blocks.

Sections (named from the P5 shortlist):
  Warden — cut / restore / limit / rename (control of a device)
  Keeper — ARP guard, kill switch, stealth, ghost firewall, masquerade,
           chameleon, nuclear, IPv6, static-IP (protection / posture)
  Watch  — device discovery, the table, live traffic
  Scope  — per-device ping / traceroute / fingerprint / recon / DNS / monitor
"""

from __future__ import annotations

import collections
import subprocess

import pyqtgraph as pg
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.identity import display_name
from core.persistence import fmt_speed
from system.network_manager import apply_static_config, get_connections, set_dhcp
from ui.theme import ACCENT, GREEN, MUTED, PANEL, QSS, RED, STATE_STYLES, TEXT
from ui.workers import submit

_COLS = ["IP", "MAC", "Name", "Vendor", "Status", "RX", "TX"]


class LanwardenWindow(QWidget):
    def __init__(self, ctrl):
        super().__init__()
        self.ctrl = ctrl
        self._state = "empty"
        self._active_op = "—"
        self._last_error = "—"
        self._last_alert = "—"
        self._blackout_confirmed = False  # confirm dialog shown once per session
        # Protection alerts land here from the protector's sniffer thread. A
        # deque is the only cross-thread touch — never a Qt call off the GUI
        # thread (that flooded Qt during an ARP storm and could crash).
        self._alert_q: collections.deque = collections.deque(maxlen=64)
        self._hist: dict[str, collections.deque] = {}
        self.setWindowTitle("Lanwarden")
        self.resize(1180, 720)
        self.setStyleSheet(QSS)
        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1200)
        self._refresh()
        self._assess_capabilities()
        # Surface defensive alerts. The protector raises them from its scapy
        # sniffer thread, so the sink must NOT touch Qt: it only appends to the
        # thread-safe deque, which the GUI-thread refresh timer drains. This also
        # coalesces an ARP-storm of alerts into one update per tick instead of
        # flooding the Qt event loop with cross-thread signal deliveries.
        self.ctrl.set_alert_callback(self._alert_q.append)

    def _assess_capabilities(self) -> None:
        """Reflect real state at startup instead of always claiming 'normal':
        disconnected without an iface/gateway, degraded without nft/tc."""
        import shutil

        net = self.ctrl.net
        if not net.iface or not net.gateway:
            self.set_state("disconnected", "no interface / gateway")
            return
        missing = [b for b in ("nft", "tc") if not shutil.which(b)]
        if missing:
            self.set_state("degraded", "missing: " + ", ".join(missing))

    # ── layout ──────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.banner = QLabel(objectName="Banner")
        self.banner.setObjectName("State")
        self.banner.setContentsMargins(10, 6, 10, 6)
        root.addWidget(self.banner)

        split = QSplitter(Qt.Horizontal)
        split.addWidget(self._sidebar())
        split.addWidget(self._table_panel())
        split.addWidget(self._detail_panel())
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setStretchFactor(2, 0)
        split.setSizes([260, 620, 300])
        root.addWidget(split, 1)

        root.addWidget(self._status_bar())

    def _sidebar(self) -> QWidget:
        frame = QFrame(objectName="Sidebar")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(8, 10, 8, 10)
        lay.addWidget(QLabel("🛡 LANWARDEN", objectName="Title"))

        self._stack = QStackedWidget()
        self._nav_group = QButtonGroup(self)
        nav_row = QVBoxLayout()
        for i, (name, builder) in enumerate(
            [
                ("Watch", self._page_watch),
                ("Warden", self._page_warden),
                ("Keeper", self._page_keeper),
                ("Scope", self._page_scope),
            ]
        ):
            btn = QPushButton(name, objectName="Nav", checkable=True)
            btn.clicked.connect(lambda _c, idx=i: self._stack.setCurrentIndex(idx))
            self._nav_group.addButton(btn, i)
            nav_row.addWidget(btn)
            self._stack.addWidget(builder())
        self._nav_group.button(0).setChecked(True)
        lay.addLayout(nav_row)
        lay.addSpacing(6)
        lay.addWidget(self._stack, 1)
        return frame

    def _section(self, title: str) -> tuple[QWidget, QVBoxLayout]:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.addWidget(QLabel(title, objectName="SectionTitle"))
        return w, lay

    def _page_watch(self) -> QWidget:
        w, lay = self._section("WATCH · discovery")
        scan = QPushButton("⟳ SCAN NETWORK", objectName="Good")
        scan.clicked.connect(self._do_scan)
        lay.addWidget(scan)
        flush = QPushButton("Clear hostname cache")
        flush.clicked.connect(lambda: self._run(self.ctrl.flush_hostnames, op="flush"))
        lay.addWidget(flush)
        self.lbl_discovery = QLabel("Idle", objectName="SectionTitle")
        lay.addWidget(self.lbl_discovery)
        lay.addStretch(1)
        return w

    def _page_warden(self) -> QWidget:
        w, lay = self._section("WARDEN · control")
        for label, obj, slot in [
            ("✕ CUT", "Danger", lambda: self._dev_op(self.ctrl.cut_device, "cut")),
            ("↺ RESTORE", "Good", lambda: self._dev_op(self.ctrl.restore_device, "restore")),
            ("⚡ LIMIT…", None, self._do_limit),
            ("∞ UNLIMIT", None, lambda: self._dev_op(self.ctrl.unlimit_device, "unlimit")),
            ("✎ RENAME…", None, self._do_rename),
        ]:
            b = QPushButton(label, objectName=obj or "")
            b.clicked.connect(slot)
            lay.addWidget(b)
        lay.addSpacing(8)
        cut_all = QPushButton("✕ CUT ALL", objectName="Danger")
        cut_all.clicked.connect(lambda: self._run(self.ctrl.cut_all, op="cut_all"))
        rest_all = QPushButton("↺ RESTORE ALL", objectName="Good")
        rest_all.clicked.connect(self._do_restore_all)
        lay.addWidget(cut_all)
        lay.addWidget(rest_all)
        lay.addSpacing(8)
        self.btn_blackout = QPushButton("⬛ BLACKOUT SEGMENT", objectName="Danger")
        self.btn_blackout.setToolTip(
            "Every device on this segment loses the gateway, including devices not in "
            "the list. Your own connection stays up."
        )
        self.btn_blackout.clicked.connect(self._do_blackout)
        lay.addWidget(self.btn_blackout)
        lay.addStretch(1)
        return w

    def _page_keeper(self) -> QWidget:
        w, lay = self._section("KEEPER · protection & posture")
        self.btn_arp = QPushButton("🛡 ARP Guard: OFF")
        self.btn_arp.clicked.connect(self._toggle_arp)
        self.btn_ks = QPushButton("🚨 Kill-Switch: OFF", objectName="Danger")
        self.btn_ks.clicked.connect(self._toggle_ks)
        self.btn_ghost = QPushButton("👻 Ghost Firewall: OFF")
        self.btn_ghost.clicked.connect(
            lambda: self._run(
                self.ctrl.toggle_ghost_firewall, not self.ctrl.firewall.active, op="ghost"
            )
        )
        self.btn_nuke = QPushButton("☢ Nuclear Stealth: OFF", objectName="Danger")
        self.btn_nuke.clicked.connect(
            lambda: self._run(
                self.ctrl.toggle_nuclear_stealth, not self.ctrl.stealth_active, op="nuclear"
            )
        )
        for b in (self.btn_arp, self.btn_ks, self.btn_ghost, self.btn_nuke):
            lay.addWidget(b)

        lay.addSpacing(6)
        lay.addWidget(QLabel("Stealth identity", objectName="SectionTitle"))
        self.cmb_profile = QComboBox()
        self.cmb_profile.addItems(["RANDOM", "Apple", "Samsung", "Intel"])
        lay.addWidget(self.cmb_profile)
        row = QHBoxLayout()
        apply_id = QPushButton("Apply")
        apply_id.clicked.connect(
            lambda: self._run(
                self.ctrl.toggle_stealth, True, profile=self.cmb_profile.currentText(), op="stealth"
            )
        )
        rest_id = QPushButton("Restore")
        rest_id.clicked.connect(
            lambda: self._run(self.ctrl.toggle_stealth, False, op="stealth_off")
        )
        row.addWidget(apply_id)
        row.addWidget(rest_id)
        lay.addLayout(row)

        lay.addSpacing(6)
        lay.addWidget(QLabel("Evasion", objectName="SectionTitle"))
        masq = QPushButton("TTL Masquerade")
        masq.clicked.connect(lambda: self._run(self.ctrl.toggle_stack_masquerade, True, op="masq"))
        cham = QPushButton("Chameleon MTU/MSS")
        cham.clicked.connect(lambda: self._run(self.ctrl.toggle_chameleon, True, op="chameleon"))
        ipv6 = QPushButton("IPv6 Hijack")
        ipv6.clicked.connect(lambda: self._run(self.ctrl.toggle_ipv6_hijack, True, op="ipv6"))
        for b in (masq, cham, ipv6):
            lay.addWidget(b)

        lay.addSpacing(6)
        lay.addWidget(QLabel("Static IP (nmcli)", objectName="SectionTitle"))
        self.cmb_conn = QComboBox()
        self._reload_connections()
        lay.addWidget(self.cmb_conn)
        srow = QHBoxLayout()
        bstatic = QPushButton("Set static…")
        bstatic.clicked.connect(self._do_static)
        bdhcp = QPushButton("DHCP")
        bdhcp.clicked.connect(self._do_dhcp)
        srow.addWidget(bstatic)
        srow.addWidget(bdhcp)
        lay.addLayout(srow)
        lay.addStretch(1)
        return w

    def _page_scope(self) -> QWidget:
        w, lay = self._section("SCOPE · per-device probes")
        for label, slot in [
            ("Ping", self._do_ping),
            ("Traceroute", self._do_traceroute),
            ("Fingerprint", self._do_fingerprint),
            (
                "Deep recon",
                lambda: self._dev_call(lambda ip: self.ctrl.run_deep_recon(ip), "recon"),
            ),
            ("🌐 DNS redirect", self._do_dns),
            ("👁 Monitor", self._do_monitor),
        ]:
            b = QPushButton(label)
            b.clicked.connect(slot)
            lay.addWidget(b)
        self.scope_out = QPlainTextEdit(readOnly=True)
        self.scope_out.setPlaceholderText("Probe output…")
        lay.addWidget(self.scope_out, 1)
        return w

    def _table_panel(self) -> QWidget:
        self.table = QTableWidget(0, len(_COLS))
        self.table.setHorizontalHeaderLabels(_COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._update_detail)
        return self.table

    def _detail_panel(self) -> QWidget:
        frame = QFrame(objectName="Detail")
        lay = QVBoxLayout(frame)
        lay.addWidget(QLabel("DETAIL", objectName="SectionTitle"))
        self.detail = QLabel("Select a device", wordWrap=True)
        lay.addWidget(self.detail)
        lay.addWidget(QLabel("Live traffic", objectName="SectionTitle"))
        pg.setConfigOptions(antialias=False, background=PANEL, foreground=MUTED)
        self.plot = pg.PlotWidget()
        self.plot.setMenuEnabled(False)
        self.plot.hideButtons()
        self.plot.setLabel("left", "B/s")
        self._rx_curve = self.plot.plot(pen=pg.mkPen(GREEN, width=1))
        self._tx_curve = self.plot.plot(pen=pg.mkPen(ACCENT, width=1))
        lay.addWidget(self.plot, 1)
        return frame

    def _status_bar(self) -> QWidget:
        bar = QFrame()
        bar.setStyleSheet(f"background:{PANEL};border-top:1px solid #2a313c;")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(8, 3, 8, 3)
        self.sb_iface = QLabel()
        self.sb_gw = QLabel()
        self.sb_count = QLabel()
        self.sb_op = QLabel()
        self.sb_prot = QLabel()
        self.sb_blackout = QLabel()
        self.sb_alert = QLabel()
        self.sb_err = QLabel()
        for lbl in (self.sb_iface, self.sb_gw, self.sb_count, self.sb_op, self.sb_prot):
            lbl.setStyleSheet(f"color:{MUTED};border-right:1px solid #2a313c;padding:0 8px;")
            lay.addWidget(lbl)
        # Blackout is a mode, shown distinctly from per-device cut state.
        self.sb_blackout.setStyleSheet(
            f"color:{RED};font-weight:bold;border-right:1px solid #2a313c;padding:0 8px;"
        )
        lay.addWidget(self.sb_blackout)
        self.sb_alert.setStyleSheet(f"color:{RED};border-right:1px solid #2a313c;padding:0 8px;")
        lay.addWidget(self.sb_alert)
        self.sb_err.setStyleSheet(f"color:{MUTED};padding:0 8px;")
        lay.addWidget(self.sb_err, 1)
        return bar

    # ── state machine ───────────────────────────────────────────────────────────

    def set_state(self, state: str, detail: str = "") -> None:
        self._state = state
        text, colour = STATE_STYLES.get(state, (state, TEXT))
        if detail:
            text = f"{text} — {detail}"
        self.banner.setText(text)
        self.banner.setStyleSheet(f"color:{colour};")
        if state in ("error", "permission_denied", "restore_failed") and detail:
            self._last_error = detail
        self._refresh_status()

    # ── data refresh ──────────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        try:
            self.ctrl.update_device_speeds()
            devs = self.ctrl.snapshot_devices()
        except Exception as e:
            self.set_state("error", str(e))
            return
        self._populate(devs)
        if self._state in ("empty", "normal", "loading"):
            self.set_state("normal" if devs else "empty")
        else:
            self._refresh_status()
        self._drain_alerts()

    def _populate(self, devs) -> None:
        sel = self._selected_ip()
        self.table.setRowCount(len(devs))
        for r, d in enumerate(devs):
            name = display_name(
                getattr(d, "nickname", ""),
                getattr(d, "hostname", ""),
                getattr(d, "identity", ""),
                getattr(d, "vendor", ""),
            )
            rx = getattr(d, "rx_speed", 0)
            tx = getattr(d, "tx_speed", 0)
            hist = self._hist.setdefault(d.ip, collections.deque(maxlen=60))
            hist.append((rx, tx))
            cells = [
                d.ip,
                getattr(d, "mac", ""),
                name,
                getattr(d, "vendor", ""),
                getattr(d, "status", ""),
                fmt_speed(rx) if not getattr(d, "cut", False) else "BLOCKED",
                fmt_speed(tx) if not getattr(d, "cut", False) else "BLOCKED",
            ]
            for c, val in enumerate(cells):
                item = QTableWidgetItem(str(val))
                if getattr(d, "cut", False):
                    item.setForeground(Qt.red)
                self.table.setItem(r, c, item)
            if d.ip == sel:
                self.table.selectRow(r)
        self._update_detail()

    def _refresh_status(self) -> None:
        net = self.ctrl.net
        self.sb_iface.setText(f"iface: {net.iface or '—'}")
        self.sb_gw.setText(f"gw: {net.gateway or '—'}")
        self.sb_count.setText(f"devices: {self.table.rowCount()}")
        self.sb_op.setText(f"op: {self._active_op}")
        prot = []
        if getattr(self.ctrl.protector, "arp_guard_enabled", False):
            prot.append("ARP-guard")
        if getattr(self.ctrl.protector, "kill_switch_enabled", False):
            prot.append("kill-switch")
        if getattr(self.ctrl.firewall, "active", False):
            prot.append("ghost-fw")
        if getattr(self.ctrl, "stealth_active", False):
            prot.append("stealth")
        self.sb_prot.setText("protection: " + (", ".join(prot) if prot else "none"))
        blackout = getattr(self.ctrl, "blackout_active", False)
        self.sb_blackout.setText("⬛ SEGMENT BLACKOUT" if blackout else "")
        self.sb_alert.setText("" if self._last_alert == "—" else f"⚠ {self._last_alert}")
        self.sb_err.setText(f"last error: {self._last_error}")
        self.btn_arp.setText(
            f"🛡 ARP Guard: {'ON' if self.ctrl.protector.arp_guard_enabled else 'OFF'}"
        )
        self.btn_ks.setText(
            f"🚨 Kill-Switch: {'ON' if self.ctrl.protector.kill_switch_enabled else 'OFF'}"
        )
        self.btn_ghost.setText(f"👻 Ghost Firewall: {'ON' if self.ctrl.firewall.active else 'OFF'}")
        self.btn_nuke.setText(f"☢ Nuclear Stealth: {'ON' if self.ctrl.stealth_active else 'OFF'}")
        self.btn_blackout.setText("⬛ BLACKOUT: ON" if blackout else "⬛ BLACKOUT SEGMENT")

    def _drain_alerts(self) -> None:
        """Drain protection alerts queued by the (off-GUI-thread) protector and
        show the most recent. Runs on the GUI thread from the refresh timer, so
        no Qt call ever happens on the sniffer thread, and an ARP-storm of alerts
        coalesces into a single status-bar update instead of flooding Qt."""
        latest = None
        while self._alert_q:
            latest = self._alert_q.popleft()
        if latest is not None and latest != self._last_alert:
            self._last_alert = latest
            self.sb_alert.setText(f"⚠ {latest}")

    def _update_detail(self) -> None:
        ip = self._selected_ip()
        if not ip:
            self.detail.setText("Select a device")
            self._rx_curve.setData([])
            self._tx_curve.setData([])
            return
        dev = self.ctrl.devices.get(ip)
        if dev:
            ports = ", ".join(str(p) for p in getattr(dev, "open_ports", [])[:12]) or "—"
            self.detail.setText(
                f"<b>{ip}</b><br>mac: {getattr(dev, 'mac', '')}<br>"
                f"vendor: {getattr(dev, 'vendor', '')}<br>os: {getattr(dev, 'os_guess', '') or '?'}<br>"
                f"status: {getattr(dev, 'status', '')}<br>ports: {ports}"
            )
        hist = self._hist.get(ip)
        if hist:
            self._rx_curve.setData([h[0] for h in hist])
            self._tx_curve.setData([h[1] for h in hist])

    # ── helpers ──────────────────────────────────────────────────────────────────

    def _selected_ip(self) -> str | None:
        items = self.table.selectedItems()
        return items[0].text() if items else None

    def _require_ip(self) -> str | None:
        ip = self._selected_ip()
        if not ip:
            self.set_state("error", "select a device first")
        return ip

    def _run(self, fn, *args, op: str = "op", **kwargs) -> None:
        """Run a controller call off the Qt thread and refresh on completion."""
        self._active_op = op
        self.set_state("running", op)
        submit(
            fn,
            *args,
            on_error=lambda msg: self.set_state("error", msg),
            on_done=self._op_done,
            **kwargs,
        )

    def _op_done(self) -> None:
        self._active_op = "—"
        if self._state == "running":
            self.set_state("normal")
        self._refresh()

    def _dev_op(self, fn, op: str) -> None:
        ip = self._require_ip()
        if ip:
            self._run(fn, ip, op=op)

    def _dev_call(self, fn, op: str) -> None:
        ip = self._require_ip()
        if ip:
            self._run(lambda: fn(ip), op=op)

    # ── Warden actions ────────────────────────────────────────────────────────────

    def _do_limit(self) -> None:
        ip = self._require_ip()
        if not ip:
            return
        kb, ok = QInputDialog.getInt(self, "Limit", f"KB/s for {ip}:", 500, 1, 1000000, 50)
        if ok:
            self._run(self.ctrl.limit_device, ip, kb, op="limit")

    def _do_rename(self) -> None:
        ip = self._require_ip()
        if not ip:
            return
        dev = self.ctrl.devices.get(ip)
        name, ok = QInputDialog.getText(self, "Rename", f"Nickname for {ip}:")
        if ok and dev is not None:
            dev.nickname = name.strip()
            dev.identity = ""
            self._refresh()

    def _do_restore_all(self) -> None:
        self.set_state("restoring")
        self._run(self.ctrl.restore_all, op="restore_all")

    def _do_blackout(self) -> None:
        want_on = not getattr(self.ctrl, "blackout_active", False)
        # Confirm once per session, then free toggling.
        if want_on and not self._blackout_confirmed:
            resp = QMessageBox.question(
                self,
                "Confirm segment blackout",
                "Blackout segment — every device on this segment loses the gateway, "
                "including devices not in the list. Your own connection stays up.\n\n"
                "Active segment-wide MITM — authorized, isolated lab only.",
            )
            if resp != QMessageBox.Yes:
                return
            self._blackout_confirmed = True
        self._run(self.ctrl.toggle_blackout, want_on, op="blackout")

    # ── Keeper actions ──────────────────────────────────────────────────────────────

    def _toggle_arp(self) -> None:
        p = self.ctrl.protector
        fn = p.disable_arp_guard if p.arp_guard_enabled else p.enable_arp_guard
        self._run(fn, op="arp_guard")

    def _toggle_ks(self) -> None:
        p = self.ctrl.protector
        self._run(p.toggle_kill_switch, not p.kill_switch_enabled, op="kill_switch")

    def _reload_connections(self) -> None:
        self.cmb_conn.clear()
        try:
            conns = get_connections()
        except Exception:
            conns = []
        self.cmb_conn.addItems(conns or ["(none)"])

    def _do_static(self) -> None:
        conn = self.cmb_conn.currentText()
        ip, ok = QInputDialog.getText(self, "Static IP", "IP/prefix (e.g. 192.168.1.50/24):")
        if not ok or not ip:
            return
        gw, ok = QInputDialog.getText(self, "Gateway", "Gateway IP:")
        if not ok or not gw:
            return
        dns, ok = QInputDialog.getText(self, "DNS", "DNS (comma):", text="8.8.8.8,1.1.1.1")
        if not ok:
            return
        self._run(lambda: apply_static_config(conn, ip, gw, dns), op="static_ip")

    def _do_dhcp(self) -> None:
        conn = self.cmb_conn.currentText()
        self._run(lambda: set_dhcp(conn), op="dhcp")

    # ── Scope actions ───────────────────────────────────────────────────────────────

    def _do_scan(self) -> None:
        self.lbl_discovery.setText("Scanning…")
        self.set_state("loading")

        def _scan_done() -> None:
            self.lbl_discovery.setText("Idle")
            self._op_done()

        submit(
            self.ctrl.scan,
            on_error=lambda msg: self.set_state("error", msg),
            on_done=_scan_done,
        )

    def _probe(self, argv: list[str], label: str) -> None:
        ip = self._require_ip()
        if not ip:
            return
        self._stack.setCurrentIndex(3)
        self.scope_out.setPlainText(f"{label} {ip}…")

        def work():
            r = subprocess.run([*argv, ip], capture_output=True, text=True, timeout=30)
            return r.stdout or r.stderr

        self._active_op = label
        submit(
            work,
            on_result=lambda out: self.scope_out.setPlainText(out),
            on_error=lambda msg: self.scope_out.setPlainText(msg),
            on_done=self._op_done,
        )

    def _do_ping(self) -> None:
        self._probe(["ping", "-c", "4"], "ping")

    def _do_traceroute(self) -> None:
        self._probe(["traceroute", "-m", "15"], "traceroute")

    def _do_fingerprint(self) -> None:
        ip = self._require_ip()
        if ip:
            self._run(self.ctrl.fingerprint, ip, op="fingerprint")

    def _do_dns(self) -> None:
        ip = self._require_ip()
        if not ip:
            return
        if (
            QMessageBox.question(
                self,
                "Confirm DNS redirect",
                "Redirect DNS for the selected device?\nActive MITM — authorized lab only.",
            )
            == QMessageBox.Yes
        ):
            self._run(self.ctrl.toggle_dns_spoof, ip, True, op="dns_redirect")

    def _do_monitor(self) -> None:
        ip = self._require_ip()
        if not ip:
            return
        if (
            QMessageBox.question(
                self,
                "Confirm interception",
                "Silently intercept (ARP-spoof, no drop) the selected device?\n"
                "Active MITM — authorized lab only.",
            )
            == QMessageBox.Yes
        ):
            self._run(self.ctrl.monitor_device, ip, op="monitor")

    # ── shutdown ─────────────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        self.set_state("stopping")
        try:
            self.ctrl.stop()
        except Exception as e:
            self.set_state("restore_failed", str(e))
        event.accept()
