"""
core/device.py — Rich Device model with full state tracking.
"""
from __future__ import annotations

from datetime import datetime

from core.persistence import db, lookup_oui


class Device:
    def __init__(self, ip: str, mac: str = "", hostname: str = "", vendor: str = ""):
        self.ip           = ip
        self.mac          = mac
        self.hostname     = hostname
        self.vendor       = vendor or lookup_oui(mac)
        self.status       = "online"   # online | self | cut
        self.cut          = False
        self.limited      = False
        self.limit_kb     = db.get("default_limit_kb", 500)
        self.last_seen    = datetime.now().strftime("%H:%M:%S")
        self.open_ports:  list[int]       = []
        self.os_guess:    str             = ""
        self.services:    dict[int, str]  = {}
        self.identity:    str             = ""
        self.rx_speed:    float           = 0.0
        self.tx_speed:    float           = 0.0
        self.rx_total:    int             = 0
        self.tx_total:    int             = 0
        # Bandwidth sparkline history (last 30 samples, bytes/s)
        self.rx_history:  list[float]     = []
        self.tx_history:  list[float]     = []

        # ── Intelligence & Confidence ──
        self.confidence:  int             = 0    # 0-100
        self.tcp_ttl:     int             = 0
        self.tcp_window:  int             = 0
        self.recon_data:  dict            = {
            "ssl_cn": "", "http_title": "", "upnp_model": "", "ptr_name": "", "ipv6_ll": ""
        }

    # ── Nickname (persisted by MAC) ────────────────────────────────────────
    @property
    def nickname(self) -> str:
        return db.get_nickname(self.mac) if self.mac else ""

    @nickname.setter
    def nickname(self, v: str):
        if self.mac:
            db.set_nickname(self.mac, v)

    # ── Display helpers ────────────────────────────────────────────────────
    def display_name(self) -> str:
        if self.nickname:   return self.nickname
        if self.hostname:   return self.hostname
        return self.ip

    def update_history(self, rx_spd: float, tx_spd: float):
        """Append to sparkline history (capped at 30 samples)."""
        self.rx_history.append(rx_spd)
        self.tx_history.append(tx_spd)
        if len(self.rx_history) > 30:
            self.rx_history.pop(0)
            self.tx_history.pop(0)

    # ── Serialisation ──────────────────────────────────────────────────────
    def to_state(self) -> dict:
        return {
            "cut":        self.cut,
            "limited":    self.limited,
            "limit_kb":   self.limit_kb,
            "open_ports": self.open_ports,
            "os_guess":   self.os_guess,
            "vendor":     self.vendor,
            "hostname":   self.hostname,
            "mac":        self.mac,
            "services":   {str(k): v for k, v in self.services.items()},
            "identity":   self.identity,
            "confidence": self.confidence,
            "recon":      self.recon_data,
        }