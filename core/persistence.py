"""
core/persistence.py — Config, nicknames, device / cut / operation-log storage
(sqlite, WAL) + speed/size format helpers. All data in ~/.lanwarden/lanwarden.db.

Storage is sqlite in WAL mode: every write is a committed transaction, so there
are no torn files (replacing the old atomic-json layer). The config/nicknames
public API is unchanged; new tables (devices, cut_records, operation_log) have
their own read/write methods. Existing config.json / nicknames.json are imported
once on first run and renamed `.migrated` (kept as a rollback).

The OUI vendor DB moved to core/oui.py and the device-identity engine to
core/identity.py — this module is storage + formatting only.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

_log = logging.getLogger(__name__)

# ── Storage paths ──────────────────────────────────────────────────────────────
CONFIG_DIR = Path.home() / ".lanwarden"
LEGACY_DIR = Path.home() / ".sadok_hakai"  # pre-rename location (Lanwarden migration)
CONFIG_FILE = CONFIG_DIR / "config.json"  # legacy json (pre-sqlite); imported once
NICK_FILE = CONFIG_DIR / "nicknames.json"  # legacy json (pre-sqlite); imported once
DB_FILE = CONFIG_DIR / "lanwarden.db"


def _migrate_legacy_dir() -> None:
    """One-time copy of config/nicknames from the pre-rename ~/.sadok_hakai.

    Copies (not moves) so the old dir stays as a rollback. Idempotent: only runs
    when the new dir has no config yet, so a fresh install or an already-migrated
    host is untouched.
    """
    try:
        if CONFIG_FILE.exists() or NICK_FILE.exists():
            return  # new config already present
        if not LEGACY_DIR.exists():
            return
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        copied = False
        for name in ("config.json", "nicknames.json"):
            src, dst = LEGACY_DIR / name, CONFIG_DIR / name
            if src.exists() and not dst.exists():
                shutil.copy2(src, dst)
                copied = True
        if copied:
            _log.info("migrated legacy config %s -> %s", LEGACY_DIR, CONFIG_DIR)
    except OSError as e:
        _log.warning("legacy config migration failed: %s", e)


try:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
except OSError as e:
    # Don't crash the whole app at import time if the home dir is read-only.
    _log.warning("could not create config dir %s: %s", CONFIG_DIR, e)

_migrate_legacy_dir()

DEFAULT_CFG: dict = {
    "iface": "auto",
    "gateway": "",
    "scan_timeout": 45,
    "refresh_ms": 1200,
    "default_limit_kb": 500,
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS config      (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nicknames   (mac TEXT PRIMARY KEY, name  TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, hostname TEXT,
    identity TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS cut_records (
    ip TEXT PRIMARY KEY, created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS operation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
    op TEXT NOT NULL, ip TEXT, detail TEXT
);
"""


def _load(path: Path, default):
    """Read a JSON file (used only by the one-time json->sqlite migration)."""
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (OSError, ValueError) as e:
        _log.warning("could not load %s (%s) — using defaults", path, e)
    return default


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Persistence:
    """sqlite-backed store. The singleton is shared across the UI and sniffer
    threads; `check_same_thread=False` + a lock around every statement make that
    safe, and each write commits atomically (WAL)."""

    def __init__(self, db_path: Path | None = None):
        self._lock = threading.Lock()
        self._path = Path(db_path) if db_path else DB_FILE
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate_json()
        # Hot-read caches, hydrated from sqlite.
        self.cfg = dict(DEFAULT_CFG)
        self.cfg.update(self._rows_config())
        self.nicknames = self._rows_nicknames()

    # ── one-time json -> sqlite import ─────────────────────────────────────────

    def _migrate_json(self) -> None:
        cfgf = self._path.parent / "config.json"
        nickf = self._path.parent / "nicknames.json"
        if not cfgf.exists() and not nickf.exists():
            return
        with self._lock:
            if self._conn.execute("SELECT COUNT(*) FROM config").fetchone()[0]:
                return  # already populated
            cfg = _load(cfgf, {})
            if isinstance(cfg, dict):
                for k, v in cfg.items():
                    self._conn.execute(
                        "INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)",
                        (k, json.dumps(v)),
                    )
            nick = _load(nickf, {})
            if isinstance(nick, dict):
                for mac, name in nick.items():
                    self._conn.execute(
                        "INSERT OR REPLACE INTO nicknames(mac, name) VALUES(?, ?)", (mac, str(name))
                    )
            self._conn.commit()
        for f in (cfgf, nickf):
            try:
                if f.exists():
                    f.rename(f.with_suffix(f.suffix + ".migrated"))
            except OSError as e:
                _log.debug("could not archive migrated json %s: %s", f, e)
        _log.info("migrated json config/nicknames -> sqlite (%s)", self._path)

    # ── internal row loaders ───────────────────────────────────────────────────

    def _rows_config(self) -> dict:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM config").fetchall()
        out: dict = {}
        for k, v in rows:
            try:
                out[k] = json.loads(v)
            except (ValueError, TypeError):
                out[k] = v
        return out

    def _rows_nicknames(self) -> dict:
        with self._lock:
            rows = self._conn.execute("SELECT mac, name FROM nicknames").fetchall()
        return {mac: name for mac, name in rows}

    # ── config / nicknames (public API — unchanged signatures) ─────────────────

    def save_config(self, iface: str = "", gateway: str = ""):
        with self._lock:
            if iface:
                self.cfg["iface"] = iface
            if gateway:
                self.cfg["gateway"] = gateway
            for key in ("iface", "gateway"):
                self._conn.execute(
                    "INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)",
                    (key, json.dumps(self.cfg[key])),
                )
            self._conn.commit()

    def get_nickname(self, mac: str) -> str:
        return self.nicknames.get(mac, "")

    def set_nickname(self, mac: str, name: str):
        with self._lock:
            self.nicknames[mac] = name
            self._conn.execute(
                "INSERT OR REPLACE INTO nicknames(mac, name) VALUES(?, ?)", (mac, name)
            )
            self._conn.commit()

    def get(self, key: str, default=None):
        return self.cfg.get(key, DEFAULT_CFG.get(key, default))

    # ── operation log ──────────────────────────────────────────────────────────

    def log_operation(self, op: str, ip: str = "", detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO operation_log(ts, op, ip, detail) VALUES(?, ?, ?, ?)",
                (_now(), op, ip, detail),
            )
            self._conn.commit()

    def recent_operations(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, op, ip, detail FROM operation_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"ts": t, "op": o, "ip": i, "detail": d} for t, o, i, d in rows]

    # ── cut records ─────────────────────────────────────────────────────────────

    def record_cut(self, ip: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cut_records(ip, created_at, active) VALUES(?, ?, 1)",
                (ip, _now()),
            )
            self._conn.commit()

    def clear_cut(self, ip: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE cut_records SET active = 0 WHERE ip = ?", (ip,))
            self._conn.commit()

    def active_cuts(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute("SELECT ip FROM cut_records WHERE active = 1").fetchall()
        return [r[0] for r in rows]

    # ── devices ──────────────────────────────────────────────────────────────────

    def save_device(
        self, ip: str, mac: str = "", vendor: str = "", hostname: str = "", identity: str = ""
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO devices(ip, mac, vendor, hostname, identity, last_seen) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (ip, mac, vendor, hostname, identity, _now()),
            )
            self._conn.commit()

    def load_devices(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, mac, vendor, hostname, identity, last_seen FROM devices"
            ).fetchall()
        return [
            {"ip": ip, "mac": mac, "vendor": v, "hostname": h, "identity": idn, "last_seen": ls}
            for ip, mac, v, h, idn, ls in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# Global singleton
db = Persistence()


# ── Format helpers ─────────────────────────────────────────────────────────────
def fmt_speed(bps: float) -> str:
    if bps <= 0:
        return "0 B/s"
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1048576:
        return f"{bps / 1024:.1f} KB/s"
    return f"{bps / 1048576:.2f} MB/s"


def fmt_mbps(mbps: float) -> str:
    if mbps <= 0:
        return "0.00 Mbps"
    if mbps < 1.0:
        return f"{mbps * 1000:.0f} Kbps"
    return f"{mbps:.2f} Mbps"


def fmt_total(b: int) -> str:
    if b <= 0:
        return "0 B"
    if b < 1024:
        return f"{b} B"
    if b < 1048576:
        return f"{b / 1024:.1f} KB"
    if b < 1073741824:
        return f"{b / 1048576:.1f} MB"
    return f"{b / 1073741824:.2f} GB"
