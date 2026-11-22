"""
Tests for the sqlite storage backend (STEP 3).

Config/nicknames keep their old API but are now sqlite-backed (WAL); new tables
(devices, cut_records, operation_log) have read/write methods; existing json is
imported once on first run. `_load` is retained for that migration and still
guards corrupt/missing files.
"""

from __future__ import annotations

import json

from core import persistence as pers
from core.persistence import Persistence


def _store(tmp_path):
    return Persistence(db_path=tmp_path / "t.db")


def test_wal_mode_enabled(tmp_path):
    db = _store(tmp_path)
    mode = db._conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    db.close()


def test_config_roundtrip_and_persists(tmp_path):
    db = _store(tmp_path)
    db.save_config(iface="eth0", gateway="192.168.1.1")
    assert db.get("iface") == "eth0"
    assert db.get("gateway") == "192.168.1.1"
    db.close()
    # Reopen the same file — values survive.
    db2 = Persistence(db_path=tmp_path / "t.db")
    assert db2.get("iface") == "eth0"
    assert db2.get("gateway") == "192.168.1.1"
    assert db2.get("scan_timeout") == 45  # default still applies
    db2.close()


def test_nickname_roundtrip_and_persists(tmp_path):
    db = _store(tmp_path)
    db.set_nickname("aa:bb:cc:dd:ee:ff", "NAS")
    assert db.get_nickname("aa:bb:cc:dd:ee:ff") == "NAS"
    db.close()
    db2 = Persistence(db_path=tmp_path / "t.db")
    assert db2.get_nickname("aa:bb:cc:dd:ee:ff") == "NAS"
    db2.close()


def test_operation_log_append_and_read(tmp_path):
    db = _store(tmp_path)
    db.log_operation("cut", "10.0.0.5")
    db.log_operation("restore", "10.0.0.5", "manual")
    ops = db.recent_operations()
    assert [o["op"] for o in ops] == ["restore", "cut"]  # newest first
    assert ops[0]["detail"] == "manual"
    db.close()


def test_cut_records_lifecycle(tmp_path):
    db = _store(tmp_path)
    db.record_cut("10.0.0.5")
    db.record_cut("10.0.0.6")
    assert set(db.active_cuts()) == {"10.0.0.5", "10.0.0.6"}
    db.clear_cut("10.0.0.5")
    assert db.active_cuts() == ["10.0.0.6"]
    db.close()


def test_devices_save_and_load(tmp_path):
    db = _store(tmp_path)
    db.save_device("10.0.0.5", mac="aa:bb", vendor="Acme", hostname="box", identity="PC")
    db.save_device("10.0.0.5", mac="aa:bb", vendor="Acme2")  # upsert
    devs = db.load_devices()
    assert len(devs) == 1
    assert devs[0]["ip"] == "10.0.0.5"
    assert devs[0]["vendor"] == "Acme2"
    db.close()


def test_json_migrated_into_sqlite_on_first_run(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"iface": "wlan0", "scan_timeout": 99}))
    (tmp_path / "nicknames.json").write_text(json.dumps({"11:22": "phone"}))

    db = Persistence(db_path=tmp_path / "t.db")

    assert db.get("iface") == "wlan0"
    assert db.get("scan_timeout") == 99
    assert db.get_nickname("11:22") == "phone"
    # The json is archived (one-time), not re-imported.
    assert (tmp_path / "config.json.migrated").exists()
    assert not (tmp_path / "config.json").exists()
    db.close()


# ── _load retained for migration ──────────────────────────────────────────────


def test_load_corrupt_returns_default(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not valid json")
    assert pers._load(p, {"d": True}) == {"d": True}


def test_load_missing_returns_default(tmp_path):
    assert pers._load(tmp_path / "nope.json", {"d": 1}) == {"d": 1}
