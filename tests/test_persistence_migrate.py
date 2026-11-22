"""
Tests for the Hakai -> Lanwarden one-time config migration (STEP 1).

core/persistence._migrate_legacy_dir copies config/nicknames from the old
~/.sadok_hakai into ~/.lanwarden on first run, without clobbering a config that
already exists and leaving the old dir as a rollback.
"""

from __future__ import annotations

from core import persistence as pers


def _point_at(monkeypatch, legacy, new):
    monkeypatch.setattr(pers, "LEGACY_DIR", legacy)
    monkeypatch.setattr(pers, "CONFIG_DIR", new)
    monkeypatch.setattr(pers, "CONFIG_FILE", new / "config.json")
    monkeypatch.setattr(pers, "NICK_FILE", new / "nicknames.json")


def test_migrates_when_new_config_absent(tmp_path, monkeypatch):
    legacy = tmp_path / ".sadok_hakai"
    legacy.mkdir()
    (legacy / "config.json").write_text('{"iface": "eth0"}')
    (legacy / "nicknames.json").write_text('{"aa:bb": "nas"}')
    new = tmp_path / ".lanwarden"
    _point_at(monkeypatch, legacy, new)

    pers._migrate_legacy_dir()

    assert (new / "config.json").read_text() == '{"iface": "eth0"}'
    assert (new / "nicknames.json").exists()
    # Old dir kept as a rollback (copy, not move).
    assert (legacy / "config.json").exists()


def test_does_not_overwrite_existing_new_config(tmp_path, monkeypatch):
    legacy = tmp_path / ".sadok_hakai"
    legacy.mkdir()
    (legacy / "config.json").write_text('{"iface": "OLD"}')
    new = tmp_path / ".lanwarden"
    new.mkdir()
    (new / "config.json").write_text('{"iface": "NEW"}')
    _point_at(monkeypatch, legacy, new)

    pers._migrate_legacy_dir()

    assert (new / "config.json").read_text() == '{"iface": "NEW"}'


def test_noop_without_legacy_dir(tmp_path, monkeypatch):
    legacy = tmp_path / ".sadok_hakai"  # does not exist
    new = tmp_path / ".lanwarden"
    _point_at(monkeypatch, legacy, new)
    pers._migrate_legacy_dir()  # must not raise
    assert not new.exists() or not (new / "config.json").exists()
