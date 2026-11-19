"""
Regression tests for core/persistence.py atomic save/load (Phase-2 hunt).

PERS-1  _save wrote JSON non-atomically (path.write_text), so an interrupted or
        concurrent write could leave a truncated file that _load then silently
        discarded, losing all persisted state. It now serializes, writes a temp
        file, and os.replace()s atomically, returning a success bool.
PERS-6  _load swallowed decode errors silently.
"""

from __future__ import annotations

import json

from core import persistence as pers


def test_save_load_roundtrip(tmp_path):
    p = tmp_path / "x.json"
    assert pers._save(p, {"a": 1, "b": [2, 3]}) is True
    assert pers._load(p, {}) == {"a": 1, "b": [2, 3]}
    assert not (tmp_path / "x.json.tmp").exists(), "temp file must not be left behind"


def test_save_atomic_preserves_original_on_replace_failure(tmp_path, monkeypatch):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"old": True}))

    def _boom(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(pers.os, "replace", _boom)
    ok = pers._save(p, {"new": True})

    assert ok is False
    # The atomic write failed at the replace step → the original is untouched.
    assert json.loads(p.read_text()) == {"old": True}
    assert not (tmp_path / "cfg.json.tmp").exists(), "temp file must be cleaned up"


def test_save_rejects_unserializable(tmp_path):
    p = tmp_path / "y.json"
    p.write_text(json.dumps({"keep": 1}))
    assert pers._save(p, {"bad": object()}) is False
    assert json.loads(p.read_text()) == {"keep": 1}, "original must survive a serialize failure"


def test_load_corrupt_returns_default(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ this is not valid json")
    assert pers._load(p, {"default": True}) == {"default": True}


def test_load_missing_returns_default(tmp_path):
    assert pers._load(tmp_path / "nope.json", {"d": 1}) == {"d": 1}
