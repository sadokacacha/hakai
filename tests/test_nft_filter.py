"""
Tests for system/nft_filter.NftFilter (STEP 2 — iptables FORWARD -> nft).

Mocked: the `run` callable is injected, so no real nft is issued. These pin the
behaviour that matters for correctness: cut DROPs are INSERTED (above the
accounting ACCEPTs), accounting is APPENDED with a counter, removal is by exact
handle (never a flush), and counters parse saddr->TX / daddr->RX.
"""

from __future__ import annotations

import json
import subprocess

from system import nft_filter as nf
from system.nft_filter import NftFilter


def _cp(rc=0, stdout=""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr="")


def _acct_rule(ip, field, byts, handle):
    return {
        "rule": {
            "chain": "forward",
            "handle": handle,
            "comment": "lanwarden_acct",
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"field": field}}, "right": ip}},
                {"counter": {"packets": 1, "bytes": byts}},
                {"accept": None},
            ],
        }
    }


def _cut_rule(ip, field, handle):
    return {
        "rule": {
            "chain": "forward",
            "handle": handle,
            "comment": "lanwarden_cut",
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"field": field}}, "right": ip}},
                {"drop": None},
            ],
        }
    }


def _runner(list_payload="", record=None):
    def run(cmd, *a, **k):
        if record is not None:
            record.append(cmd)
        if "list" in cmd and "-j" in cmd:
            return _cp(0, stdout=list_payload)
        return _cp(0)

    return run


def test_cut_inserts_drops_with_tag(monkeypatch):
    monkeypatch.setattr(nf, "_IS_WINDOWS", False)
    rec: list = []
    f = NftFilter(run=_runner(list_payload="", record=rec))  # empty chain

    assert f.cut("192.168.1.5") is True
    inserts = [c for c in rec if "insert" in c and "rule" in c]
    assert len(inserts) == 2, "saddr + daddr drops inserted"
    for c in inserts:
        assert "drop" in c and "lanwarden_cut" in c
    # DROP uses INSERT (top of chain), never APPEND.
    assert not any("add" in c and "rule" in c and "drop" in c for c in rec)


def test_cut_rejects_invalid_ip(monkeypatch):
    monkeypatch.setattr(nf, "_IS_WINDOWS", False)
    rec: list = []
    f = NftFilter(run=_runner(record=rec))
    assert f.cut("nope") is False
    assert not any("insert" in c for c in rec)


def test_accounting_appends_with_counter(monkeypatch):
    monkeypatch.setattr(nf, "_IS_WINDOWS", False)
    rec: list = []
    f = NftFilter(run=_runner(list_payload="", record=rec))

    assert f.add_accounting("10.0.0.9") is True
    adds = [c for c in rec if "add" in c and "rule" in c]
    assert len(adds) == 2
    for c in adds:
        assert "counter" in c and "accept" in c and "lanwarden_acct" in c


def test_read_counters_maps_saddr_tx_daddr_rx(monkeypatch):
    monkeypatch.setattr(nf, "_IS_WINDOWS", False)
    payload = json.dumps(
        {
            "nftables": [
                _acct_rule("1.2.3.4", "saddr", 1500, 11),  # upload / TX
                _acct_rule("1.2.3.4", "daddr", 3000, 12),  # download / RX
            ]
        }
    )
    f = NftFilter(run=_runner(list_payload=payload))
    assert f.read_counters() == {"1.2.3.4": (3000, 1500)}  # (rx, tx)


def test_uncut_deletes_by_exact_handle(monkeypatch):
    monkeypatch.setattr(nf, "_IS_WINDOWS", False)
    payload = json.dumps(
        {
            "nftables": [
                _cut_rule("1.2.3.4", "saddr", 7),
                _cut_rule("1.2.3.4", "daddr", 8),
                _cut_rule("9.9.9.9", "saddr", 9),  # different ip — must be untouched
            ]
        }
    )
    rec: list = []
    f = NftFilter(run=_runner(list_payload=payload, record=rec))
    f.uncut("1.2.3.4")

    deletes = [c for c in rec if "delete" in c and "rule" in c]
    handles = {c[c.index("handle") + 1] for c in deletes}
    assert handles == {"7", "8"}, "only the matching ip's handles deleted; never a flush"
    assert not any("flush" in c for c in rec)


def test_cleanup_deletes_own_table(monkeypatch):
    monkeypatch.setattr(nf, "_IS_WINDOWS", False)
    rec: list = []
    f = NftFilter(run=_runner(record=rec))
    f.cleanup()
    assert ["nft", "delete", "table", "inet", "lanwarden"] in rec


def test_windows_is_noop(monkeypatch):
    monkeypatch.setattr(nf, "_IS_WINDOWS", True)
    rec: list = []
    f = NftFilter(run=_runner(record=rec))
    f.cut("1.2.3.4")
    f.add_accounting("1.2.3.4")
    assert rec == []
