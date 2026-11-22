"""
system/nft_filter.py — FORWARD cut (DROP) + accounting (ACCEPT) via nftables.

Replaces the old iptables FORWARD path (system/iptables_manager.py + the inline
iptables DROP in network/arp.py). One table/chain owns both halves:

    table inet lanwarden {
        chain forward {                      # explicit hook + priority
            type filter hook forward priority filter; policy accept;
            # cut rules (inserted at the TOP, so DROP precedes ACCEPT):
            ip saddr <ip> drop   comment "lanwarden_cut"
            ip daddr <ip> drop   comment "lanwarden_cut"
            # accounting (appended, after the drops):
            ip saddr <ip> counter accept comment "lanwarden_acct"
            ip daddr <ip> counter accept comment "lanwarden_acct"
        }
    }

Rules carry the `lanwarden_*` comment tag so a startup sweep can clear orphans
left by a hard kill. Removal is by **exact handle match** (read the chain, find
the rule's handle, delete that handle) — never a flush, so another tool's or our
own other rules are untouched. All calls are argv lists, Windows is an explicit
no-op (logged by callers), and failures degrade (rc != 0) rather than raise.

Linux-only; byte counters are authoritative only while we hold the MITM position.
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Callable

from core.netutil import valid_ip
from core.osutil import IS_WINDOWS as _IS_WINDOWS

_log = logging.getLogger(__name__)

TABLE = "lanwarden"
FAMILY = "inet"
CHAIN = "forward"
_CUT = "lanwarden_cut"
_ACCT = "lanwarden_acct"

Run = Callable[..., subprocess.CompletedProcess]


def _nft(run: Run, *args: str) -> subprocess.CompletedProcess:
    if _IS_WINDOWS:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    try:
        return run(["nft", *args], capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        _log.warning("nft %s failed to run: %s", " ".join(args), e)
        return subprocess.CompletedProcess(args=list(args), returncode=1, stdout="", stderr=str(e))


class NftFilter:
    def __init__(self, run: Run = subprocess.run):
        self._run = run
        self._cut_ips: set[str] = set()
        self._acct_ips: set[str] = set()

    # ── Table / chain lifecycle ───────────────────────────────────────────────

    def ensure(self) -> bool:
        """Create the table + forward chain idempotently. Returns True on success."""
        r1 = _nft(self._run, "add", "table", FAMILY, TABLE)
        r2 = _nft(
            self._run,
            "add",
            "chain",
            FAMILY,
            TABLE,
            CHAIN,
            "{ type filter hook forward priority filter ; policy accept ; }",
        )
        ok = r1.returncode == 0 and r2.returncode == 0
        if not ok:
            _log.warning(
                "nft_filter: ensure failed (table rc=%s chain rc=%s)", r1.returncode, r2.returncode
            )
        return ok

    def cleanup(self) -> None:
        """Delete our own table (scoped — never flushes anything else)."""
        _nft(self._run, "delete", "table", FAMILY, TABLE)
        self._cut_ips.clear()
        self._acct_ips.clear()

    # ── Cut (FORWARD DROP) ────────────────────────────────────────────────────

    def cut(self, ip: str) -> bool:
        """Insert drop rules for ``ip`` at the TOP of the chain (DROP first)."""
        if not valid_ip(ip):
            _log.warning("nft_filter: refusing to cut invalid ip %r", ip)
            return False
        self.ensure()
        ok = True
        # insert (not add) so the drops sit above the accounting accepts.
        for field in ("daddr", "saddr"):
            if not self._has_rule(_CUT, field, ip):
                r = _nft(
                    self._run,
                    "insert",
                    "rule",
                    FAMILY,
                    TABLE,
                    CHAIN,
                    "ip",
                    field,
                    ip,
                    "drop",
                    "comment",
                    _CUT,
                )
                if r.returncode != 0:
                    _log.warning("nft_filter: cut %s %s failed: %s", field, ip, r.stderr.strip())
                    ok = False
        self._cut_ips.add(ip)
        return ok

    def uncut(self, ip: str) -> None:
        self._delete_tagged(_CUT, ip)
        self._cut_ips.discard(ip)

    # ── Accounting (FORWARD ACCEPT + counter) ─────────────────────────────────

    def add_accounting(self, ip: str) -> bool:
        if not valid_ip(ip):
            return False
        if ip in self._acct_ips:
            return True
        self.ensure()
        ok = True
        for field in ("saddr", "daddr"):
            if not self._has_rule(_ACCT, field, ip):
                r = _nft(
                    self._run,
                    "add",
                    "rule",
                    FAMILY,
                    TABLE,
                    CHAIN,
                    "ip",
                    field,
                    ip,
                    "counter",
                    "accept",
                    "comment",
                    _ACCT,
                )
                if r.returncode != 0:
                    _log.warning(
                        "nft_filter: accounting %s %s failed: %s", field, ip, r.stderr.strip()
                    )
                    ok = False
        self._acct_ips.add(ip)
        return ok

    def remove_accounting(self, ip: str) -> None:
        self._delete_tagged(_ACCT, ip)
        self._acct_ips.discard(ip)

    def remove_all_accounting(self) -> None:
        for ip in list(self._acct_ips):
            self.remove_accounting(ip)

    # ── Counters ──────────────────────────────────────────────────────────────

    def read_counters(self) -> dict[str, tuple[int, int]]:
        """Return {ip: (rx_bytes, tx_bytes)} from the accounting rules.

        saddr counts upload (TX), daddr counts download (RX) — matching the old
        iptables FORWARD -s/-d semantics.
        """
        out: dict[str, list[int]] = {}
        for rule in self._list_rules():
            if rule.get("comment") != _ACCT:
                continue
            field, ip, byts = _rule_ip_bytes(rule)
            if ip is None:
                continue
            slot = out.setdefault(ip, [0, 0])
            if field == "daddr":
                slot[0] += byts  # RX
            elif field == "saddr":
                slot[1] += byts  # TX
        return {ip: (rx, tx) for ip, (rx, tx) in out.items()}

    # ── Internals ─────────────────────────────────────────────────────────────

    def _list_rules(self) -> list[dict]:
        r = _nft(self._run, "-j", "list", "chain", FAMILY, TABLE, CHAIN)
        if r.returncode != 0 or not r.stdout:
            return []
        try:
            data = json.loads(r.stdout)
        except (ValueError, TypeError):
            return []
        return [obj["rule"] for obj in data.get("nftables", []) if "rule" in obj]

    def _has_rule(self, tag: str, field: str, ip: str) -> bool:
        for rule in self._list_rules():
            if rule.get("comment") != tag:
                continue
            f, rip, _ = _rule_ip_bytes(rule)
            if f == field and rip == ip:
                return True
        return False

    def _delete_tagged(self, tag: str, ip: str) -> None:
        """Delete every rule with ``tag`` matching ``ip`` by exact handle."""
        for rule in self._list_rules():
            if rule.get("comment") != tag:
                continue
            _f, rip, _b = _rule_ip_bytes(rule)
            handle = rule.get("handle")
            if rip == ip and handle is not None:
                _nft(self._run, "delete", "rule", FAMILY, TABLE, CHAIN, "handle", str(handle))


def _rule_ip_bytes(rule: dict) -> tuple[str | None, str | None, int]:
    """Extract (field, ip, byte-count) from an nft rule's expr list."""
    field: str | None = None
    ip: str | None = None
    byts = 0
    for expr in rule.get("expr", []):
        if "match" in expr:
            left = expr["match"].get("left", {})
            payload = left.get("payload", {})
            if payload.get("field") in ("saddr", "daddr"):
                field = payload["field"]
                ip = expr["match"].get("right")
        elif "counter" in expr:
            byts = expr["counter"].get("bytes", 0)
    return field, ip, byts
