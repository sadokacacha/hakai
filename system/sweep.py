"""
system/sweep.py — startup sweep of orphaned kernel objects.

Hakai → Lanwarden rename: a host that ran the OLD build may hold kernel objects
named under the old brand that the new code (which references the new names)
would never clear — an uncleanable nft table or a stuck OUTPUT DROP. This sweep
removes those legacy objects at startup, best-effort and idempotent.

It is also the home for the broader "clear orphans left by a hard kill" sweep:
every kernel object this app creates is comment/name-tagged with the `lanwarden`
operation id, so a crash that skipped teardown can be swept on the next start.

Linux-only; all calls are argv lists with captured output, and failures are
logged, never raised (a missing object is the normal case).
"""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable

from core.osutil import IS_WINDOWS as _IS_WINDOWS

_log = logging.getLogger(__name__)

# Objects named under the pre-rename brand that must be cleared on upgrade.
_LEGACY_NFT_TABLES = (("inet", "hakai_stealth"),)
_LEGACY_IPT_COMMENTS = ("hakai_killswitch",)


def sweep_legacy(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
    """Remove kernel objects left under the old (Hakai) brand. Best-effort."""
    if _IS_WINDOWS:
        return
    for family, table in _LEGACY_NFT_TABLES:
        try:
            run(["nft", "delete", "table", family, table], capture_output=True)
        except (OSError, subprocess.SubprocessError) as e:
            _log.debug("sweep: nft delete %s %s failed: %s", family, table, e)

    for comment in _LEGACY_IPT_COMMENTS:
        # Repeated kills could have stacked duplicates; delete until none remain.
        for _ in range(10):
            try:
                r = run(
                    [
                        "iptables",
                        "-D",
                        "OUTPUT",
                        "-m",
                        "comment",
                        "--comment",
                        comment,
                        "-j",
                        "DROP",
                    ],
                    capture_output=True,
                )
            except (OSError, subprocess.SubprocessError) as e:
                _log.debug("sweep: iptables -D %s failed: %s", comment, e)
                break
            if r.returncode != 0:
                break
    _log.debug("legacy kernel-object sweep complete")
