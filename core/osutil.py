"""
core/osutil.py — single source of truth for the platform check.

The networking engine is Linux-only; `IS_WINDOWS` gates the Linux-only paths
(iptables/tc/nft/sysctl/scapy raw sockets) that were previously each guarded by a
module-local `_IS_WINDOWS = sys.platform == "win32"`. A leaf module (imports only
`sys`), so any layer can import it without an import cycle.

NOTE (P4-5): this centralises only the *definition*. The Windows *behaviour* is
still inconsistent across the engine — some paths silently fake success
(iptables/tc), others return an explicit error (masquerade/chameleon/firewall/
nmcli). Unifying that (AGENTS.md: "Windows paths must not silently no-op") is a
behaviour change on an unsupported, untested platform and needs a product
decision (Windows = explicitly-unsupported vs best-effort-degraded); left
documented, not changed.
"""

from __future__ import annotations

import sys

IS_WINDOWS: bool = sys.platform == "win32"
