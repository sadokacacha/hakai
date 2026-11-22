"""
system/firewall_apex.py — Sovereign nftables logic.
Status: [SHIELDS: LOCKED]
"""

from __future__ import annotations

import logging
import subprocess

_log = logging.getLogger(__name__)


class GhostFirewall:
    def __init__(self):
        self.active = False

    def toggle_stealth(self, enable: bool) -> str:
        """
        Implements a Stealth-Drop policy via nftables.
        The host becomes a 'Black Hole' for Nmap, Ping, and unsolicited TCP.
        """
        try:
            # 1. Clear our own lanwarden table for a clean state (scoped to our own
            #    table — never touches the host's other nftables rules).
            subprocess.run(
                ["nft", "delete", "table", "inet", "lanwarden_stealth"], capture_output=True
            )

            if not enable:
                self.active = False
                return "[SHIELDS: DISENGAGED]"

            try:
                # 2. Create table
                subprocess.run(
                    ["nft", "add", "table", "inet", "lanwarden_stealth"],
                    check=True,
                    capture_output=True,
                )
                # 3. Create chain with DROP policy
                subprocess.run(
                    [
                        "nft",
                        "add",
                        "chain",
                        "inet",
                        "lanwarden_stealth",
                        "input",
                        "{ type filter hook input priority 0; policy drop; }",
                    ],
                    check=True,
                    capture_output=True,
                )
                # 4. Allow Established/Related traffic (so we can still use the net)
                subprocess.run(
                    [
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        "lanwarden_stealth",
                        "input",
                        "ct state established,related accept",
                    ],
                    check=True,
                    capture_output=True,
                )
                # 5. Allow Loopback
                subprocess.run(
                    ["nft", "add", "rule", "inet", "lanwarden_stealth", "input", "iif lo accept"],
                    check=True,
                    capture_output=True,
                )
            except (subprocess.CalledProcessError, OSError) as e:
                # A partial build leaves a drop-policy chain WITHOUT the accept
                # rules, which locks the host out of its own network. Tear the
                # half-built table down so we fail safe.
                _log.error("GhostFirewall build failed, rolling back half-built table: %s", e)
                subprocess.run(
                    ["nft", "delete", "table", "inet", "lanwarden_stealth"], capture_output=True
                )
                self.active = False
                return "[ERROR: FIREWALL_FAIL - build rolled back]"

            self.active = True
            return "[SHIELDS: LOCKED]"
        except (subprocess.CalledProcessError, OSError) as e:
            self.active = False
            return f"[ERROR: {e!s}]"
