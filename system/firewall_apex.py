"""
system/firewall_apex.py — Sovereign nftables logic.
Status: [SHIELDS: LOCKED]
"""
from __future__ import annotations
import subprocess

class GhostFirewall:
    def __init__(self):
        self.active = False

    def toggle_stealth(self, enable: bool) -> str:
        """
        Implements a Stealth-Drop policy via nftables.
        The host becomes a 'Black Hole' for Nmap, Ping, and unsolicited TCP.
        """
        try:
            # 1. Clear existing Hakai tables for a clean state
            subprocess.run(["nft", "delete", "table", "inet", "hakai_stealth"], capture_output=True)
            
            if enable:
                # 2. Create table
                subprocess.run(["nft", "add", "table", "inet", "hakai_stealth"], check=True)
                # 3. Create chain with DROP policy
                subprocess.run(["nft", "add", "chain", "inet", "hakai_stealth", "input", 
                               "{ type filter hook input priority 0; policy drop; }"], check=True)
                # 4. Allow Established/Related traffic (so we can still use the net)
                subprocess.run(["nft", "add", "rule", "inet", "hakai_stealth", "input", 
                               "ct state established,related accept"], check=True)
                # 5. Allow Loopback
                subprocess.run(["nft", "add", "rule", "inet", "hakai_stealth", "input", 
                               "iif lo accept"], check=True)
                
                self.active = True
                return "[SHIELDS: LOCKED]"
            else:
                self.active = False
                return "[SHIELDS: DISENGAGED]"
        except subprocess.CalledProcessError as e:
            return f"[ERROR: FIREWALL_FAIL - Check permissions]"
        except Exception as e:
            return f"[ERROR: {str(e)}]"
