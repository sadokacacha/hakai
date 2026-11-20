"""
network/fingerprint.py — Device fingerprinting via nmap -O -sV.
Runs in a background daemon thread, calls back with results.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import threading

_log = logging.getLogger(__name__)

COMMON_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3389,5900,8080,8443,1883,5432,3306"


def _valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


def _parse_nmap(stdout: str) -> tuple[list[int], str, dict[int, str]]:
    """Extract (open_ports, os_guess, services) from `nmap -O -sV` output."""
    open_ports: list[int] = []
    os_guess: str = ""
    services: dict[int, str] = {}

    for line in stdout.splitlines():
        ls = line.strip()

        if "/tcp" in ls and "open" in ls:
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?", ls)
            if m:
                port = int(m.group(1))
                svc = m.group(2)
                ver = (m.group(3) or "").strip()[:40]
                open_ports.append(port)
                services[port] = f"{svc} {ver}".strip()

        if "OS details:" in ls:
            candidate = ls.split(":", 1)[1].strip()[:80]
            if not os_guess or len(candidate) > len(os_guess):
                os_guess = candidate
        elif "Aggressive OS guesses:" in ls and not os_guess:
            raw = ls.split(":", 1)[1].strip()
            first = raw.split(",")[0]
            os_guess = re.sub(r"\s*\(\d+%\)", "", first).strip()[:80]
        elif "Running:" in ls and not os_guess:
            os_guess = ls.split(":", 1)[1].strip()[:80]

    return open_ports, os_guess, services


def fingerprint_device(ip: str, callback):
    """
    Background nmap OS+service detection.
    callback(open_ports: list[int], os_guess: str, services: dict[int, str])
    """
    if not _valid_ip(ip):
        _log.warning("fingerprint: refusing to scan invalid IP %r", ip)
        callback([], "", {})
        return

    def _run():
        nmap = shutil.which("nmap")
        if not nmap:
            callback([], "", {})
            return

        try:
            r = subprocess.run(
                [
                    nmap,
                    "-O",
                    "-sV",
                    "--osscan-guess",
                    "--osscan-limit",
                    "--version-intensity",
                    "5",
                    "-p",
                    COMMON_PORTS,
                    "--host-timeout",
                    "20s",
                    "--open",
                    ip,
                ],
                capture_output=True,
                text=True,
                timeout=45,
            )
            result = _parse_nmap(r.stdout)
        except (OSError, subprocess.SubprocessError) as e:
            _log.debug("fingerprint: nmap failed for %s: %s", ip, e)
            result = ([], "", {})

        callback(*result)

    threading.Thread(target=_run, daemon=True, name=f"fp_{ip}").start()
