"""
network/rawsock.py — raw AF_PACKET L2 sender (STEP 4 send-path optimisation).

The division of labour is "scapy builds, raw socket sends, scapy parses": a
caller serialises a scapy frame once (``bytes(pkt)``) and then blasts those bytes
through a bound ``AF_PACKET`` / ``SOCK_RAW`` socket in a tight loop, avoiding
scapy's per-call ``sendp`` overhead (re-resolve iface, re-serialise, route).

AF_PACKET requires root (CAP_NET_RAW). When the socket can't be opened (non-root,
Windows, no such iface) ``available`` is False and the caller falls back to
scapy's ``sendp`` — so behaviour is never worse, only faster when permitted.

The actual packets/sec gain is root-gated; see tools/bench_send.py.
"""

from __future__ import annotations

import logging
import socket
from collections.abc import Callable

from core.osutil import IS_WINDOWS as _IS_WINDOWS

_log = logging.getLogger(__name__)

_ETH_P_ALL = 0x0003


def _default_socket() -> socket.socket:
    return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))


class RawL2Sender:
    """Send pre-built L2 frames via a bound AF_PACKET socket.

    ``available`` is False if the socket could not be opened/bound (non-root,
    Windows, bad iface); callers use scapy as the fallback in that case.
    """

    def __init__(self, iface: str, sock_factory: Callable[[], socket.socket] = _default_socket):
        self.iface = iface
        self._sock: socket.socket | None = None
        self.available = False
        if _IS_WINDOWS or not iface:
            return
        try:
            s = sock_factory()
            s.bind((iface, 0))
            self._sock = s
            self.available = True
        except (OSError, PermissionError) as e:
            _log.info("rawsock: AF_PACKET unavailable on %s (%s) — using scapy fallback", iface, e)

    def send(self, frame: bytes) -> bool:
        """Send one raw L2 frame. Returns False (never raises) on any failure."""
        if not self.available or self._sock is None:
            return False
        try:
            self._sock.send(frame)
            return True
        except OSError as e:
            _log.debug("rawsock: send failed on %s: %s", self.iface, e)
            return False

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self.available = False

    def __enter__(self) -> RawL2Sender:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
