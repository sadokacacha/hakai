"""
Regression test for network/dhcp_sniffer.py (Phase-2 hunt).

DHCP-1  The option loop guarded isinstance(opt, tuple) but not length, so a
        malformed/short option tuple from an untrusted LAN DHCP packet raised
        IndexError on opt[1], aborting the parse (and restarting the intel
        sniffer). Short option tuples are now skipped.

A fake packet mimics only the layers the parser touches (no real scapy packet
construction needed).
"""

from __future__ import annotations

from scapy.all import BOOTP, DHCP, IP, Ether  # type: ignore[attr-defined]  # scapy.all is dynamic

from network import dhcp_sniffer as dhcp_mod


class _Layer:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Pkt:
    def __init__(self, options):
        self._layers = {
            DHCP: _Layer(options=options),
            Ether: _Layer(src="aa:bb:cc:dd:ee:ff"),
            IP: _Layer(src="192.168.1.5"),
            BOOTP: _Layer(ciaddr="0.0.0.0", yiaddr="0.0.0.0"),
        }

    def haslayer(self, cls):
        return cls in self._layers

    def __getitem__(self, cls):
        return self._layers[cls]


def test_malformed_short_option_does_not_abort_parse():
    os_calls: list = []
    # ("hostname",) is a malformed 1-tuple; the valid param_req_list follows it.
    pkt = _Pkt([("hostname",), ("param_req_list", [1, 3, 6, 15, 119, 252])])
    dhcp_mod.sniff_dhcp_os(pkt, lambda m, o: os_calls.append((m, o)), lambda i, h, m: None)
    assert os_calls == [("aa:bb:cc:dd:ee:ff", "Apple/iOS (Modern)")]


def test_valid_hostname_and_os_parse():
    os_calls: list = []
    hn_calls: list = []
    pkt = _Pkt(
        [
            ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
            ("hostname", b"my-laptop"),
        ]
    )
    dhcp_mod.sniff_dhcp_os(
        pkt,
        lambda m, o: os_calls.append((m, o)),
        lambda i, h, m: hn_calls.append((i, h, m)),
    )
    assert os_calls and os_calls[0] == ("aa:bb:cc:dd:ee:ff", "Windows 11")
    assert len(hn_calls) == 1
    assert hn_calls[0][1] == "my-laptop" and hn_calls[0][2] == "aa:bb:cc:dd:ee:ff"
