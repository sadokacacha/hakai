"""
network/xdp_engine.py — High-Performance Packet Nullification via eBPF XDP.

Drops packets at the NIC driver level (RX path) for zero-CPU "Cuts."
This bypasses the entire Linux networking stack (iptables/nftables).
"""

import ipaddress
import logging
from typing import Any

_log = logging.getLogger(__name__)

# The eBPF C program to be loaded into the NIC.
XDP_PROGRAM_C = r"""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Map to store the IPs we want to drop */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);
    __type(value, __u8);
} drop_ips SEC(".maps");

SEC("xdp")
int hakai_xdp_drop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* Check if source OR destination IP is in our drop map */
    __u8 *drop_src = bpf_map_lookup_elem(&drop_ips, &iph->saddr);
    __u8 *drop_dst = bpf_map_lookup_elem(&drop_ips, &iph->daddr);
    
    if (drop_src || drop_dst) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""


class XDPEngine:
    def __init__(self, iface: str):
        self.iface = iface
        self._loaded = False
        self._bpf: Any = None

    def load(self):
        """Loads the XDP program using BCC (if installed)."""
        try:
            from bcc import BPF

            self._bpf = BPF(text=XDP_PROGRAM_C)
            fn = self._bpf.load_func("hakai_xdp_drop", BPF.XDP)
            self._bpf.attach_xdp(self.iface, fn, 0)
            self._loaded = True
            return True
        except Exception:
            # Fallback: BCC/clang is required for XDP. Don't keep a half-built
            # BPF reference around on failure.
            self._bpf = None
            self._loaded = False
            return False

    @staticmethod
    def _key(ip: str) -> bytes | None:
        """Network-byte-order 4-byte key for the eBPF __be32 map, or None if the
        IP isn't a valid dotted-quad IPv4 (socket.inet_aton accepts short forms
        like '1.2.3' and would produce a wrong key that never matches traffic)."""
        try:
            return ipaddress.IPv4Address(ip).packed
        except (ipaddress.AddressValueError, ValueError):
            return None

    def add_drop(self, ip: str):
        if not self._loaded:
            return
        key = self._key(ip)
        if key is None:
            _log.warning("xdp: refusing to drop invalid IPv4 %r", ip)
            return
        import struct

        try:
            self._bpf["drop_ips"][key] = struct.pack("B", 1)
        except Exception as e:
            _log.warning("xdp: failed to add drop for %s: %s", ip, e)

    def remove_drop(self, ip: str):
        if not self._loaded:
            return
        key = self._key(ip)
        if key is None:
            return
        try:
            del self._bpf["drop_ips"][key]
        except Exception:
            pass

    def unload(self):
        if not (self._loaded and self._bpf):
            return
        try:
            self._bpf.remove_xdp(self.iface, 0)
        except Exception as e:
            _log.warning("xdp: remove_xdp failed, program may remain attached: %s", e)
        finally:
            # Clear state regardless, so unload is idempotent and a failed
            # detach can't wedge _loaded True.
            self._loaded = False
            self._bpf = None
