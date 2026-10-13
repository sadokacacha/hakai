"""
network/xdp_engine.py — High-Performance Packet Nullification via eBPF XDP.

Drops packets at the NIC driver level (RX path) for zero-CPU "Cuts."
This bypasses the entire Linux networking stack (iptables/nftables).
"""

from typing import Any

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
            # Fallback: explain that BCC/clang is required for XDP
            return False

    def add_drop(self, ip: str):
        if not self._loaded: return
        import socket
        import struct
        try:
            # key must be in network byte order (big-endian) for the eBPF code
            key = socket.inet_aton(ip)
            self._bpf["drop_ips"][key] = struct.pack("B", 1)
        except Exception:
            pass

    def remove_drop(self, ip: str):
        if not self._loaded: return
        import socket
        try:
            key = socket.inet_aton(ip)
            del self._bpf["drop_ips"][key]
        except Exception:
            pass

    def unload(self):
        if self._loaded and self._bpf:
            self._bpf.remove_xdp(self.iface, 0)
            self._loaded = False
