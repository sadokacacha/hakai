"""
network/recon_engine.py — Sovereign Zero-Visibility Recon Engine.
"""
from __future__ import annotations
import asyncio
import socket
import re
import ssl
import xml.etree.ElementTree as ET
from typing import Optional, Tuple
from scapy.all import DNS, DNSRR, IP, UDP

class ReconEngine:
    def __init__(self):
        # Domain -> Device Class mapping
        self._domain_map = {
            "icloud.com": "Apple User", "apple.com": "Apple User",
            "googleapis.com": "Android User", "android.com": "Android User",
            "microsoft.com": "Windows User", "windows.com": "Windows User",
            "spotify.com": "Spotify Player", "netflix.com": "Media Device",
            "amazon.com": "Amazon/Echo", "nintendo.net": "Nintendo Switch"
        }
        self._ptr_cache = {}

    async def run_recon(self, ip: str, gateway_ip: str) -> dict:
        """Executes parallel Stages 2-5 for a target node."""
        # The semaphore must be created inside the running loop. run_deep_recon
        # drives each call via asyncio.run() in its own worker thread (a fresh
        # event loop per call), so a semaphore built in __init__ would be bound
        # to a different loop and raise "got Future attached to a different loop".
        semaphore = asyncio.Semaphore(25)
        async with semaphore:
            tasks = [
                self.get_ssl_cert_cn(ip),
                self.get_upnp_friendly_name(ip),
                self.get_netbios_name(ip),
                self.get_ptr_record(ip, gateway_ip),
                self.get_ipv6_neighbor(ip)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            return {
                "ssl_cn":     results[0] if isinstance(results[0], str) else "",
                "upnp_model": results[1] if isinstance(results[1], str) else "",
                "netbios":    results[2] if isinstance(results[2], str) else "",
                "ptr_name":   results[3] if isinstance(results[3], str) else "",
                "ipv6_ll":    results[4] if isinstance(results[4], str) else ""
            }

    # ── Stage 1: DNS Traffic Analysis (Passive Correlation) ───────────
    def analyze_dns(self, pkt) -> tuple[Optional[str], Optional[str]]:
        """Maps query domains to device classes."""
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0 or not pkt.haslayer(IP): return None, None
        
        ip = pkt[IP].src
        qname = pkt[DNS].qd.qname.decode(errors="ignore").lower()
        
        for dom, cls in self._domain_map.items():
            if dom in qname:
                return ip, cls
        return ip, None

    # ── Stage 3: SSL Cert Scraping (Modem/Router ID) ──────────────────
    async def get_ssl_cert_cn(self, ip: str) -> str:
        """Extracts CN from SSL certificate without full handshake."""
        try:
            # We use a custom SSL context to avoid full verify
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Using asyncio.open_connection to handle the TCP part
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx), timeout=3.0
            )
            cert_bin = writer.get_extra_info("ssl_obj").getpeercert(binary_form=True)
            writer.close()
            await writer.wait_closed()
            
            # Use DER decoding to find the CN field
            # Simplified: look for the common name pattern in binary
            if b"\x06\x03U\x04\x03" in cert_bin: # OID for Common Name
                idx = cert_bin.find(b"\x06\x03U\x04\x03") + 5
                # The next few bytes are the string length/type
                # This is a bit rough but works for most modem certs
                cn_raw = cert_bin[idx+2 : idx+32].split(b"\x00")[0]
                cn = cn_raw.decode(errors="ignore").strip()
                # Clean up non-printable characters
                return "".join(c for c in cn if c.isprintable())
            return ""
        except Exception:
            return ""

    # ── Stage 3: UPnP/SSDP XML Parsing ────────────────────────────────
    async def get_upnp_friendly_name(self, ip: str) -> str:
        """Queries port 1900/80/8080 for UPnP description.xml."""
        for port in [1900, 80, 8080]:
            try:
                # In a real environment, we'd look for the Location header from SSDP
                # Here we probe common paths
                url = f"http://{ip}:{port}/description.xml"
                # Simplified fetch using asyncio
                # (Normally we'd use aiohttp, but let's stick to standard libs)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=2.0
                )
                writer.write(f"GET /description.xml HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
                await writer.drain()
                data = await reader.read(4096)
                writer.close()
                await writer.wait_closed()
                
                resp = data.decode(errors="ignore")
                if "<friendlyName>" in resp:
                    m = re.search(r"<friendlyName>(.*?)</friendlyName>", resp)
                    return m.group(1) if m else ""
            except Exception:
                continue
        return ""

    # ── Stage 2: NetBIOS Name Query ──────────────────────────────────
    async def get_netbios_name(self, ip: str) -> str:
        """Queries port 137 for Windows NetBIOS name."""
        class NetBIOSProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.future = asyncio.get_event_loop().create_future()
            def datagram_received(self, data, addr):
                if not self.future.done(): self.future.set_result(data)
            def error_received(self, exc):
                if not self.future.done(): self.future.set_exception(exc)

        try:
            # NetBIOS Node Status Request
            query = b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01"
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                NetBIOSProtocol, remote_addr=(ip, 137)
            )
            
            try:
                transport.sendto(query)
                data = await asyncio.wait_for(protocol.future, timeout=1.5)
                # Parse NetBIOS response: Name is usually at index 57+
                if len(data) > 57:
                    name_raw = data[57:72].split(b"\x00")[0].split(b" ")[0]
                    return name_raw.decode(errors="ignore").strip()
            finally:
                transport.close()
            return ""
        except Exception:
            return ""


    # ── Stage 4: Reverse DNS (PTR) ───────────────────────────────────
    async def get_ptr_record(self, ip: str, dns_server: str) -> str:
        try:
            proc = await asyncio.create_subprocess_shell(
                f"dig @{dns_server} -x {ip} +short",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            name = stdout.decode().strip().rstrip(".")
            return name if name else ""
        except Exception:
            return ""

    # ── Stage 5: IPv6 Neighbor Correlation ───────────────────────────
    async def get_ipv6_neighbor(self, ip: str) -> str:
        try:
            proc = await asyncio.create_subprocess_shell(
                f"ip -6 neigh show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            for line in stdout.decode().splitlines():
                if "lladdr" in line:
                    parts = line.split()
                    v6_ip = parts[0]
                    # This logic would match MAC to correlate v4/v6
                    return v6_ip
            return ""
        except Exception:
            return ""
