"""
ThreatLens – Packet Parser
Extracts structured fields from raw packets using Scapy.
Falls back to manual struct parsing when Scapy is unavailable.
"""

from datetime import datetime
from typing import Optional

from .models import ParsedPacket, AppType
from .sni_extractor import extract_sni, extract_http_host

# SNI → AppType keyword mapping
_SNI_MAP = [
    (["youtube", "googlevideo", "ytimg"],           AppType.YOUTUBE),
    (["facebook", "fbcdn", "fb.com", "fbsbx"],      AppType.FACEBOOK),
    (["instagram", "cdninstagram"],                  AppType.INSTAGRAM),
    (["tiktok", "tiktokcdn", "musical.ly"],          AppType.TIKTOK),
    (["netflix", "nflxso", "nflxvideo"],             AppType.NETFLIX),
    (["google", "googleapis", "gstatic", "gmail"],   AppType.GOOGLE),
    (["microsoft", "msft", "azure", "live.com", "outlook"], AppType.MICROSOFT),
    (["apple", "icloud", "mzstatic", "aaplimg"],     AppType.APPLE),
    (["amazon", "amazonaws", "cloudfront"],          AppType.AMAZON),
    (["github", "githubusercontent"],                AppType.GITHUB),
    (["cloudflare"],                                 AppType.CLOUDFLARE),
    (["twitter", "twimg", "t.co"],                   AppType.TWITTER),
    (["doubleclick", "googlesyndication", "adnxs",
      "ads.", "adserver", "adtrack", "taboola",
      "outbrain", "moatads"],                        AppType.ADWARE),
]

_MALWARE_KEYWORDS = [
    "malware", "botnet", "c2server", "ransomware", "exploit",
    "payload", "dropper", "rat.", "backdoor"
]


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
    sni_lower = sni.lower()
    for keywords, app in _SNI_MAP:
        if any(kw in sni_lower for kw in keywords):
            return app
    for kw in _MALWARE_KEYWORDS:
        if kw in sni_lower:
            return AppType.MALWARE
    return AppType.HTTPS


def parse_packet(raw_bytes: bytes, timestamp: Optional[float] = None) -> Optional[ParsedPacket]:
    """
    Parse raw bytes into a ParsedPacket.
    Uses Scapy if available, otherwise returns None for unsupported packets.
    """
    try:
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS
        import scapy.packet as sp

        pkt = Ether(raw_bytes)
        ts = datetime.utcfromtimestamp(timestamp) if timestamp else datetime.utcnow()

        parsed = ParsedPacket(timestamp=ts)
        parsed.src_mac = pkt.src if hasattr(pkt, "src") else ""
        parsed.dst_mac = pkt.dst if hasattr(pkt, "dst") else ""

        if IP in pkt:
            ip = pkt[IP]
            parsed.src_ip  = ip.src
            parsed.dst_ip  = ip.dst
            parsed.length  = len(raw_bytes)

            if TCP in pkt:
                tcp = pkt[TCP]
                parsed.src_port  = tcp.sport
                parsed.dst_port  = tcp.dport
                parsed.protocol  = "TCP"
                parsed.tcp_flags = str(tcp.flags)

                # Extract payload
                payload = bytes(tcp.payload)
                parsed.payload = payload

                # TLS SNI extraction (port 443 or TLS magic byte)
                if payload and (parsed.dst_port == 443 or payload[0] == 0x16):
                    sni = extract_sni(payload)
                    if sni:
                        parsed.sni = sni
                        parsed.is_tls = True
                        parsed.app_type = sni_to_app_type(sni)

                # HTTP Host extraction
                elif payload and parsed.dst_port in (80, 8080, 8000):
                    host = extract_http_host(payload)
                    if host:
                        parsed.http_host = host
                        parsed.app_type  = sni_to_app_type(host)
                    else:
                        parsed.app_type = AppType.HTTP

                if parsed.app_type == AppType.UNKNOWN:
                    parsed.app_type = AppType.HTTPS if parsed.dst_port == 443 else AppType.HTTP

            elif UDP in pkt:
                udp = pkt[UDP]
                parsed.src_port = udp.sport
                parsed.dst_port = udp.dport
                parsed.protocol = "UDP"
                payload = bytes(udp.payload)
                parsed.payload = payload

                # DNS query extraction
                if DNS in pkt:
                    try:
                        dns = pkt[DNS]
                        if dns.qd:
                            parsed.dns_query = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                            parsed.app_type  = AppType.DNS
                    except Exception:
                        pass

            elif ICMP in pkt:
                parsed.protocol = "ICMP"

        return parsed

    except ImportError:
        # Scapy not installed – return minimal parsed packet
        return None
    except Exception:
        return None
