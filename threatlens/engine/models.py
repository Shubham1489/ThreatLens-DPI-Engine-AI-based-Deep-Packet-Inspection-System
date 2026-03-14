"""
ThreatLens – Core Data Models
Dataclasses representing network entities throughout the system.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from enum import Enum


class AppType(str, Enum):
    UNKNOWN   = "Unknown"
    HTTP      = "HTTP"
    HTTPS     = "HTTPS"
    DNS       = "DNS"
    GOOGLE    = "Google"
    YOUTUBE   = "YouTube"
    FACEBOOK  = "Facebook"
    TWITTER   = "Twitter"
    INSTAGRAM = "Instagram"
    TIKTOK    = "TikTok"
    NETFLIX   = "Netflix"
    AMAZON    = "Amazon"
    MICROSOFT = "Microsoft"
    APPLE     = "Apple"
    GITHUB    = "GitHub"
    CLOUDFLARE= "Cloudflare"
    ADWARE    = "Adware"
    MALWARE   = "Malware"


class ThreatLabel(str, Enum):
    NORMAL      = "NORMAL"
    PORT_SCAN   = "PORT_SCAN"
    DOS_ATTACK  = "DOS_ATTACK"
    MALWARE_C2  = "MALWARE_C2"
    ADWARE      = "ADWARE"
    TOR_TRAFFIC = "TOR_TRAFFIC"
    P2P_TRAFFIC = "P2P_TRAFFIC"
    ANOMALY     = "ANOMALY"


class AlertSeverity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class FiveTuple:
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: str  # TCP / UDP / ICMP

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.protocol == other.protocol)

    def reverse(self) -> "FiveTuple":
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)


@dataclass
class ParsedPacket:
    timestamp:    datetime
    src_mac:      str = ""
    dst_mac:      str = ""
    src_ip:       str = ""
    dst_ip:       str = ""
    src_port:     int = 0
    dst_port:     int = 0
    protocol:     str = "UNKNOWN"
    length:       int = 0
    payload:      bytes = b""
    sni:          Optional[str] = None
    http_host:    Optional[str] = None
    app_type:     AppType = AppType.UNKNOWN
    is_tls:       bool = False
    blocked:      bool = False
    tcp_flags:    str = ""
    dns_query:    Optional[str] = None


@dataclass
class Flow:
    five_tuple:      FiveTuple
    start_time:      datetime = field(default_factory=datetime.utcnow)
    end_time:        Optional[datetime] = None
    pkt_count:       int = 0
    byte_count:      int = 0
    sni:             Optional[str] = None
    http_host:       Optional[str] = None
    app_type:        AppType = AppType.UNKNOWN
    ml_label:        ThreatLabel = ThreatLabel.NORMAL
    ml_confidence:   float = 0.0
    blocked:         bool = False
    pkt_sizes:       list = field(default_factory=list)
    inter_arrivals:  list = field(default_factory=list)
    last_ts:         Optional[datetime] = None


@dataclass
class Alert:
    alert_type:   str
    severity:     AlertSeverity
    src_ip:       str
    description:  str
    timestamp:    datetime = field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    flow_id:      Optional[str] = None
