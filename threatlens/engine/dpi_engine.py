"""
ThreatLens – DPI Engine
Main orchestrator: reads packets, parses them, tracks flows,
applies ML classification, checks rules, fires alerts.
"""

import asyncio
import threading
import time
import os
os.environ["SCAPY_USE_PCAP"] = "true"
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, List, Optional, Dict

from .models import ParsedPacket, Flow, Alert, AlertSeverity, ThreatLabel, AppType
from .packet_parser import parse_packet
from .flow_tracker import FlowTracker
from .rule_manager import RuleManager

# Alert thresholds
PORT_SCAN_THRESHOLD    = 20   # unique dst_ports / 10s
DOS_THRESHOLD          = 500  # packets / second from single IP
ML_ALERT_CONFIDENCE    = 0.75

# Alert cooldowns (seconds) – prevent the same IP from spamming alerts
DOS_ALERT_COOLDOWN       = 60   # 1 minute between DOS alerts per IP
PORT_SCAN_ALERT_COOLDOWN = 30   # 30 seconds between portscan alerts per IP


class DPIEngine:
    """
    Core engine that ties together:
    - Live capture or PCAP file reading (via Scapy)
    - Packet parsing and SNI extraction
    - Flow tracking
    - ML-based threat classification
    - Rule-based blocking
    - Alert generation
    """

    def __init__(self, rule_manager: RuleManager, classifier=None):
        self.rule_manager = rule_manager
        self.classifier   = classifier   # Optional MLClassifier instance
        self.flow_tracker = FlowTracker()

        self._running        = False
        self._capture_thread: Optional[threading.Thread] = None

        # Metrics
        self.total_packets  = 0
        self.total_bytes    = 0
        self.blocked_count  = 0
        self.start_time     = datetime.utcnow()

        # Recent packets ring-buffer for dashboard
        self._recent_packets: deque = deque(maxlen=500)
        self._recent_alerts:  deque = deque(maxlen=200)
        self._packets_per_sec: deque = deque(maxlen=60)  # last 60 seconds
        self._pps_window: Dict[int, int] = defaultdict(int)
        self._bps_window: Dict[int, int] = defaultdict(int)  # bytes per second
        self._pps_history: deque = deque(maxlen=120)  # 2-min history for charts
        self._bps_history: deque = deque(maxlen=120)

        # Port scan detection: ip -> set of ports seen in last 10s
        self._port_scan_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # DoS detection: ip -> packet timestamps in last 1s
        self._dos_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))

        # Alert cooldowns: ip -> last alert timestamp
        self._dos_alert_cooldown: Dict[str, float] = {}
        self._portscan_alert_cooldown: Dict[str, float] = {}

        # Callbacks
        self._on_packet_callbacks: List[Callable] = []
        self._on_alert_callbacks:  List[Callable] = []
        self._on_flow_callbacks:   List[Callable] = []

    # ── Callbacks ────────────────────────────────────────────────────────────

    def on_packet(self, cb: Callable): self._on_packet_callbacks.append(cb)
    def on_alert(self,  cb: Callable): self._on_alert_callbacks.append(cb)
    def on_flow(self,   cb: Callable): self._on_flow_callbacks.append(cb)

    def _fire_packet(self, pkt): [cb(pkt) for cb in self._on_packet_callbacks]
    def _fire_alert(self,  a):   [cb(a)   for cb in self._on_alert_callbacks]
    def _fire_flow(self,   f):   [cb(f)   for cb in self._on_flow_callbacks]

    # ── Packet processing ────────────────────────────────────────────────────

    def process_raw(self, raw_bytes: bytes, timestamp: Optional[float] = None):
        """Parse and process a single raw packet."""
        pkt = parse_packet(raw_bytes, timestamp)
        if pkt is None:
            return

        self.total_packets += 1
        self.total_bytes   += pkt.length

        # Track packets/sec and bytes/sec
        sec_bucket = int(time.time())
        self._pps_window[sec_bucket] += 1
        self._bps_window[sec_bucket] += pkt.length

        # Cleanup old entries (keep last 10 seconds) to prevent memory leak
        stale = [k for k in self._pps_window if sec_bucket - k > 10]
        for k in stale:
            del self._pps_window[k]
            self._bps_window.pop(k, None)

        # Check blocking rules
        if self.rule_manager.should_block(pkt.src_ip, pkt.dst_ip, pkt.sni or "", pkt.app_type):
            pkt.blocked = True
            self.blocked_count += 1

        # Update flow
        flow = self.flow_tracker.update(pkt)
        if flow is None:
            return

        # Threat detection
        self._detect_port_scan(pkt)
        self._detect_dos(pkt)
        self._detect_adware(pkt)

        # ML classification on completed flows
        for completed in self.flow_tracker.get_completed_flows():
            self._classify_flow(completed)
            self._fire_flow(completed)

        # Store recent packet summary (no raw payload for privacy)
        summary = {
            "ts":        pkt.timestamp.isoformat(),
            "src_ip":    pkt.src_ip,
            "dst_ip":    pkt.dst_ip,
            "src_port":  pkt.src_port,
            "dst_port":  pkt.dst_port,
            "protocol":  pkt.protocol,
            "length":    pkt.length,
            "app_type":  pkt.app_type.value,
            "sni":       pkt.sni or "",
            "blocked":   pkt.blocked,
        }
        self._recent_packets.append(summary)
        self._fire_packet(summary)

    # ── Threat detection ─────────────────────────────────────────────────────

    def _detect_port_scan(self, pkt: ParsedPacket):
        if pkt.protocol != "TCP" or not pkt.src_ip:
            return
        now = time.time()
        tracker = self._port_scan_tracker[pkt.src_ip]
        tracker.append((now, pkt.dst_port))

        # Count unique ports in last 10 seconds
        recent = [(ts, p) for ts, p in tracker if now - ts <= 10]
        unique_ports = len(set(p for _, p in recent))

        if unique_ports >= PORT_SCAN_THRESHOLD:
            # Check cooldown — skip if we already alerted recently for this IP
            last_alert = self._portscan_alert_cooldown.get(pkt.src_ip, 0)
            if now - last_alert < PORT_SCAN_ALERT_COOLDOWN:
                return
            self._portscan_alert_cooldown[pkt.src_ip] = now
            self._emit_alert(
                alert_type  = "PORT_SCAN",
                severity    = AlertSeverity.HIGH,
                src_ip      = pkt.src_ip,
                description = f"Port scan detected: {unique_ports} unique ports probed in 10s from {pkt.src_ip}",
            )
            self._port_scan_tracker[pkt.src_ip] = deque(maxlen=200)  # reset

    def _detect_dos(self, pkt: ParsedPacket):
        if not pkt.src_ip:
            return
        now = time.time()
        tracker = self._dos_tracker[pkt.src_ip]
        tracker.append(now)

        # Count packets in last second
        recent = sum(1 for ts in tracker if now - ts <= 1.0)
        if recent >= DOS_THRESHOLD:
            # Check cooldown — skip if we already alerted recently for this IP
            last_alert = self._dos_alert_cooldown.get(pkt.src_ip, 0)
            if now - last_alert < DOS_ALERT_COOLDOWN:
                return
            self._dos_alert_cooldown[pkt.src_ip] = now
            self._emit_alert(
                alert_type  = "DOS_ATTACK",
                severity    = AlertSeverity.CRITICAL,
                src_ip      = pkt.src_ip,
                description = f"DoS/DDoS detected: {recent} packets/sec from {pkt.src_ip}",
            )
            self._dos_tracker[pkt.src_ip] = deque(maxlen=10000)  # reset

    def _detect_adware(self, pkt: ParsedPacket):
        if pkt.app_type == AppType.ADWARE:
            self._emit_alert(
                alert_type  = "ADWARE",
                severity    = AlertSeverity.MEDIUM,
                src_ip      = pkt.src_ip,
                description = f"Adware network call detected: {pkt.sni or pkt.http_host or pkt.dst_ip}",
            )

    def _classify_flow(self, flow: Flow):
        if self.classifier is None:
            return
        try:
            label, confidence = self.classifier.classify(flow)
            flow.ml_label      = label
            flow.ml_confidence = confidence
            if label != ThreatLabel.NORMAL and confidence >= ML_ALERT_CONFIDENCE:
                self._emit_alert(
                    alert_type  = label.value,
                    severity    = AlertSeverity.HIGH if confidence > 0.9 else AlertSeverity.MEDIUM,
                    src_ip      = flow.five_tuple.src_ip,
                    description = f"ML detected {label.value} (confidence {confidence:.0%}) from {flow.five_tuple.src_ip} → {flow.five_tuple.dst_ip}",
                )
        except Exception:
            pass

    # ── Alert emission ────────────────────────────────────────────────────────

    def _emit_alert(self, alert_type: str, severity: AlertSeverity, src_ip: str, description: str):
        alert = Alert(
            alert_type  = alert_type,
            severity    = severity,
            src_ip      = src_ip,
            description = description,
        )
        self._recent_alerts.append({
            "id":           id(alert),
            "ts":           alert.timestamp.isoformat(),
            "type":         alert.alert_type,
            "severity":     alert.severity.value,
            "src_ip":       alert.src_ip,
            "description":  alert.description,
            "acknowledged": False,
        })
        self._fire_alert(self._recent_alerts[-1])

    # ── Stats / accessors ─────────────────────────────────────────────────────

    def get_security_score(self) -> int:
        """Calculate a security score from 0-100. Higher = more secure."""
        score = 100
        total = max(self.total_packets, 1)

        # Deduct for blocked ratio (up to -15 pts)
        blocked_ratio = self.blocked_count / total
        score -= min(int(blocked_ratio * 150), 15)

        # Deduct for alerts (up to -30 pts)
        alert_count = len(self._recent_alerts)
        score -= min(alert_count * 2, 30)

        # Deduct for critical/high alerts (extra penalty)
        crit = sum(1 for a in self._recent_alerts if a.get("severity") in ("CRITICAL", "HIGH"))
        score -= min(crit * 5, 25)

        # Deduct for adware traffic (up to -10 pts)
        adware_pkts = sum(1 for p in self._recent_packets if p.get("app_type") == "Adware")
        adware_ratio = adware_pkts / max(len(self._recent_packets), 1)
        score -= min(int(adware_ratio * 100), 10)

        # Bonus for having rules active (+5)
        if self.rule_manager.get_all_rules():
            score = min(score + 5, 100)

        return max(0, min(100, score))

    def get_stats(self) -> dict:
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        now = int(time.time())
        pps = self._pps_window.get(now, 0) or self._pps_window.get(now - 1, 0)
        bps = self._bps_window.get(now, 0) or self._bps_window.get(now - 1, 0)
        active_flows = self.flow_tracker.get_active_flows()

        # Store history for charts
        self._pps_history.append(pps)
        self._bps_history.append(bps)

        # App breakdown from recent packets
        app_counts: Dict[str, int] = defaultdict(int)
        for p in self._recent_packets:
            app_counts[p["app_type"]] += 1

        # Protocol breakdown
        proto_counts: Dict[str, int] = defaultdict(int)
        for p in self._recent_packets:
            proto_counts[p["protocol"]] += 1

        return {
            "total_packets":   self.total_packets,
            "total_bytes":     self.total_bytes,
            "blocked_count":   self.blocked_count,
            "active_flows":    len(active_flows),
            "alerts_count":    len(self._recent_alerts),
            "packets_per_sec": pps,
            "bytes_per_sec":   bps,
            "uptime_sec":      int(uptime),
            "app_breakdown":   dict(app_counts),
            "proto_breakdown": dict(proto_counts),
            "security_score":  self.get_security_score(),
            "pps_history":     list(self._pps_history),
            "bps_history":     list(self._bps_history),
        }

    def get_recent_packets(self, limit: int = 100) -> list:
        return list(self._recent_packets)[-limit:]

    def get_recent_alerts(self, limit: int = 50) -> list:
        return list(self._recent_alerts)[-limit:]

    def get_active_flows_summary(self) -> list:
        flows = self.flow_tracker.get_active_flows()
        return [
            {
                "src_ip":   f.five_tuple.src_ip,
                "dst_ip":   f.five_tuple.dst_ip,
                "protocol": f.five_tuple.protocol,
                "sni":      f.sni or "",
                "app":      f.app_type.value,
                "pkts":     f.pkt_count,
                "bytes":    f.byte_count,
                "label":    f.ml_label.value,
            }
            for f in flows
        ]

    # ── Live capture ──────────────────────────────────────────────────────────

    def start_capture(self, interface: str = None, pcap_file: str = None):
        """Start packet capture in a background thread."""
        self._running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, pcap_file),
            daemon=True,
        )
        self._capture_thread.start()

    def stop_capture(self):
        self._running = False

    def _capture_loop(self, interface: Optional[str], pcap_file: Optional[str]):
        try:
            from scapy.sendrecv import sniff
            from scapy.utils import rdpcap

            # Fix for Windows asyncio + scapy conflict
            try:
                asyncio.set_event_loop(asyncio.new_event_loop())
            except Exception:
                pass

            if pcap_file:
                # ── PCAP file mode ────────────────────────────────────────
                if not os.path.exists(pcap_file):
                    print(f"[ThreatLens] PCAP file not found: {pcap_file}. Falling back to demo mode.")
                    self._demo_mode()
                    return

                print(f"[ThreatLens] Analysing PCAP: {pcap_file}")
                pkts = rdpcap(pcap_file)

                for pkt in pkts:
                    if not self._running:
                        break
                    self.process_raw(bytes(pkt), float(pkt.time))

                print(f"[ThreatLens] PCAP analysis complete ({len(pkts)} packets).")

                # Keep dashboard alive after PCAP is done
                self._demo_mode()

            else:
                # ── Live capture mode ─────────────────────────────────────
                iface = interface or self._default_interface()

                if iface is None:
                    print("[ThreatLens] No usable network interface found. Running in demo mode.")
                    self._demo_mode()
                    return

                print(f"[ThreatLens] Live capture on interface: {iface}")

                sniff(
                    iface       = iface,
                    prn         = lambda p: self.process_raw(bytes(p), float(p.time)),
                    store       = False,
                    stop_filter = lambda _: not self._running,
                )

        except ImportError:
            print("[ThreatLens] Scapy not installed. Running in demo mode.")
            self._demo_mode()

        except PermissionError:
            print("[ThreatLens] Permission denied for live capture.")
            print("[ThreatLens] On Windows: run PowerShell/CMD as Administrator.")
            print("[ThreatLens] On Linux/Mac: use  sudo python run.py --interface <iface>")
            print("[ThreatLens] Falling back to demo mode.")
            self._demo_mode()

        except Exception as e:
            err = str(e)

            if "not found" in err.lower() or "interface" in err.lower():
                print(f"[ThreatLens] Interface error: {e}")
                print("[ThreatLens] Tip — list available interfaces with:")
                print("             python -c \"from scapy.interfaces import get_if_list; print(get_if_list())\"")
                print("[ThreatLens] Falling back to demo mode.")
            else:
                print(f"[ThreatLens] Capture error: {e}")
                print("[ThreatLens] Falling back to demo mode.")

            self._demo_mode()


    def _demo_mode(self):
        """Generate synthetic traffic for demo/testing."""
        import random
        import struct

        apps = ["youtube.com", "facebook.com", "google.com", "github.com",
                "doubleclick.net", "amazon.com", "netflix.com"]
        ips  = [f"192.168.1.{i}" for i in range(2, 20)]

        while self._running:
            src_ip  = random.choice(ips)
            dst_ip  = f"142.250.{random.randint(1,254)}.{random.randint(1,254)}"
            sni     = random.choice(apps)
            length  = random.randint(64, 1500)
            ts      = datetime.utcnow()

            # Build fake TLS Client Hello SNI packet
            sni_bytes    = sni.encode()
            sni_len      = len(sni_bytes)
            ext_data     = struct.pack("!HBH", sni_len + 3, 0, sni_len) + sni_bytes
            ext          = struct.pack("!HH", 0, len(ext_data)) + ext_data
            exts         = struct.pack("!H", len(ext)) + ext
            hello_body   = b"\x03\x03" + b"\x00" * 32  # version + random
            hello_body  += b"\x00"                       # session id len
            hello_body  += b"\x00\x02\xc0\x2c"          # cipher suites
            hello_body  += b"\x01\x00"                   # compression
            hello_body  += exts
            hs           = b"\x01" + b"\x00" + struct.pack("!H", len(hello_body)) + hello_body
            tls_record   = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

            # Wrap in fake Ethernet+IP+TCP header (simplified, parse_packet handles gracefully)
            # For demo mode, directly inject a summary
            from .models import ParsedPacket, AppType
            from .sni_extractor import extract_sni
            from .packet_parser import sni_to_app_type

            extracted = extract_sni(tls_record)
            pkt = ParsedPacket(timestamp=ts)
            pkt.src_ip   = src_ip
            pkt.dst_ip   = dst_ip
            pkt.src_port = random.randint(1024, 65535)
            pkt.dst_port = 443
            pkt.protocol = "TCP"
            pkt.length   = length
            pkt.sni      = extracted or sni
            pkt.is_tls   = True
            pkt.app_type = sni_to_app_type(pkt.sni)

            # Check rules
            blocked = self.rule_manager.should_block(pkt.src_ip, pkt.dst_ip, pkt.sni or "", pkt.app_type)

            self.total_packets += 1
            self.total_bytes   += length
            if blocked:
                self.blocked_count += 1

            sec_bucket = int(time.time())
            self._pps_window[sec_bucket] += 1
            self._bps_window[sec_bucket] += length

            # Track flow for ML and stats
            flow = self.flow_tracker.update(pkt)

            self._detect_adware(pkt)

            # ML classification on completed flows
            for completed in self.flow_tracker.get_completed_flows():
                self._classify_flow(completed)
                self._fire_flow(completed)

            summary = {
                "ts":        ts.isoformat(),
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  pkt.src_port,
                "dst_port":  443,
                "protocol":  "TCP",
                "length":    length,
                "app_type":  pkt.app_type.value,
                "sni":       pkt.sni or "",
                "blocked":   blocked,
            }
            self._recent_packets.append(summary)
            self._fire_packet(summary)

            time.sleep(random.uniform(0.05, 0.3))

    @staticmethod
    def _default_interface() -> Optional[str]:
        """
        Auto-detect the best available network interface.
        Works on Windows (Npcap), Linux, and macOS.
        Returns None if no usable interface is found (triggers demo mode).
        """
        try:
            from scapy.interfaces import get_if_list, get_working_ifaces
            import sys

            # ── Windows ───────────────────────────────────────────────────
            if sys.platform == "win32":
                # Prefer get_working_ifaces() which returns rich interface objects
                try:
                    working = get_working_ifaces()
                    if working:
                        # Pick the first one that looks like a real NIC
                        # (skip loopback and virtual adapters)
                        skip_kw = ("loopback", "lo", "npcap loopback", "virtual",
                                   "vmware", "virtualbox", "hyper-v", "bluetooth")
                        for iface in working:
                            name = (getattr(iface, "name", "") or "").lower()
                            desc = (getattr(iface, "description", "") or "").lower()
                            if not any(kw in name or kw in desc for kw in skip_kw):
                                return iface
                        # All skipped — just return first working one
                        return working[0]
                except Exception:
                    pass

                # Fallback: use raw interface name list
                ifaces = get_if_list()
                for iface in ifaces:
                    if "loopback" not in iface.lower():
                        return iface
                return ifaces[0] if ifaces else None

            # ── Linux ─────────────────────────────────────────────────────
            elif sys.platform.startswith("linux"):
                candidates = ["eth0", "ens3", "ens33", "enp0s3",
                              "enp3s0", "wlan0", "wlp2s0"]
                ifaces = get_if_list()
                for c in candidates:
                    if c in ifaces:
                        return c
                # Return first non-loopback
                for iface in ifaces:
                    if iface != "lo":
                        return iface
                return None

            # ── macOS ─────────────────────────────────────────────────────
            else:
                candidates = ["en0", "en1", "en2", "eth0"]
                ifaces = get_if_list()
                for c in candidates:
                    if c in ifaces:
                        return c
                for iface in ifaces:
                    if iface not in ("lo0", "lo"):
                        return iface
                return None

        except Exception:
            return None
