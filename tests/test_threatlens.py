"""
ThreatLens – Test Suite
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import struct
import pytest
from datetime import datetime


# ═══════════════════════════════════════════════════
#  SNI Extractor Tests
# ═══════════════════════════════════════════════════

def build_tls_client_hello(sni: str) -> bytes:
    """Helper: build a minimal TLS ClientHello with an SNI extension."""
    sni_bytes    = sni.encode()
    sni_len      = len(sni_bytes)
    ext_data     = struct.pack("!HBH", sni_len + 3, 0, sni_len) + sni_bytes
    ext          = struct.pack("!HH", 0, len(ext_data)) + ext_data
    exts         = struct.pack("!H", len(ext)) + ext

    hello_body   = b"\x03\x03"           # client version TLS 1.2
    hello_body  += b"\x00" * 32          # random
    hello_body  += b"\x00"               # session id length = 0
    hello_body  += b"\x00\x02\xc0\x2c"  # cipher suites length + one suite
    hello_body  += b"\x01\x00"           # compression
    hello_body  += exts

    hs_len       = len(hello_body)
    handshake    = b"\x01" + struct.pack("!I", hs_len)[1:] + hello_body
    record_len   = len(handshake)
    return b"\x16\x03\x01" + struct.pack("!H", record_len) + handshake


def test_sni_extraction_youtube():
    from threatlens.engine.sni_extractor import extract_sni
    payload = build_tls_client_hello("www.youtube.com")
    result  = extract_sni(payload)
    assert result == "www.youtube.com"


def test_sni_extraction_facebook():
    from threatlens.engine.sni_extractor import extract_sni
    payload = build_tls_client_hello("static.xx.fbcdn.net")
    result  = extract_sni(payload)
    assert result == "static.xx.fbcdn.net"


def test_sni_extraction_empty():
    from threatlens.engine.sni_extractor import extract_sni
    assert extract_sni(b"")   is None
    assert extract_sni(b"\x00" * 10) is None


def test_http_host_extraction():
    from threatlens.engine.sni_extractor import extract_http_host
    payload = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n"
    result  = extract_http_host(payload)
    assert result == "www.example.com"


def test_http_host_with_port():
    from threatlens.engine.sni_extractor import extract_http_host
    payload = b"GET / HTTP/1.1\r\nHost: api.service.io:8080\r\n\r\n"
    result  = extract_http_host(payload)
    assert result == "api.service.io"


# ═══════════════════════════════════════════════════
#  App Type Mapping Tests
# ═══════════════════════════════════════════════════

def test_app_type_youtube():
    from threatlens.engine.packet_parser import sni_to_app_type
    from threatlens.engine.models import AppType
    assert sni_to_app_type("r1---sn-vgqsknle.googlevideo.com") == AppType.YOUTUBE
    assert sni_to_app_type("www.youtube.com")                   == AppType.YOUTUBE


def test_app_type_adware():
    from threatlens.engine.packet_parser import sni_to_app_type
    from threatlens.engine.models import AppType
    assert sni_to_app_type("doubleclick.net")            == AppType.ADWARE
    assert sni_to_app_type("ads.adnxs.com")              == AppType.ADWARE


def test_app_type_unknown():
    from threatlens.engine.packet_parser import sni_to_app_type
    from threatlens.engine.models import AppType
    assert sni_to_app_type("some.random.domain.xyz") == AppType.HTTPS


# ═══════════════════════════════════════════════════
#  Flow Tracker Tests
# ═══════════════════════════════════════════════════

def make_pkt(src="10.0.0.1", dst="8.8.8.8", sport=12345, dport=443, proto="TCP", length=500):
    from threatlens.engine.models import ParsedPacket, AppType
    pkt           = ParsedPacket(timestamp=datetime.utcnow())
    pkt.src_ip    = src
    pkt.dst_ip    = dst
    pkt.src_port  = sport
    pkt.dst_port  = dport
    pkt.protocol  = proto
    pkt.length    = length
    pkt.app_type  = AppType.HTTPS
    return pkt


def test_flow_created_on_first_packet():
    from threatlens.engine.flow_tracker import FlowTracker
    tracker = FlowTracker()
    pkt     = make_pkt()
    flow    = tracker.update(pkt)
    assert flow is not None
    assert flow.pkt_count  == 1
    assert flow.byte_count == 500


def test_flow_accumulates_packets():
    from threatlens.engine.flow_tracker import FlowTracker
    tracker = FlowTracker()
    for _ in range(5):
        tracker.update(make_pkt())
    flows = tracker.get_active_flows()
    assert len(flows) == 1
    assert flows[0].pkt_count == 5


def test_separate_flows_different_tuples():
    from threatlens.engine.flow_tracker import FlowTracker
    tracker = FlowTracker()
    tracker.update(make_pkt(src="10.0.0.1", dport=443))
    tracker.update(make_pkt(src="10.0.0.2", dport=443))
    assert len(tracker.get_active_flows()) == 2


# ═══════════════════════════════════════════════════
#  Rule Manager Tests
# ═══════════════════════════════════════════════════

def test_rule_manager_add_and_block_domain():
    from threatlens.engine.rule_manager import RuleManager
    rm = RuleManager()
    rm._rules.clear()  # start fresh
    rm.add_rule("DOMAIN", "evilsite.com")
    assert rm.is_blocked_domain("api.evilsite.com") is True
    assert rm.is_blocked_domain("google.com")        is False


def test_rule_manager_block_ip():
    from threatlens.engine.rule_manager import RuleManager
    rm = RuleManager()
    rm._rules.clear()
    rm.add_rule("IP", "192.168.1.99")
    assert rm.is_blocked_ip("192.168.1.99") is True
    assert rm.is_blocked_ip("192.168.1.1")  is False


def test_rule_manager_remove():
    from threatlens.engine.rule_manager import RuleManager
    rm    = RuleManager()
    rm._rules.clear()
    rule  = rm.add_rule("DOMAIN", "tracker.io")
    assert rm.is_blocked_domain("tracker.io") is True
    rm.remove_rule(rule.id)
    assert rm.is_blocked_domain("tracker.io") is False


def test_rule_manager_toggle():
    from threatlens.engine.rule_manager import RuleManager
    rm   = RuleManager()
    rm._rules.clear()
    rule = rm.add_rule("DOMAIN", "ads.example.com")
    assert rm.is_blocked_domain("ads.example.com") is True
    rm.toggle_rule(rule.id)  # disable
    assert rm.is_blocked_domain("ads.example.com") is False


# ═══════════════════════════════════════════════════
#  ML Classifier Tests (heuristic mode)
# ═══════════════════════════════════════════════════

def make_flow(pkt_count=10, byte_count=5000, dst_port=443, proto="TCP",
              duration=5.0, ia=100.0, ia_std=20.0):
    from threatlens.engine.models import Flow, FiveTuple, AppType
    f = Flow(five_tuple=FiveTuple("10.0.0.1","8.8.8.8",12345,dst_port,proto))
    f.pkt_count   = pkt_count
    f.byte_count  = byte_count
    f.pkt_sizes   = [byte_count // max(pkt_count, 1)] * pkt_count
    f.inter_arrivals = [ia] * max(pkt_count - 1, 1)
    from datetime import timedelta
    f.end_time    = datetime.utcnow()
    f.start_time  = f.end_time - timedelta(seconds=duration)
    f.last_ts     = f.end_time
    return f


def test_classify_normal():
    from threatlens.ml.classifier import MLClassifier
    from threatlens.engine.models import ThreatLabel
    clf   = MLClassifier()
    label, conf = clf.classify(make_flow())
    assert label == ThreatLabel.NORMAL
    assert conf  > 0.5


def test_classify_tor():
    from threatlens.ml.classifier import MLClassifier
    from threatlens.engine.models import ThreatLabel
    clf   = MLClassifier()
    label, conf = clf.classify(make_flow(dst_port=9001))
    assert label == ThreatLabel.TOR_TRAFFIC
    assert conf  >= 0.8


def test_classify_dos():
    from threatlens.ml.classifier import MLClassifier
    from threatlens.engine.models import ThreatLabel
    clf   = MLClassifier()
    # bps = 10MB/s → DOS
    label, conf = clf.classify(make_flow(pkt_count=1000, byte_count=10_000_000, duration=1.0))
    assert label == ThreatLabel.DOS_ATTACK


# ═══════════════════════════════════════════════════
#  ParsedPacket Model Tests
# ═══════════════════════════════════════════════════

def test_parsed_packet_has_blocked_field():
    """ParsedPacket must have a proper `blocked` field (not monkey-patched)."""
    from threatlens.engine.models import ParsedPacket
    pkt = ParsedPacket(timestamp=datetime.utcnow())
    assert pkt.blocked is False
    pkt.blocked = True
    assert pkt.blocked is True


# ═══════════════════════════════════════════════════
#  FlowTracker Edge Case Tests
# ═══════════════════════════════════════════════════

def test_flow_tracker_returns_none_for_empty_src():
    """FlowTracker.update() should return None when src_ip is empty."""
    from threatlens.engine.flow_tracker import FlowTracker
    from threatlens.engine.models import ParsedPacket
    tracker = FlowTracker()
    pkt = ParsedPacket(timestamp=datetime.utcnow())
    pkt.src_ip = ""
    pkt.protocol = "TCP"
    result = tracker.update(pkt)
    assert result is None


def test_flow_tracker_returns_none_for_empty_protocol():
    from threatlens.engine.flow_tracker import FlowTracker
    from threatlens.engine.models import ParsedPacket
    tracker = FlowTracker()
    pkt = ParsedPacket(timestamp=datetime.utcnow())
    pkt.src_ip = "10.0.0.1"
    pkt.protocol = ""
    result = tracker.update(pkt)
    assert result is None


# ═══════════════════════════════════════════════════
#  DPIEngine Integration Tests
# ═══════════════════════════════════════════════════

def test_engine_stats_structure():
    """get_stats() should return a dict with all expected keys."""
    from threatlens.engine.rule_manager import RuleManager
    from threatlens.engine.dpi_engine import DPIEngine
    engine = DPIEngine(rule_manager=RuleManager())
    stats  = engine.get_stats()
    expected_keys = [
        "total_packets", "total_bytes", "blocked_count", "active_flows",
        "alerts_count", "packets_per_sec", "bytes_per_sec", "uptime_sec",
        "app_breakdown", "proto_breakdown", "security_score",
        "pps_history", "bps_history",
    ]
    for key in expected_keys:
        assert key in stats, f"Missing key: {key}"


def test_security_score_range():
    """Security score must always be between 0 and 100."""
    from threatlens.engine.rule_manager import RuleManager
    from threatlens.engine.dpi_engine import DPIEngine
    engine = DPIEngine(rule_manager=RuleManager())
    score  = engine.get_security_score()
    assert 0 <= score <= 100


def test_engine_rule_blocking():
    """DPIEngine should block packets matching a domain rule."""
    from threatlens.engine.rule_manager import RuleManager
    from threatlens.engine.dpi_engine import DPIEngine
    from threatlens.engine.models import ParsedPacket, AppType
    rm     = RuleManager()
    rm._rules.clear()
    rm.add_rule("DOMAIN", "evil.com")
    engine = DPIEngine(rule_manager=rm)

    pkt = ParsedPacket(timestamp=datetime.utcnow())
    pkt.src_ip   = "10.0.0.1"
    pkt.dst_ip   = "1.2.3.4"
    pkt.src_port = 12345
    pkt.dst_port = 443
    pkt.protocol = "TCP"
    pkt.length   = 200
    pkt.sni      = "api.evil.com"
    pkt.app_type = AppType.HTTPS

    # Simulate what process_raw does for blocking
    blocked = rm.should_block(pkt.src_ip, pkt.dst_ip, pkt.sni, pkt.app_type)
    assert blocked is True

