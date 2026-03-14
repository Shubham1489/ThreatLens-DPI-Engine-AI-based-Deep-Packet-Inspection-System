"""
ThreatLens – Flow Tracker
Maintains per-connection state using 5-tuple keys.
Detects flow completion on TCP FIN/RST or idle timeout.
"""

import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .models import Flow, FiveTuple, ParsedPacket, AppType, ThreatLabel

IDLE_TIMEOUT_SEC = 60  # Close idle flows after 60 seconds


class FlowTracker:
    def __init__(self):
        self._flows: Dict[FiveTuple, Flow] = {}
        self._completed: List[Flow] = []
        self._lock = threading.Lock()

    def update(self, pkt: ParsedPacket) -> Optional[Flow]:
        """Update or create a flow for the given packet. Returns the flow, or None if packet is invalid."""
        if not pkt.src_ip or not pkt.protocol:
            return None

        key = FiveTuple(
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol,
        )
        # Normalise direction: use lower IP as src to merge bidirectional flows
        rev_key = key.reverse()

        with self._lock:
            # Check forward or reverse direction
            if key in self._flows:
                flow = self._flows[key]
            elif rev_key in self._flows:
                flow = self._flows[rev_key]
                key  = rev_key
            else:
                flow = Flow(five_tuple=key, start_time=pkt.timestamp)
                self._flows[key] = flow

            # Update flow stats
            flow.pkt_count  += 1
            flow.byte_count += pkt.length

            if pkt.sni and not flow.sni:
                flow.sni      = pkt.sni
                flow.app_type = pkt.app_type

            if pkt.http_host and not flow.http_host:
                flow.http_host = pkt.http_host
                if flow.app_type == AppType.UNKNOWN:
                    flow.app_type = pkt.app_type

            # Track inter-arrival times
            if flow.last_ts:
                delta = (pkt.timestamp - flow.last_ts).total_seconds() * 1000
                flow.inter_arrivals.append(delta)
            flow.last_ts = pkt.timestamp

            # Track packet sizes (cap at 500 for memory)
            if len(flow.pkt_sizes) < 500:
                flow.pkt_sizes.append(pkt.length)

            # Detect flow end on TCP FIN or RST
            if pkt.protocol == "TCP" and pkt.tcp_flags:
                flags = str(pkt.tcp_flags)
                if "F" in flags or "R" in flags:
                    flow.end_time = pkt.timestamp
                    self._completed.append(flow)
                    del self._flows[key]

        return flow

    def expire_idle_flows(self) -> List[Flow]:
        """Move flows idle for > IDLE_TIMEOUT_SEC to completed list."""
        cutoff = datetime.utcnow() - timedelta(seconds=IDLE_TIMEOUT_SEC)
        expired = []
        with self._lock:
            for key in list(self._flows.keys()):
                flow = self._flows[key]
                if flow.last_ts and flow.last_ts < cutoff:
                    flow.end_time = datetime.utcnow()
                    self._completed.append(flow)
                    expired.append(flow)
                    del self._flows[key]
        return expired

    def get_active_flows(self) -> List[Flow]:
        with self._lock:
            return list(self._flows.values())

    def get_completed_flows(self) -> List[Flow]:
        with self._lock:
            result = list(self._completed)
            self._completed.clear()
            return result

    def clear(self):
        with self._lock:
            self._flows.clear()
            self._completed.clear()
