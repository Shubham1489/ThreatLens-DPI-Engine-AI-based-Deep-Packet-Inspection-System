"""
ThreatLens – ML Traffic Classifier
Feature extraction and Random Forest / XGBoost threat classification.
Falls back to rule-based heuristics when scikit-learn is not available.
"""

import os
import pickle
import statistics
from typing import Tuple, Optional

from ..engine.models import Flow, ThreatLabel


# Feature names (must match training order)
FEATURE_NAMES = [
    "avg_pkt_size",
    "pkt_count",
    "flow_duration_sec",
    "bytes_per_sec",
    "dst_port",
    "protocol_tcp",
    "protocol_udp",
    "has_sni",
    "inter_arrival_mean",
    "inter_arrival_std",
    "pkt_size_std",
]

MODEL_PATH  = os.path.join(os.path.dirname(__file__), "models", "rf_model.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "models", "scaler.pkl")


def extract_features(flow: Flow) -> list:
    """Convert a Flow into a feature vector for ML inference."""
    duration = 0.0
    if flow.start_time and flow.end_time:
        duration = max((flow.end_time - flow.start_time).total_seconds(), 0.001)
    elif flow.start_time and flow.last_ts:
        duration = max((flow.last_ts - flow.start_time).total_seconds(), 0.001)
    else:
        duration = 0.001

    pkt_sizes = flow.pkt_sizes or [flow.byte_count]
    arrivals  = flow.inter_arrivals or [0]

    avg_pkt    = statistics.mean(pkt_sizes) if pkt_sizes else 0
    pkt_std    = statistics.stdev(pkt_sizes) if len(pkt_sizes) > 1 else 0
    ia_mean    = statistics.mean(arrivals)  if arrivals  else 0
    ia_std     = statistics.stdev(arrivals) if len(arrivals) > 1 else 0
    bps        = flow.byte_count / duration if duration > 0 else 0

    proto = flow.five_tuple.protocol.upper()
    return [
        avg_pkt,
        min(flow.pkt_count, 1000),
        duration,
        bps,
        flow.five_tuple.dst_port,
        1 if proto == "TCP" else 0,
        1 if proto == "UDP" else 0,
        1 if flow.sni else 0,
        ia_mean,
        ia_std,
        pkt_std,
    ]


class MLClassifier:
    """
    Wraps a trained scikit-learn RandomForest model.
    Falls back to heuristic rules when model file not found.
    """

    def __init__(self):
        self._model  = None
        self._scaler = None
        self._load()

    def _load(self):
        try:
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, "rb") as f:
                    self._model = pickle.load(f)
            if os.path.exists(SCALER_PATH):
                with open(SCALER_PATH, "rb") as f:
                    self._scaler = pickle.load(f)
        except Exception as e:
            print(f"[ML] Could not load model: {e}. Using heuristics.")

    def classify(self, flow: Flow) -> Tuple[ThreatLabel, float]:
        """Return (label, confidence). Confidence 0.0–1.0."""
        features = extract_features(flow)

        if self._model is not None:
            try:
                import numpy as np
                X = np.array(features).reshape(1, -1)
                if self._scaler:
                    X = self._scaler.transform(X)
                proba = self._model.predict_proba(X)[0]
                idx   = int(proba.argmax())
                label_str = self._model.classes_[idx]
                return ThreatLabel(label_str), float(proba[idx])
            except Exception as e:
                pass  # Fall through to heuristics

        # ── Heuristic fallback ───────────────────────────────────────────────
        return self._heuristic(flow, features)

    def _heuristic(self, flow: Flow, features: list) -> Tuple[ThreatLabel, float]:
        avg_pkt, pkt_count, duration, bps, dst_port = features[:5]
        ia_mean = features[8]

        # DoS: very high packet rate
        if bps > 5_000_000:
            return ThreatLabel.DOS_ATTACK, 0.85

        # Port scan: many small packets, very short inter-arrival
        if pkt_count > 50 and avg_pkt < 80 and ia_mean < 5:
            return ThreatLabel.PORT_SCAN, 0.80

        # Malware C2: regular beaconing pattern (low variance inter-arrival)
        if (flow.inter_arrivals and len(flow.inter_arrivals) > 10 and
                statistics.stdev(flow.inter_arrivals) < 50 and
                10 < ia_mean < 60000):
            return ThreatLabel.MALWARE_C2, 0.70

        # TOR: port 9001/9030
        if dst_port in (9001, 9030, 9050):
            return ThreatLabel.TOR_TRAFFIC, 0.90

        # P2P: high ports + large transfers
        if dst_port > 40000 and bps > 100_000:
            return ThreatLabel.P2P_TRAFFIC, 0.65

        # Adware: short flows to ad networks (already caught by rule manager, but reinforce)
        from ..engine.models import AppType
        if flow.app_type == AppType.ADWARE:
            return ThreatLabel.ADWARE, 0.88

        return ThreatLabel.NORMAL, 0.95

    def is_available(self) -> bool:
        return self._model is not None
