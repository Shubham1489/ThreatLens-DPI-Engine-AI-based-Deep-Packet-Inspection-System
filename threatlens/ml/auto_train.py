"""
ThreatLens – Auto-Training System
===================================
Continuously improves the ML model by:

1.  ONLINE LEARNING  – Every confirmed threat or blocked packet is added to a
                       rolling buffer. When the buffer hits a threshold, the
                       model is retrained with the new examples merged in.

2.  SCHEDULED RETRAINING – A background scheduler retrains fully every N hours
                            using all accumulated data (base dataset + live buffer).

3.  FEEDBACK LOOP    – Analyst confirmations ("yes this is a threat") and
                        false-positive reports are stored and used in the next
                        training round with higher sample weight.

4.  ADWARE LEARNING  – Adware/tracker domain patterns seen in live traffic are
                        extracted and added as training examples automatically.

5.  MODEL VERSIONING – Every trained model is saved with a timestamp. The best
                       model (highest validation F1) is promoted to production.
"""

import os
import sys
import csv
import time
import pickle
import random
import logging
import threading
import statistics
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque, defaultdict
from typing import Optional, Dict, List, Tuple

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT   = Path(__file__).resolve().parent.parent
DATA_DIR       = PROJECT_ROOT / "data"
PROCESSED_DIR  = DATA_DIR / "processed"
MODEL_DIR      = PROJECT_ROOT / "ml" / "models"
FEEDBACK_CSV   = DATA_DIR / "feedback.csv"
LIVE_BUFFER_CSV= DATA_DIR / "live_buffer.csv"
COMBINED_CSV   = PROCESSED_DIR / "threatlens_dataset.csv"
MODEL_PATH     = MODEL_DIR / "rf_model.pkl"
SCALER_PATH    = MODEL_DIR / "scaler.pkl"
HISTORY_DIR    = MODEL_DIR / "history"

for d in [MODEL_DIR, HISTORY_DIR, PROCESSED_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Settings ──────────────────────────────────────────────────────────────────
ONLINE_BUFFER_SIZE     = 500      # trigger retraining after N new live examples
RETRAIN_INTERVAL_HOURS = 4        # scheduled full retrain every N hours
MIN_SAMPLES_TO_TRAIN   = 200      # need at least this many rows to train
MAX_LIVE_BUFFER_ROWS   = 100_000  # cap on live_buffer.csv size

FEATURE_COLS = [
    "avg_pkt_size", "pkt_count", "flow_duration_sec", "bytes_per_sec",
    "dst_port", "protocol_tcp", "protocol_udp", "has_sni",
    "inter_arrival_mean", "inter_arrival_std", "pkt_size_std",
]
LABEL_COL = "label"
ALL_COLS  = FEATURE_COLS + [LABEL_COL]

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [AutoTrain] %(levelname)s %(message)s",
    datefmt = "%H:%M:%S",
)
log = logging.getLogger("AutoTrain")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  FEATURE EXTRACTION  (from a live Flow object)                         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def flow_to_feature_row(flow, label: str) -> Optional[dict]:
    """
    Convert a ThreatLens Flow object into a CSV row for the training buffer.
    Returns None if the flow doesn't have enough data to be useful.
    """
    try:
        if flow.pkt_count < 2:
            return None

        duration = 0.001
        if flow.start_time and flow.last_ts:
            duration = max((flow.last_ts - flow.start_time).total_seconds(), 0.001)

        pkt_sizes = flow.pkt_sizes or [flow.byte_count]
        arrivals  = flow.inter_arrivals or [0]

        avg_pkt  = statistics.mean(pkt_sizes)
        pkt_std  = statistics.stdev(pkt_sizes) if len(pkt_sizes) > 1 else 0.0
        ia_mean  = statistics.mean(arrivals)
        ia_std   = statistics.stdev(arrivals)  if len(arrivals)  > 1 else 0.0
        bps      = flow.byte_count / duration

        return {
            "avg_pkt_size":       round(avg_pkt, 2),
            "pkt_count":          min(flow.pkt_count, 1000),
            "flow_duration_sec":  round(duration, 4),
            "bytes_per_sec":      round(bps, 2),
            "dst_port":           flow.five_tuple.dst_port,
            "protocol_tcp":       1 if flow.five_tuple.protocol == "TCP" else 0,
            "protocol_udp":       1 if flow.five_tuple.protocol == "UDP" else 0,
            "has_sni":            1 if flow.sni else 0,
            "inter_arrival_mean": round(ia_mean, 2),
            "inter_arrival_std":  round(ia_std,  2),
            "pkt_size_std":       round(pkt_std, 2),
            "label":              label,
        }
    except Exception:
        return None


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  LIVE BUFFER  (append new examples to disk, avoid RAM growth)          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class LiveBuffer:
    """Thread-safe append-only CSV buffer for live training examples."""

    def __init__(self, path: Path = LIVE_BUFFER_CSV):
        self._path  = path
        self._lock  = threading.Lock()
        self._count = 0
        self._pending: List[dict] = []

        # Initialise file with header if needed
        if not path.exists():
            with open(path, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=ALL_COLS + ["weight"]).writeheader()
        else:
            # Count existing rows
            with open(path) as f:
                self._count = sum(1 for _ in f) - 1  # minus header

    def add(self, row: dict, weight: float = 1.0) -> int:
        """Add one example. Returns current buffer size."""
        row_with_w = {**row, "weight": weight}
        with self._lock:
            self._pending.append(row_with_w)
            if len(self._pending) >= 50:   # flush every 50 rows
                self._flush()
        return self._count

    def _flush(self):
        """Write pending rows to disk (call with lock held)."""
        if not self._pending:
            return
        with open(self._path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=ALL_COLS + ["weight"])
            writer.writerows(self._pending)
        self._count += len(self._pending)
        self._pending.clear()

    def flush(self):
        with self._lock:
            self._flush()

    def size(self) -> int:
        with self._lock:
            return self._count + len(self._pending)

    def clear(self):
        """Reset the buffer (called after a successful full retrain)."""
        with self._lock:
            with open(self._path, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=ALL_COLS + ["weight"]).writeheader()
            self._count = 0
            self._pending.clear()
        log.info("Live buffer cleared after retraining.")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  FEEDBACK STORE  (analyst confirmations / false-positive reports)      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class FeedbackStore:
    """Stores analyst feedback (confirmed threats, false positives)."""

    FEEDBACK_WEIGHT = 5.0   # confirmed examples get 5× weight in training

    def __init__(self, path: Path = FEEDBACK_CSV):
        self._path = path
        self._lock = threading.Lock()
        if not path.exists():
            with open(path, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=ALL_COLS + ["weight", "source", "ts"]).writeheader()

    def confirm_threat(self, flow, label: str, source: str = "analyst"):
        """Analyst confirmed this flow as a threat — high-weight training example."""
        row = flow_to_feature_row(flow, label)
        if row is None:
            return
        row["weight"] = self.FEEDBACK_WEIGHT
        row["source"] = source
        row["ts"]     = datetime.utcnow().isoformat()
        with self._lock:
            with open(self._path, "a", newline="") as f:
                csv.DictWriter(f, fieldnames=ALL_COLS + ["weight", "source", "ts"]).writerow(row)
        log.info(f"Feedback stored: {label} from {source}")

    def report_false_positive(self, flow, wrong_label: str):
        """Analyst says this flow was NOT a threat — add as NORMAL with high weight."""
        row = flow_to_feature_row(flow, "NORMAL")
        if row is None:
            return
        row["weight"] = self.FEEDBACK_WEIGHT
        row["source"] = f"fp_correction:{wrong_label}"
        row["ts"]     = datetime.utcnow().isoformat()
        with self._lock:
            with open(self._path, "a", newline="") as f:
                csv.DictWriter(f, fieldnames=ALL_COLS + ["weight", "source", "ts"]).writerow(row)
        log.info(f"False positive stored: was {wrong_label}, now NORMAL")

    def load_as_rows(self) -> List[Tuple[dict, float]]:
        """Return list of (feature_dict, weight) tuples."""
        results = []
        try:
            with open(self._path) as f:
                for row in csv.DictReader(f):
                    feat   = {k: float(row[k]) if k != "label" else row[k]
                              for k in ALL_COLS if k in row}
                    weight = float(row.get("weight", 1.0))
                    if len(feat) == len(ALL_COLS):
                        results.append((feat, weight))
        except Exception:
            pass
        return results


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  TRAINER  (the actual sklearn training logic)                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class ModelTrainer:
    """Trains, validates, versions, and promotes RandomForest models."""

    def __init__(self):
        self._training_lock = threading.Lock()

    def train(
        self,
        base_csv:   Optional[Path]   = COMBINED_CSV,
        live_buf:   Optional[LiveBuffer]    = None,
        feedback:   Optional[FeedbackStore] = None,
        n_estimators: int = 200,
        save_if_better: bool = True,
    ) -> Optional[float]:
        """
        Train a new model and optionally promote it if it beats the current one.
        Returns the validation F1 score, or None on failure.
        """
        if not self._training_lock.acquire(blocking=False):
            log.info("Training already in progress, skipping.")
            return None

        try:
            return self._train_inner(base_csv, live_buf, feedback, n_estimators, save_if_better)
        finally:
            self._training_lock.release()

    def _train_inner(self, base_csv, live_buf, feedback, n_estimators, save_if_better) -> Optional[float]:
        import numpy as np
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.preprocessing import StandardScaler
            from sklearn.metrics import f1_score
        except ImportError:
            log.error("scikit-learn not installed. Run: pip install scikit-learn")
            return None

        log.info("Starting model training…")
        t0 = time.time()

        X_list, y_list, w_list = [], [], []

        # ── Load base dataset ──────────────────────────────────────────────
        if base_csv and base_csv.exists():
            with open(base_csv) as f:
                for row in csv.DictReader(f):
                    try:
                        feat = [float(row[c]) for c in FEATURE_COLS]
                        lbl  = row.get(LABEL_COL, "").strip()
                        if lbl and feat:
                            X_list.append(feat)
                            y_list.append(lbl)
                            w_list.append(1.0)
                    except (ValueError, KeyError):
                        pass
            log.info(f"  Base dataset: {len(X_list):,} rows from {base_csv.name}")
        else:
            log.warning("  No base dataset found — training on live data only.")

        # ── Load live buffer ───────────────────────────────────────────────
        if live_buf:
            live_buf.flush()
            if LIVE_BUFFER_CSV.exists():
                added = 0
                with open(LIVE_BUFFER_CSV) as f:
                    for row in csv.DictReader(f):
                        try:
                            feat = [float(row[c]) for c in FEATURE_COLS]
                            lbl  = row.get(LABEL_COL, "").strip()
                            w    = float(row.get("weight", 1.0))
                            if lbl and feat:
                                X_list.append(feat)
                                y_list.append(lbl)
                                w_list.append(w)
                                added += 1
                        except (ValueError, KeyError):
                            pass
                log.info(f"  Live buffer: +{added:,} rows")

        # ── Load feedback ──────────────────────────────────────────────────
        if feedback:
            fb_rows = feedback.load_as_rows()
            for feat_dict, w in fb_rows:
                try:
                    X_list.append([float(feat_dict[c]) for c in FEATURE_COLS])
                    y_list.append(feat_dict[LABEL_COL])
                    w_list.append(w)
                except (KeyError, ValueError):
                    pass
            if fb_rows:
                log.info(f"  Feedback: +{len(fb_rows):,} high-weight rows")

        total = len(X_list)
        if total < MIN_SAMPLES_TO_TRAIN:
            log.warning(f"  Only {total} samples — need {MIN_SAMPLES_TO_TRAIN}. Skipping.")
            return None

        log.info(f"  Total training samples: {total:,}")

        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list)
        w = np.array(w_list, dtype=np.float32)

        # Print label distribution
        unique, counts = np.unique(y, return_counts=True)
        for lbl, cnt in zip(unique, counts):
            log.info(f"    {lbl:<16} {cnt:>7,}  ({100*cnt/total:.1f}%)")

        # ── Scale ──────────────────────────────────────────────────────────
        scaler  = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # ── Split ──────────────────────────────────────────────────────────
        X_tr, X_val, y_tr, y_val, w_tr, _ = train_test_split(
            X_scaled, y, w, test_size=0.2, stratify=y, random_state=42
        )

        # ── Train ──────────────────────────────────────────────────────────
        clf = RandomForestClassifier(
            n_estimators  = n_estimators,
            max_depth     = 25,
            min_samples_leaf = 2,
            class_weight  = "balanced",
            n_jobs        = -1,
            random_state  = 42,
        )
        clf.fit(X_tr, y_tr, sample_weight=w_tr)

        # ── Evaluate ───────────────────────────────────────────────────────
        y_pred = clf.predict(X_val)
        f1     = f1_score(y_val, y_pred, average="weighted", zero_division=0)
        log.info(f"  Validation F1 (weighted): {f1:.4f}")

        elapsed = time.time() - t0
        log.info(f"  Training took {elapsed:.1f}s")

        # ── Compare with existing model ────────────────────────────────────
        if save_if_better:
            current_f1 = self._load_current_f1()
            if f1 > current_f1:
                self._save_model(clf, scaler, f1)
                log.info(f"  ✓ New model promoted (F1 {current_f1:.4f} → {f1:.4f})")
            else:
                log.info(f"  ✗ New model NOT promoted (F1 {f1:.4f} ≤ current {current_f1:.4f})")
                # Archive anyway for reference
                self._archive_model(clf, scaler, f1)
        else:
            self._save_model(clf, scaler, f1)

        return f1

    def _save_model(self, clf, scaler, f1: float):
        """Save model as production model + archive a copy."""
        with open(MODEL_PATH,  "wb") as f: pickle.dump(clf,    f)
        with open(SCALER_PATH, "wb") as f: pickle.dump(scaler, f)

        # Write metadata
        meta_path = MODEL_DIR / "model_meta.txt"
        with open(meta_path, "w") as f:
            f.write(f"trained_at={datetime.utcnow().isoformat()}\n")
            f.write(f"f1_score={f1:.6f}\n")
            f.write(f"n_estimators={clf.n_estimators}\n")
            f.write(f"classes={','.join(clf.classes_)}\n")

        self._archive_model(clf, scaler, f1)
        log.info(f"  Model saved → {MODEL_PATH}")

    def _archive_model(self, clf, scaler, f1: float):
        ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        tag  = f"f1_{f1:.4f}".replace(".", "_")
        stem = HISTORY_DIR / f"model_{ts}_{tag}"
        with open(str(stem) + "_clf.pkl",    "wb") as f: pickle.dump(clf,    f)
        with open(str(stem) + "_scaler.pkl", "wb") as f: pickle.dump(scaler, f)

        # Prune history: keep only latest 10 versions
        pkls = sorted(HISTORY_DIR.glob("*_clf.pkl"))
        for old in pkls[:-10]:
            old.unlink(missing_ok=True)
            scl = Path(str(old).replace("_clf.pkl", "_scaler.pkl"))
            scl.unlink(missing_ok=True)

    def _load_current_f1(self) -> float:
        meta = MODEL_DIR / "model_meta.txt"
        if meta.exists():
            with open(meta) as f:
                for line in f:
                    if line.startswith("f1_score="):
                        try:
                            return float(line.split("=")[1].strip())
                        except ValueError:
                            pass
        return 0.0


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  AUTO-TRAIN ENGINE  (the main orchestrator)                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class AutoTrainEngine:
    """
    Plugs into the DPIEngine via callbacks:

        auto_train = AutoTrainEngine()
        dpi_engine.on_flow(auto_train.on_flow_completed)

    Then in the background it:
      - Adds every completed flow with a non-NORMAL ML label to the live buffer
      - Adds every adware-matched flow as ADWARE training example
      - Triggers online retraining when buffer fills up
      - Runs full scheduled retraining every RETRAIN_INTERVAL_HOURS hours
    """

    def __init__(
        self,
        retrain_interval_hours: float = RETRAIN_INTERVAL_HOURS,
        online_buffer_size:     int   = ONLINE_BUFFER_SIZE,
    ):
        self.live_buffer  = LiveBuffer()
        self.feedback     = FeedbackStore()
        self.trainer      = ModelTrainer()

        self._interval    = retrain_interval_hours * 3600
        self._buf_trigger = online_buffer_size
        self._last_full   = time.time()
        self._online_since_last = 0
        self._lock        = threading.Lock()
        self._running     = False
        self._sched_thread: Optional[threading.Thread] = None

        # Stats for the dashboard
        self.stats = {
            "total_flows_seen":       0,
            "examples_added":         0,
            "online_retrains":        0,
            "scheduled_retrains":     0,
            "last_retrain":           None,
            "last_f1":                None,
            "buffer_size":            0,
        }

        log.info(
            f"AutoTrainEngine ready  |  "
            f"online trigger={online_buffer_size}  |  "
            f"scheduled every {retrain_interval_hours}h"
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self):
        """Start the background scheduler thread."""
        self._running = True
        self._sched_thread = threading.Thread(
            target=self._scheduler_loop, daemon=True, name="AutoTrain-Scheduler"
        )
        self._sched_thread.start()
        log.info("AutoTrainEngine scheduler started.")

    def stop(self):
        self._running = False
        log.info("AutoTrainEngine stopping.")

    # ── Flow callback (called by DPIEngine for every completed flow) ──────

    def on_flow_completed(self, flow):
        """
        Main entry point. Called by DPIEngine.on_flow() for every closed flow.
        Decides if this flow should be added to the training buffer.
        """
        self.stats["total_flows_seen"] += 1

        from threatlens.engine.models import ThreatLabel, AppType

        label = None

        # ML detected a non-normal label with decent confidence
        if (flow.ml_label != ThreatLabel.NORMAL and
                flow.ml_confidence >= 0.65):
            label = flow.ml_label.value

        # Rule-based adware detection
        elif flow.app_type == AppType.ADWARE:
            label = "ADWARE"

        # Rule-blocked flow (treat as a threat for training purposes)
        elif flow.blocked and flow.sni:
            label = self._infer_label_from_blocked(flow)

        if label is None:
            # Even normal flows are useful (balanced training)
            if random.random() < 0.05:   # sample 5% of normal flows
                label = "NORMAL"

        if label:
            row = flow_to_feature_row(flow, label)
            if row:
                # Higher weight for confirmed threats than sampled normals
                weight = 2.0 if label != "NORMAL" else 1.0
                size   = self.live_buffer.add(row, weight)
                self.stats["examples_added"] += 1
                self.stats["buffer_size"]     = size
                self._online_since_last      += 1

                # Trigger online retrain if buffer threshold hit
                if self._online_since_last >= self._buf_trigger:
                    self._trigger_online_retrain()

    def _infer_label_from_blocked(self, flow) -> str:
        """Guess label for a rule-blocked flow (adware/malware heuristic)."""
        from threatlens.engine.models import AppType
        if flow.app_type == AppType.ADWARE:
            return "ADWARE"
        if flow.five_tuple.dst_port in (9001, 9030, 9050):
            return "TOR_TRAFFIC"
        return "MALWARE_C2"

    # ── Analyst feedback API ──────────────────────────────────────────────

    def confirm_threat(self, flow, label: str):
        """Analyst confirmed: this flow is a threat."""
        self.feedback.confirm_threat(flow, label, source="analyst")
        # Also add to live buffer with highest weight
        row = flow_to_feature_row(flow, label)
        if row:
            self.live_buffer.add(row, weight=FeedbackStore.FEEDBACK_WEIGHT)
            log.info(f"Analyst confirmation added: {label}")

    def report_false_positive(self, flow, wrong_label: str):
        """Analyst confirmed: this alert was a false positive."""
        self.feedback.report_false_positive(flow, wrong_label)
        row = flow_to_feature_row(flow, "NORMAL")
        if row:
            self.live_buffer.add(row, weight=FeedbackStore.FEEDBACK_WEIGHT)
            log.info(f"False positive correction added (was {wrong_label})")

    # ── Retraining ────────────────────────────────────────────────────────

    def _trigger_online_retrain(self):
        """Lightweight online retrain (fewer estimators, faster)."""
        self._online_since_last = 0
        log.info(f"Online retrain triggered (buffer={self.live_buffer.size():,} rows)")
        threading.Thread(
            target=self._run_retrain,
            kwargs={"n_estimators": 100, "kind": "online"},
            daemon=True,
        ).start()

    def _trigger_scheduled_retrain(self):
        """Full scheduled retrain (more estimators, thorough)."""
        log.info("Scheduled full retrain triggered")
        threading.Thread(
            target=self._run_retrain,
            kwargs={"n_estimators": 200, "kind": "scheduled"},
            daemon=True,
        ).start()

    def _run_retrain(self, n_estimators: int = 200, kind: str = "scheduled"):
        f1 = self.trainer.train(
            base_csv      = COMBINED_CSV if COMBINED_CSV.exists() else None,
            live_buf      = self.live_buffer,
            feedback      = self.feedback,
            n_estimators  = n_estimators,
            save_if_better= True,
        )
        if f1 is not None:
            self.stats["last_retrain"] = datetime.utcnow().isoformat()
            self.stats["last_f1"]      = round(f1, 4)
            if kind == "online":
                self.stats["online_retrains"] += 1
            else:
                self.stats["scheduled_retrains"] += 1

            # After a successful retrain, reload the model in the live classifier
            self._reload_live_classifier()

    def _reload_live_classifier(self):
        """Hot-reload the classifier in the running DPIEngine (if accessible)."""
        try:
            from threatlens.ml.classifier import MLClassifier
            # The global classifier used by the engine
            import threatlens.api.main as api_main
            if hasattr(api_main, "classifier"):
                api_main.classifier._load()
                log.info("Live classifier reloaded from new model.")
        except Exception as e:
            log.warning(f"Could not hot-reload classifier: {e}")

    # ── Scheduler loop ────────────────────────────────────────────────────

    def _scheduler_loop(self):
        while self._running:
            time.sleep(60)  # check every minute
            now = time.time()
            if now - self._last_full >= self._interval:
                self._last_full = now
                self._trigger_scheduled_retrain()

    # ── Stats API ─────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        self.stats["buffer_size"] = self.live_buffer.size()
        return dict(self.stats)

    def force_retrain(self):
        """Manually trigger a full retrain (e.g. from the dashboard)."""
        log.info("Manual retrain triggered.")
        threading.Thread(
            target=self._run_retrain,
            kwargs={"n_estimators": 200, "kind": "scheduled"},
            daemon=True,
        ).start()
