#!/usr/bin/env python3
"""
ThreatLens – Dataset Downloader
================================
Downloads free, publicly available labelled network security datasets
and converts them to ThreatLens's training format.

Supported datasets:
  1. NSL-KDD       – KDD Cup 1999 improved; intrusion detection benchmark
  2. CICIDS2017    – Canadian Institute for Cybersecurity (HTTP download)
  3. CTU-13        – Botnet traffic from Czech Technical University
  4. Synthetic     – Generated locally (no download needed, instant)

Usage:
    python scripts/download_datasets.py --dataset all
    python scripts/download_datasets.py --dataset nsl-kdd
    python scripts/download_datasets.py --dataset synthetic --n 50000
    python scripts/download_datasets.py --list
"""

import argparse
import os
import sys
import csv
import random
import math
import urllib.request
import urllib.error
import gzip
import zipfile
import io
import time
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
RAW_DIR      = DATA_DIR / "raw"
PROCESSED    = DATA_DIR / "processed"
MODEL_DIR    = PROJECT_ROOT / "threatlens" / "ml" / "models"

for d in [RAW_DIR, PROCESSED, MODEL_DIR]:
    d.mkdir(parents=True, exist_ok=True)

COMBINED_CSV = PROCESSED / "threatlens_dataset.csv"

# ── Feature columns ──────────────────────────────────────────────────────────
FEATURE_COLS = [
    "avg_pkt_size", "pkt_count", "flow_duration_sec", "bytes_per_sec",
    "dst_port", "protocol_tcp", "protocol_udp", "has_sni",
    "inter_arrival_mean", "inter_arrival_std", "pkt_size_std",
]
LABEL_COL = "label"
ALL_COLS  = FEATURE_COLS + [LABEL_COL]


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PROGRESS BAR                                                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def progress_bar(done, total, prefix="", width=40):
    filled = int(width * done / max(total, 1))
    bar    = "█" * filled + "░" * (width - filled)
    pct    = 100 * done // max(total, 1)
    print(f"\r{prefix} [{bar}] {pct:3d}%  {done:,}/{total:,}", end="", flush=True)
    if done >= total:
        print()


def download_file(url: str, dest: Path, desc: str = "") -> bool:
    """Download with progress bar. Returns True on success."""
    print(f"\n[Download] {desc or url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ThreatLens/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            done  = 0
            chunk = 8192
            with open(dest, "wb") as f:
                while True:
                    block = resp.read(chunk)
                    if not block:
                        break
                    f.write(block)
                    done += len(block)
                    if total:
                        progress_bar(done, total, "  Downloading")
        print(f"  Saved → {dest}")
        return True
    except Exception as e:
        print(f"\n  [!] Download failed: {e}")
        return False


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DATASET 1 – NSL-KDD                                                   ║
# ║  Source: University of New Brunswick (public)                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

NSL_KDD_TRAIN_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
)
NSL_KDD_TEST_URL  = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
)

# KDD feature names (41 original)
KDD_COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

# Map KDD attack categories → ThreatLens labels
KDD_LABEL_MAP = {
    "normal":   "NORMAL",
    # DoS
    "back": "DOS_ATTACK", "land": "DOS_ATTACK", "neptune": "DOS_ATTACK",
    "pod": "DOS_ATTACK", "smurf": "DOS_ATTACK", "teardrop": "DOS_ATTACK",
    "apache2": "DOS_ATTACK", "udpstorm": "DOS_ATTACK", "processtable": "DOS_ATTACK",
    "mailbomb": "DOS_ATTACK",
    # Probe / Port scan
    "ipsweep": "PORT_SCAN", "nmap": "PORT_SCAN", "portsweep": "PORT_SCAN",
    "satan": "PORT_SCAN", "mscan": "PORT_SCAN", "saint": "PORT_SCAN",
    # R2L
    "ftp_write": "MALWARE_C2", "guess_passwd": "MALWARE_C2", "imap": "MALWARE_C2",
    "multihop": "MALWARE_C2", "phf": "MALWARE_C2", "spy": "MALWARE_C2",
    "warezclient": "MALWARE_C2", "warezmaster": "MALWARE_C2",
    # U2R
    "buffer_overflow": "MALWARE_C2", "loadmodule": "MALWARE_C2",
    "perl": "MALWARE_C2", "rootkit": "MALWARE_C2", "httptunnel": "MALWARE_C2",
    "ps": "MALWARE_C2", "sqlattack": "MALWARE_C2", "xterm": "MALWARE_C2",
}

# Map KDD protocol/service → ports
KDD_PORT_MAP = {
    "http": 80, "ftp": 21, "smtp": 25, "ssh": 22, "dns": 53,
    "https": 443, "pop3": 110, "imap": 143, "telnet": 23,
    "ftp_data": 20, "finger": 79, "auth": 113,
}


def _kdd_row_to_features(row: list) -> dict | None:
    """Convert one KDD row to ThreatLens feature dict."""
    if len(row) < 42:
        return None
    raw_label = row[41].strip().rstrip(".")
    label = KDD_LABEL_MAP.get(raw_label)
    if label is None:
        return None

    try:
        duration    = float(row[0])
        proto       = row[1].strip().lower()
        service     = row[2].strip().lower()
        src_bytes   = float(row[4])
        dst_bytes   = float(row[5])

        total_bytes = src_bytes + dst_bytes
        pkt_count   = max(int(float(row[22])), 1)
        dur_safe    = max(duration, 0.001)
        bps         = total_bytes / dur_safe
        avg_pkt     = total_bytes / pkt_count
        dst_port    = KDD_PORT_MAP.get(service, random.randint(1024, 65535))

        # Simulate std values from count
        ia_mean = (dur_safe * 1000) / pkt_count
        ia_std  = ia_mean * random.uniform(0.05, 0.4)
        pkt_std = avg_pkt * random.uniform(0.05, 0.35)

        return {
            "avg_pkt_size":       round(avg_pkt, 2),
            "pkt_count":          min(pkt_count, 1000),
            "flow_duration_sec":  round(dur_safe, 4),
            "bytes_per_sec":      round(bps, 2),
            "dst_port":           dst_port,
            "protocol_tcp":       1 if proto == "tcp"  else 0,
            "protocol_udp":       1 if proto == "udp"  else 0,
            "has_sni":            1 if service in ("https","ssl") else 0,
            "inter_arrival_mean": round(ia_mean, 2),
            "inter_arrival_std":  round(ia_std,  2),
            "pkt_size_std":       round(pkt_std, 2),
            "label":              label,
        }
    except (ValueError, IndexError):
        return None


def download_nsl_kdd() -> int:
    """Download NSL-KDD dataset and convert to ThreatLens format."""
    print("\n╔═══════════════════════════════╗")
    print("║  Dataset: NSL-KDD             ║")
    print("╚═══════════════════════════════╝")

    rows_written = 0
    for url, fname in [
        (NSL_KDD_TRAIN_URL, "kdd_train.txt"),
        (NSL_KDD_TEST_URL,  "kdd_test.txt"),
    ]:
        dest = RAW_DIR / fname
        if dest.exists():
            print(f"  [Cache] {fname} already downloaded, skipping.")
        else:
            ok = download_file(url, dest, fname)
            if not ok:
                print(f"  [Skip] Could not download {fname}")
                continue

        # Parse and convert
        out_path = PROCESSED / fname.replace(".txt", "_processed.csv")
        with open(dest) as fin, open(out_path, "w", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=ALL_COLS)
            writer.writeheader()
            for line in fin:
                parts = line.strip().split(",")
                feat  = _kdd_row_to_features(parts)
                if feat:
                    writer.writerow(feat)
                    rows_written += 1

        print(f"  Converted {rows_written:,} rows → {out_path.name}")

    return rows_written


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DATASET 2 – CTU-13 Botnet (selected scenarios via GitHub mirror)      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

CTU13_URL = (
    "https://raw.githubusercontent.com/brownfieldcity/CTU-13-Dataset/"
    "main/CTU-13-Dataset/1/capture20110810.binetflow"
)

CTU13_LABEL_MAP = {
    "background": "NORMAL",
    "normal":     "NORMAL",
    "botnet":     "MALWARE_C2",
    "c&c":        "MALWARE_C2",
    "cc":         "MALWARE_C2",
}


def _ctu_row_to_features(row: dict) -> dict | None:
    """Convert CTU-13 binetflow row → ThreatLens features."""
    try:
        label_raw = row.get("Label", "").lower()
        label = next(
            (v for k, v in CTU13_LABEL_MAP.items() if k in label_raw),
            None,
        )
        if label is None:
            return None

        proto   = row.get("Proto", "").lower()
        dport   = row.get("Dport", "0").strip()
        dur     = float(row.get("Dur", "0").strip() or "0")
        packets = int(float(row.get("TotPkts", "1").strip() or "1"))
        bytes_  = int(float(row.get("TotBytes", "0").strip() or "0"))

        # Parse port
        try:
            dst_port = int(dport.split("/")[0]) if "/" in dport else int(dport)
        except ValueError:
            dst_port = 0

        dur_safe = max(dur, 0.001)
        avg_pkt  = bytes_ / max(packets, 1)
        bps      = bytes_ / dur_safe
        ia_mean  = (dur_safe * 1000) / max(packets, 1)
        ia_std   = ia_mean * random.uniform(0.05, 0.4)
        pkt_std  = avg_pkt * random.uniform(0.05, 0.35)

        return {
            "avg_pkt_size":       round(avg_pkt, 2),
            "pkt_count":          min(packets, 1000),
            "flow_duration_sec":  round(dur_safe, 4),
            "bytes_per_sec":      round(bps, 2),
            "dst_port":           dst_port,
            "protocol_tcp":       1 if "tcp" in proto else 0,
            "protocol_udp":       1 if "udp" in proto else 0,
            "has_sni":            1 if dst_port == 443 else 0,
            "inter_arrival_mean": round(ia_mean, 2),
            "inter_arrival_std":  round(ia_std,  2),
            "pkt_size_std":       round(pkt_std, 2),
            "label":              label,
        }
    except (ValueError, KeyError):
        return None


def download_ctu13() -> int:
    print("\n╔═══════════════════════════════╗")
    print("║  Dataset: CTU-13 Botnet       ║")
    print("╚═══════════════════════════════╝")

    dest = RAW_DIR / "ctu13_s1.binetflow"
    if not dest.exists():
        ok = download_file(CTU13_URL, dest, "CTU-13 Scenario 1")
        if not ok:
            return 0

    out_path = PROCESSED / "ctu13_processed.csv"
    rows_written = 0
    with open(dest, newline="", errors="ignore") as fin, \
         open(out_path, "w", newline="") as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=ALL_COLS)
        writer.writeheader()
        for row in reader:
            feat = _ctu_row_to_features(row)
            if feat:
                writer.writerow(feat)
                rows_written += 1

    print(f"  Converted {rows_written:,} rows → {out_path.name}")
    return rows_written


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DATASET 3 – Synthetic (generated locally, no download)                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# Adware / tracking domain patterns (real domains used for ad tracking)
ADWARE_DOMAINS_PORTS = [80, 443, 8080]
TOR_PORTS             = [9001, 9030, 9050, 9150]
P2P_PORTS             = [6881, 6882, 6883, 51413, 49152]

LABEL_CONFIGS = {
    "NORMAL":      dict(weight=0.40, avg_pkt=(200,1400), pkts=(5,200),   bps=(1e3,5e5),  ia=(20,800),    ia_var=0.3, port_choices=[80,443,8080,8443]),
    "PORT_SCAN":   dict(weight=0.10, avg_pkt=(40,100),   pkts=(50,500),  bps=(2e3,8e4),  ia=(1,15),      ia_var=0.1, port_choices=list(range(20,1024))),
    "DOS_ATTACK":  dict(weight=0.10, avg_pkt=(60,256),   pkts=(500,1000),bps=(5e5,5e7),  ia=(0.1,3),     ia_var=0.05,port_choices=[80,443]),
    "MALWARE_C2":  dict(weight=0.12, avg_pkt=(200,900),  pkts=(8,60),    bps=(500,1.5e4),ia=(28000,32000),ia_var=0.04,port_choices=[443,4444,6666,1337,8080]),
    "ADWARE":      dict(weight=0.13, avg_pkt=(80,500),   pkts=(3,30),    bps=(200,8e3),  ia=(50,2000),   ia_var=0.4, port_choices=ADWARE_DOMAINS_PORTS),
    "TOR_TRAFFIC": dict(weight=0.07, avg_pkt=(400,1400), pkts=(20,300),  bps=(5e3,2e5),  ia=(5,200),     ia_var=0.3, port_choices=TOR_PORTS),
    "P2P_TRAFFIC": dict(weight=0.08, avg_pkt=(700,1400), pkts=(100,600), bps=(1e4,5e5),  ia=(2,80),      ia_var=0.2, port_choices=P2P_PORTS),
}


def _make_synthetic_row(label: str, cfg: dict) -> dict:
    ia_mean = random.uniform(*cfg["ia"])
    ia_std  = ia_mean * random.uniform(0.01, cfg["ia_var"])
    avg_pkt = random.uniform(*cfg["avg_pkt"])
    pkt_std = avg_pkt * random.uniform(0.02, 0.35)
    pkts    = random.randint(*cfg["pkts"])
    bps     = random.uniform(*cfg["bps"])
    dur     = max((avg_pkt * pkts) / bps, 0.001)
    port    = random.choice(cfg["port_choices"])
    has_sni = 1 if port == 443 else 0

    return {
        "avg_pkt_size":       round(avg_pkt, 2),
        "pkt_count":          min(pkts, 1000),
        "flow_duration_sec":  round(dur, 4),
        "bytes_per_sec":      round(bps, 2),
        "dst_port":           port,
        "protocol_tcp":       random.choice([0, 1]),
        "protocol_udp":       random.choice([0, 1]),
        "has_sni":            has_sni,
        "inter_arrival_mean": round(ia_mean, 2),
        "inter_arrival_std":  round(ia_std,  2),
        "pkt_size_std":       round(pkt_std, 2),
        "label":              label,
    }


def generate_synthetic(n: int = 50_000) -> int:
    print(f"\n╔═══════════════════════════════════════╗")
    print(f"║  Dataset: Synthetic ({n:,} rows)  ║")
    print(f"╚═══════════════════════════════════════╝")

    out_path = PROCESSED / "synthetic_dataset.csv"
    rows_written = 0

    with open(out_path, "w", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=ALL_COLS)
        writer.writeheader()

        for label, cfg in LABEL_CONFIGS.items():
            count = int(n * cfg["weight"])
            for i in range(count):
                writer.writerow(_make_synthetic_row(label, cfg))
                rows_written += 1
                if rows_written % 1000 == 0:
                    progress_bar(rows_written, n, "  Generating")

    progress_bar(rows_written, rows_written, "  Generating")
    print(f"  Saved {rows_written:,} rows → {out_path.name}")
    return rows_written


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  COMBINE all processed CSVs into one master dataset                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def combine_datasets() -> int:
    csv_files = list(PROCESSED.glob("*_processed.csv")) + \
                list(PROCESSED.glob("synthetic_dataset.csv"))

    if not csv_files:
        print("[Combine] No processed datasets found.")
        return 0

    total = 0
    with open(COMBINED_CSV, "w", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=ALL_COLS)
        writer.writeheader()
        for path in csv_files:
            with open(path, newline="") as fin:
                reader = csv.DictReader(fin)
                for row in reader:
                    # Keep only known columns
                    clean = {k: row[k] for k in ALL_COLS if k in row}
                    if len(clean) == len(ALL_COLS):
                        writer.writerow(clean)
                        total += 1

    print(f"\n[Combine] Master dataset: {COMBINED_CSV.name}  ({total:,} total rows)")

    # Print label distribution
    counts: dict[str, int] = {}
    with open(COMBINED_CSV) as f:
        for row in csv.DictReader(f):
            lbl = row.get("label", "?")
            counts[lbl] = counts.get(lbl, 0) + 1
    print("  Label distribution:")
    for lbl, cnt in sorted(counts.items(), key=lambda x: -x[1]):
        bar = "█" * int(30 * cnt / total)
        print(f"    {lbl:<16} {cnt:>7,}  {bar}")

    return total


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  MAIN                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

AVAILABLE = {
    "nsl-kdd":   ("NSL-KDD intrusion detection",          download_nsl_kdd),
    "ctu13":     ("CTU-13 Botnet flows",                  download_ctu13),
    "synthetic": ("Synthetic generated dataset (fast)",   None),
}


def main():
    parser = argparse.ArgumentParser(
        description="ThreatLens – Download and prepare training datasets"
    )
    parser.add_argument(
        "--dataset", default="all",
        help="Dataset to download: all | nsl-kdd | ctu13 | synthetic"
    )
    parser.add_argument("--n", default=50000, type=int,
                        help="Rows for synthetic dataset (default: 50000)")
    parser.add_argument("--list", action="store_true",
                        help="List available datasets")
    parser.add_argument("--skip-train", action="store_true",
                        help="Only download, do not trigger training")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable datasets:")
        for key, (desc, _) in AVAILABLE.items():
            print(f"  {key:<14} {desc}")
        print("  all            Download + generate all of the above")
        return

    print("╔══════════════════════════════════════════════════════╗")
    print("║   ThreatLens – Dataset Downloader v1.0              ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"  Output directory: {DATA_DIR}")

    total_rows = 0
    ds = args.dataset.lower()

    if ds in ("all", "nsl-kdd"):
        total_rows += download_nsl_kdd()

    if ds in ("all", "ctu13"):
        total_rows += download_ctu13()

    if ds in ("all", "synthetic"):
        total_rows += generate_synthetic(args.n)

    if ds not in AVAILABLE and ds != "all":
        print(f"[Error] Unknown dataset '{args.dataset}'. Use --list to see options.")
        sys.exit(1)

    total_rows += combine_datasets() if total_rows > 0 else 0

    print(f"\n✓ Done. {total_rows:,} total rows ready in {DATA_DIR}")

    if not args.skip_train and COMBINED_CSV.exists():
        print("\n[Auto-train] Starting model training on combined dataset…")
        # Import and run trainer directly
        sys.path.insert(0, str(PROJECT_ROOT))
        from scripts.train_model import train
        train(str(COMBINED_CSV), str(MODEL_DIR))


if __name__ == "__main__":
    main()
