#!/usr/bin/env python3
"""
ThreatLens – Model Training Script (v2)
=========================================
Trains an XGBoost classifier with SMOTE oversampling and stratified
cross-validation.  Falls back to RandomForest if XGBoost is unavailable.

Usage:
    python scripts/train_model.py                       # use combined dataset
    python scripts/train_model.py --synthetic --n 80000
    python scripts/train_model.py --data /path/to.csv
    python scripts/train_model.py --force
"""

import argparse, csv, os, pickle, sys, time, json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
PROCESSED    = DATA_DIR / "processed"
MODEL_DIR    = PROJECT_ROOT / "threatlens" / "ml" / "models"
COMBINED_CSV = PROCESSED / "threatlens_dataset.csv"

FEATURE_COLS = [
    "avg_pkt_size", "pkt_count", "flow_duration_sec", "bytes_per_sec",
    "dst_port", "protocol_tcp", "protocol_udp", "has_sni",
    "inter_arrival_mean", "inter_arrival_std", "pkt_size_std",
]
LABEL_COL = "label"


def train(data_path: str, output_dir: str, force: bool = False):
    import numpy as np
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.metrics import classification_report, f1_score, confusion_matrix

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ── Load data ────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  ThreatLens Model Training v2.0")
    print(f"{'='*60}")
    print(f"\n[1/6] Loading data: {data_path}")
    X_list, y_list = [], []
    with open(data_path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                X_list.append([float(row[c]) for c in FEATURE_COLS])
                y_list.append(row[LABEL_COL].strip())
            except (KeyError, ValueError):
                pass

    total = len(X_list)
    if total < 200:
        print(f"[!] Only {total} rows, need 200+. Aborting.")
        return None

    X = np.array(X_list, dtype="float32")
    y = np.array(y_list)

    print(f"      {total:,} samples loaded")
    unique, counts = np.unique(y, return_counts=True)
    for lbl, cnt in zip(unique, counts):
        print(f"      {lbl:<16} {cnt:>7,}  {'█'*int(40*cnt/total)}")

    # ── Encode labels ────────────────────────────────────────────────────────
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # ── Scale features ───────────────────────────────────────────────────────
    print(f"\n[2/6] Scaling features...")
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── SMOTE oversampling ───────────────────────────────────────────────────
    print(f"[3/6] Applying SMOTE for class balance...")
    try:
        from imblearn.over_sampling import SMOTE
        # Check minimum class size for SMOTE neighbors
        min_count = min(counts)
        k_neighbors = min(5, min_count - 1) if min_count > 1 else 1
        smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
        X_resampled, y_resampled = smote.fit_resample(X_scaled, y_encoded)
        print(f"      Before SMOTE: {len(X_scaled):,} → After: {len(X_resampled):,}")
    except ImportError:
        print("      [!] imbalanced-learn not installed, skipping SMOTE")
        X_resampled, y_resampled = X_scaled, y_encoded

    # ── Train/Val split ──────────────────────────────────────────────────────
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_resampled, y_resampled, test_size=0.2, stratify=y_resampled, random_state=42
    )

    # ── Train XGBoost ────────────────────────────────────────────────────────
    print(f"\n[4/6] Training XGBoost on {len(X_tr):,} samples...")
    t0 = time.time()
    model_type = "xgboost"

    try:
        from xgboost import XGBClassifier

        clf = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            gamma=0.1,
            reg_alpha=0.1,
            reg_lambda=1.0,
            use_label_encoder=False,
            eval_metric="mlogloss",
            n_jobs=-1,
            random_state=42,
            verbosity=0,
        )
        clf.fit(
            X_tr, y_tr,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )
    except ImportError:
        print("      [!] XGBoost not available, falling back to RandomForest")
        from sklearn.ensemble import RandomForestClassifier
        model_type = "random_forest"
        clf = RandomForestClassifier(
            n_estimators=300, max_depth=25, min_samples_leaf=2,
            class_weight="balanced", n_jobs=-1, random_state=42
        )
        clf.fit(X_tr, y_tr)

    elapsed = time.time() - t0
    print(f"      Done in {elapsed:.1f}s ({model_type})")

    # ── Cross-validation ─────────────────────────────────────────────────────
    print(f"\n[5/6] 5-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_resampled, y_resampled, cv=cv, scoring="f1_weighted", n_jobs=-1)
    print(f"      CV F1 scores: {[f'{s:.4f}' for s in cv_scores]}")
    print(f"      CV F1 mean:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Evaluate on held-out set ─────────────────────────────────────────────
    y_pred = clf.predict(X_val)
    f1 = f1_score(y_val, y_pred, average="weighted", zero_division=0)
    print(f"\n      Validation F1: {f1:.4f}")

    # Decode labels for readable report
    target_names = le.classes_
    y_val_labels  = le.inverse_transform(y_val)
    y_pred_labels = le.inverse_transform(y_pred)

    print(f"\n{classification_report(y_val_labels, y_pred_labels, zero_division=0)}")

    # Confusion matrix
    cm = confusion_matrix(y_val_labels, y_pred_labels, labels=target_names)
    print("  Confusion Matrix:")
    print(f"  {'':>16}", "  ".join(f"{n[:6]:>6}" for n in target_names))
    for i, row in enumerate(cm):
        print(f"  {target_names[i]:>16}", "  ".join(f"{v:>6}" for v in row))

    # ── Save model ───────────────────────────────────────────────────────────
    print(f"\n[6/6] Saving model...")

    model_filename = "xgb_model.pkl" if model_type == "xgboost" else "rf_model.pkl"
    model_path  = out / model_filename
    scaler_path = out / "scaler.pkl"
    le_path     = out / "label_encoder.pkl"
    meta_path   = out / "model_meta.json"

    # Check existing model score
    current_f1 = 0.0
    if meta_path.exists() and not force:
        try:
            with open(meta_path) as mf:
                meta = json.load(mf)
                current_f1 = meta.get("f1_score", 0.0)
        except Exception:
            pass

    if f1 > current_f1 or force:
        pickle.dump(clf,    open(model_path,  "wb"))
        pickle.dump(scaler, open(scaler_path, "wb"))
        pickle.dump(le,     open(le_path,     "wb"))

        # Also save as rf_model.pkl for backward compatibility
        if model_type == "xgboost":
            pickle.dump(clf, open(out / "rf_model.pkl", "wb"))

        import datetime
        meta = {
            "trained_at":    datetime.datetime.now(datetime.UTC).isoformat(),
            "model_type":    model_type,
            "f1_score":      round(f1, 6),
            "cv_f1_mean":    round(cv_scores.mean(), 6),
            "cv_f1_std":     round(cv_scores.std(), 6),
            "n_estimators":  300,
            "classes":       list(le.classes_),
            "samples":       total,
            "smote_applied": len(X_resampled) != len(X_scaled),
            "features":      FEATURE_COLS,
        }
        with open(meta_path, "w") as mf:
            json.dump(meta, mf, indent=2)

        print(f"\n  ✓ Model saved  (F1 {current_f1:.4f} → {f1:.4f})")
        print(f"    {model_path}")
        print(f"    {scaler_path}")
        print(f"    {meta_path}")
    else:
        print(f"\n  Existing model (F1={current_f1:.4f}) is better. Use --force to override.")

    print(f"\n{'='*60}")
    print(f"  Training complete. Restart ThreatLens to load the new model.")
    print(f"{'='*60}\n")
    return f1


def main():
    parser = argparse.ArgumentParser(description="ThreatLens ML Model Trainer v2")
    parser.add_argument("--data",      default=None, help="Path to CSV dataset")
    parser.add_argument("--output",    default=str(MODEL_DIR), help="Output directory for model files")
    parser.add_argument("--synthetic", action="store_true", help="Generate synthetic data first")
    parser.add_argument("--n",         default=80000, type=int, help="Rows for synthetic dataset")
    parser.add_argument("--force",     action="store_true", help="Force overwrite even if F1 is lower")
    args = parser.parse_args()

    sys.path.insert(0, str(PROJECT_ROOT))

    if args.synthetic:
        from scripts.download_datasets import generate_synthetic
        PROCESSED.mkdir(parents=True, exist_ok=True)
        generate_synthetic(args.n)
        train(str(PROCESSED / "synthetic_dataset.csv"), args.output, args.force)
    elif args.data:
        train(args.data, args.output, args.force)
    elif COMBINED_CSV.exists():
        train(str(COMBINED_CSV), args.output, args.force)
    else:
        print("No dataset found. Run:")
        print("  python scripts/download_datasets.py --dataset all")
        print("  python scripts/train_model.py --synthetic")
        sys.exit(1)


if __name__ == "__main__":
    main()
