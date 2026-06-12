#!/usr/bin/env python3
"""Calibrate Layer 3 (CTU-13 RF) threshold for optimal benign/attack separation.

Usage:
    python scripts/calibrate_l3_threshold.py [--target-fpr 0.05]

This script:
  1. Loads the CTU-13 Random Forest from models/
  2. Generates synthetic benign and attack test sets
  3. Computes ROC curve and optimal threshold
  4. Recommends new threshold to achieve target FPR
  5. Shows impact on detection rate and false positive rate
"""

import numpy as np
from pathlib import Path
from sklearn.metrics import roc_curve, auc
import joblib
import json
import argparse

MODELS_DIR = Path(__file__).parent.parent / "models"
L3_THREAT_THRESHOLD = 0.40  # Current hardcoded value in packet_agent.py


def load_feature_names():
    """Load the 20 feature names expected by the RF model."""
    with open(MODELS_DIR / "packet_rf_features.json") as f:
        return json.load(f)


def generate_benign_samples(n=500, n_features=20, seed=42):
    """Generate synthetic benign flow features (normal IAT patterns)."""
    rng = np.random.default_rng(seed)
    
    # Benign: normal to moderately high variability across features
    # Generate realistic CTU-13 feature range for benign flows
    sample = rng.normal(
        loc=[
            2.5,      # dur (log scale, ~100s)
            15.0,     # tot_pkts
            8000.0,   # tot_bytes
            4000.0,   # src_bytes
            500.0,    # bytes_per_pkt
            3000.0,   # bytes_per_sec
            6.0,      # pkts_per_sec
            0.15,     # iat_mean_proxy (high variance = benign)
            1.2,      # iat_cv_proxy (high CV = benign)
            0.4,      # regularity (low = irregular = benign)
            0.3,      # size_consistency
            0.6,      # flow_efficiency
            0.3,      # beacon_score_raw
            1.0,      # proto_tcp
            0.0,      # proto_udp
            0.1,      # dir_unidirectional
            0.5,      # bwd_fwd_ratio
            0.0,      # stos
            0.0,      # dtos
            0.0,      # proto_enc
        ],
        scale=[0.5, 10, 5000, 3000, 200, 2000, 3, 0.1, 0.5, 0.2, 0.2, 0.2, 0.2, 0.1, 0.1, 0.1, 0.2, 0.1, 0.1, 0.1],
        size=(n, n_features)
    )
    
    return sample


def generate_attack_samples(n=200, n_features=20, seed=123):
    """Generate synthetic attack flow features (regular C2 beaconing)."""
    rng = np.random.default_rng(seed)
    
    # Attack: low IAT variance (regular beaconing), high beacon score
    sample = rng.normal(
        loc=[
            1.5,      # dur (shorter sessions)
            10.0,     # tot_pkts
            3000.0,   # tot_bytes
            1500.0,   # src_bytes
            300.0,    # bytes_per_pkt
            2000.0,   # bytes_per_sec
            5.0,      # pkts_per_sec
            0.05,     # iat_mean_proxy (LOW = regular beaconing)
            0.1,      # iat_cv_proxy (LOW CV = regular = attack)
            0.85,     # regularity (HIGH = regular = attack)
            0.8,      # size_consistency
            0.5,      # flow_efficiency
            0.75,     # beacon_score_raw (HIGH = likely beacon)
            1.0,      # proto_tcp
            0.0,      # proto_udp
            0.8,      # dir_unidirectional
            0.3,      # bwd_fwd_ratio
            0.0,      # stos
            0.0,      # dtos
            0.0,      # proto_enc
        ],
        scale=[0.3, 5, 1000, 500, 100, 500, 2, 0.02, 0.05, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.05, 0.05, 0.05],
        size=(n, n_features)
    )
    
    return sample


def calibrate_threshold(target_fpr=0.05):
    """Calibrate optimal threshold for Layer 3."""
    print(f"\n{'='*70}")
    print(f"Layer 3 (CTU-13 RF) Threshold Calibration")
    print(f"{'='*70}\n")
    
    # Load model and scaler
    try:
        rf_model = joblib.load(MODELS_DIR / "packet_rf_ctu.pkl")
        rf_scaler = joblib.load(MODELS_DIR / "packet_rf_scaler.pkl")
        features = load_feature_names()
        n_features = len(features)
        print(f"✓ Loaded RF model from {MODELS_DIR / 'packet_rf_ctu.pkl'}")
        print(f"✓ Model expects {n_features} features")
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        return
    
    # Generate test data
    print("\nGenerating synthetic test sets...")
    X_benign = generate_benign_samples(n=500, n_features=n_features, seed=42)
    X_attack = generate_attack_samples(n=200, n_features=n_features, seed=123)
    
    print(f"  Benign samples : {len(X_benign)} (shape: {X_benign.shape})")
    print(f"  Attack samples : {len(X_attack)} (shape: {X_attack.shape})")
    
    # Scale and predict
    print("\nScoring flows with RF model...")
    X_benign_scaled = rf_scaler.transform(X_benign)
    X_attack_scaled = rf_scaler.transform(X_attack)
    
    # RandomForest returns probabilities (higher = more anomalous)
    y_benign_proba = rf_model.predict_proba(X_benign_scaled)[:, 1]  # anomaly prob
    y_attack_proba = rf_model.predict_proba(X_attack_scaled)[:, 1]
    
    print(f"  Benign scores : min={y_benign_proba.min():.4f}, "
          f"max={y_benign_proba.max():.4f}, "
          f"mean={y_benign_proba.mean():.4f}")
    print(f"  Attack scores : min={y_attack_proba.min():.4f}, "
          f"max={y_attack_proba.max():.4f}, "
          f"mean={y_attack_proba.mean():.4f}")
    
    # Build ROC curve
    y_true = np.concatenate([np.zeros(len(y_benign_proba)), 
                             np.ones(len(y_attack_proba))])
    y_scores = np.concatenate([y_benign_proba, y_attack_proba])
    
    fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)
    
    print(f"\n  ROC AUC : {roc_auc:.4f}")
    
    # Find threshold for target FPR
    idx = np.argmin(np.abs(fpr - target_fpr))
    optimal_threshold = thresholds[idx]
    actual_fpr = fpr[idx]
    actual_tpr = tpr[idx]
    
    print(f"\n{'─'*70}")
    print(f"Recommended Threshold (target FPR={target_fpr:.1%}):")
    print(f"{'─'*70}")
    print(f"  Threshold       : {optimal_threshold:.4f}")
    print(f"  Actual FPR      : {actual_fpr:.1%}  (false positives on benign)")
    print(f"  Detection Rate  : {actual_tpr:.1%}  (true positives on attacks)")
    print(f"  Current value   : {L3_THREAT_THRESHOLD:.4f}")
    
    # Compare with current threshold
    print(f"\n{'─'*70}")
    print(f"Impact of Current Threshold ({L3_THREAT_THRESHOLD:.4f}):")
    print(f"{'─'*70}")
    
    benign_flagged = (y_benign_proba > L3_THREAT_THRESHOLD).sum()
    attack_detected = (y_attack_proba > L3_THREAT_THRESHOLD).sum()
    
    current_fpr = benign_flagged / len(y_benign_proba)
    current_tpr = attack_detected / len(y_attack_proba)
    
    print(f"  False Positive Rate : {current_fpr:.1%}  ({benign_flagged}/{len(y_benign_proba)})")
    print(f"  Detection Rate      : {current_tpr:.1%}  ({attack_detected}/{len(y_attack_proba)})")
    
    # Show a few threshold options
    print(f"\n{'─'*70}")
    print(f"Threshold Options for Different FPR Targets:")
    print(f"{'─'*70}")
    print(f"  {'Target FPR':<15} {'Threshold':<15} {'Detection Rate':<20}")
    print(f"  {'-'*15} {'-'*15} {'-'*20}")
    
    for target in [0.01, 0.05, 0.10, 0.15]:
        idx = np.argmin(np.abs(fpr - target))
        thr = thresholds[idx]
        dr = tpr[idx]
        print(f"  {target:<15.1%} {thr:<15.4f} {dr:<20.1%}")
    
    print(f"\n{'='*70}")
    print(f"RECOMMENDATION:")
    print(f"{'='*70}")
    print(f"""
Update _THREAT_THRESHOLD in agents/packet_agent.py from {L3_THREAT_THRESHOLD} to {optimal_threshold:.4f}

This will achieve:
  - False Positive Rate: {actual_fpr:.1%} (legitimate traffic incorrectly flagged)
  - Detection Rate:      {actual_tpr:.1%} (attacks correctly detected)

If detection rate is too low, lower the threshold further.
If false positives are too high, raise the threshold.
""")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-fpr", type=float, default=0.05,
                       help="Target false positive rate (default 0.05 = 5%%)")
    args = parser.parse_args()
    
    calibrate_threshold(target_fpr=args.target_fpr)
