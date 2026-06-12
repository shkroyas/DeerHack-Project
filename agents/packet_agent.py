"""
BankSentinel — Packet Agent
============================
Challenge Addressed: C4 — Encrypted TLS 1.3 Traffic

The Packet Agent detects threats inside encrypted sessions without
any payload decryption using three independent layers:

  Layer 1 — JA3 Hash Match
    Looks up the client TLS fingerprint hash against the live
    abuse.ch JA3 threat database (refreshed every 30 minutes).
    Catches known malware families by their TLS handshake signature.

  Layer 2 — JA3S Bidirectional Cross-Signal
    Looks up the SERVER-side TLS fingerprint. Even when an attacker
    randomises the client JA3 (evading Layer 1), Cobalt Strike and
    similar C2 frameworks leave a recognisable server-side response
    fingerprint that is harder to change.
    Cross-signal: client JA3 is clean BUT server JA3S is malicious
    → medium-confidence alert.

  Layer 3 — Beacon IAT / Flow Entropy Classifier
    Uses the Random Forest trained on CTU-13 real botnet C2 traffic.
    Features: flow duration, packet counts, byte ratios, and beacon
    timing proxies (regularity, iat_cv_proxy, size_consistency).
    Catches zero-day TLS C2 where NEITHER JA3 nor JA3S is known.
    C2 beaconing has LOW inter-arrival time variance (malware calls
    home on a schedule). Human HTTPS has HIGH variance.

PAPER REFERENCE
---------------
  Section V-A (Packet Agent)
  Equation (2): JA3 = MD5(Version, Ciphers, Extensions, Curves, PointFormats)
  Table VI: JA3+JA3S achieves 91.7% DR on CTU-13 TLS scenarios
  Layer 3 extends this to zero-day fingerprints not in any database.

ARTIFACTS (downloaded from Colab, placed in models/)
-----------------------------------------------------
  packet_xgb_cicids.pkl         XGBoost on CICIDS-2018 Friday (91 features)
  packet_xgb_threshold.pkl      Optimal probability threshold (0.4868)
  packet_xgb_scaler.pkl         RobustScaler for CICIDS features
  packet_xgb_features.json      Ordered list of 91 CICIDS feature names
  packet_rf_ctu.pkl             Random Forest on CTU-13 (beacon detector)
  packet_rf_scaler.pkl          RobustScaler for CTU-13 features
  packet_rf_features.json       Ordered list of CTU-13 beacon feature names

Usage:
    from agents.packet_agent import PacketAgent
    from intel.threat_feed import threat_engine

    threat_engine.start()
    agent = PacketAgent.load()
    alert = agent.score(flow_record)
    if alert.is_threat:
        print(alert)
"""

from __future__ import annotations

import hashlib
import json
import logging
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np

from config import (
    BEACON_IAT_CV_THRESHOLD,
    BEACON_L3_CONFIDENCE,
    C2_IP_HIT_WEIGHT,
    JA3_FAMILY_HIT_WEIGHT,
    JA3S_CROSS_CONFIDENCE,
    MITRE_C2_TECHNIQUE,
    MODELS_DIR,
    TOR_EXIT_WEIGHT,
)
from intel.threat_feed import ThreatIntelEngine, threat_engine as _default_engine
from pipeline.ingestion import FlowRecord

logger = logging.getLogger(__name__)


# DATA STRUCTURES

@dataclass
class PacketAlert:
    """
    Structured alert emitted by the Packet Agent for every scored flow.

    The Correlation Agent reads confidence, is_threat, active_layers,
    and mitre_technique when computing the Composite Risk Score.

    Fields
    ------
    src_ip          Source IP address.
    dst_ip          Destination IP address.
    dst_port        Destination port.
    ja3_hash        Computed JA3 client fingerprint (32-char MD5 hex).
    ja3s_hash       Computed JA3S server fingerprint (32-char MD5 hex).
    confidence      Combined [0, 1] threat confidence.
    is_threat       True when confidence exceeds the alert threshold.
    active_layers   Which of L1/L2/L3 fired.
    layer_scores    Per-layer confidence scores.
    malware_family  Malware family name if Layer 1 or 2 hit, else None.
    mitre_technique MITRE ATT&CK technique if threat, else None.
    explanation     Human-readable SOC dashboard explanation.
    ja3_feed_age    Minutes since the JA3 threat feed was last refreshed.
    timestamp       UTC creation time.
    """
    src_ip:          str
    dst_ip:          str
    dst_port:        int
    ja3_hash:        Optional[str]
    ja3s_hash:       Optional[str]
    confidence:      float
    is_threat:       bool
    active_layers:   List[str]
    layer_scores:    Dict[str, float]
    malware_family:  Optional[str]
    mitre_technique: Optional[str]
    explanation:     str
    ja3_feed_age:    Optional[float] = None
    timestamp:       datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __str__(self) -> str:
        status = "THREAT" if self.is_threat else "clean"
        layers = "+".join(self.active_layers) if self.active_layers else "none"
        return (
            f"[PacketAlert {status}] "
            f"{self.src_ip}→{self.dst_ip}:{self.dst_port} "
            f"conf={self.confidence:.3f} "
            f"layers={layers} "
            f"family={self.malware_family}"
        )


# JA3 COMPUTATION

# GREASE extension/cipher values — excluded from JA3 per RFC
# (https://tools.ietf.org/html/rfc8701)
_GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def compute_ja3(
    version:       int,
    ciphers:       List[int],
    extensions:    List[int],
    curves:        List[int],
    point_formats: List[int],
) -> str:
    """
    Compute a JA3 fingerprint hash from TLS ClientHello fields.

    Implements Equation (2) from the paper:
      JA3 = MD5(Version,Ciphers,Extensions,EllipticCurves,PointFormats)

    GREASE values (RFC 8701) are stripped before hashing so that
    random GREASE bytes do not produce unique per-connection hashes.

    Args:
        version:       TLS version from ClientHello (e.g. 771 = TLS 1.2)
        ciphers:       List of cipher suite codes
        extensions:    List of extension type codes
        curves:        List of supported elliptic curve IDs
        point_formats: List of supported EC point format IDs

    Returns:
        32-character lowercase MD5 hex string.
    """
    def _clean(values: List[int]) -> str:
        return "-".join(
            str(v) for v in values if v not in _GREASE_VALUES
        )

    components = (
        f"{version},"
        f"{_clean(ciphers)},"
        f"{_clean(extensions)},"
        f"{_clean(curves)},"
        f"{_clean(point_formats)}"
    )
    return hashlib.md5(components.encode()).hexdigest()


def compute_ja3s(
    version:    int,
    cipher:     int,
    extensions: List[int],
) -> str:
    """
    Compute a JA3S fingerprint from TLS ServerHello fields.

    JA3S = MD5(Version, Cipher, Extensions)

    Args:
        version:    TLS version from ServerHello
        cipher:     Single selected cipher suite
        extensions: List of extension type codes in ServerHello

    Returns:
        32-character lowercase MD5 hex string.
    """
    components = (
        f"{version},"
        f"{cipher},"
        f"{'-'.join(str(e) for e in extensions if e not in _GREASE_VALUES)}"
    )
    return hashlib.md5(components.encode()).hexdigest()


# BEACON FEATURE ENGINEERING
# matches exactly what was computed during CTU-13 training in Colab

def compute_beacon_features(record: FlowRecord) -> np.ndarray:
    """
    Compute the Layer 3 beacon detection feature vector from a FlowRecord.

    These features mirror the CTU-13 preprocessing in the Colab notebook
    exactly. The order must match packet_rf_features.json.

    CTU-13 raw columns: dur, tot_pkts, tot_bytes, src_bytes
    Derived features:   bytes_per_pkt, bytes_per_sec, pkts_per_sec,
                        iat_mean_proxy, iat_cv_proxy, regularity,
                        size_consistency, flow_efficiency,
                        beacon_score_raw, proto_tcp, proto_udp,
                        dir_unidirectional, bwd_fwd_ratio

    Args:
        record: FlowRecord with features populated from ingestion.

    Returns:
        1-D float32 ndarray with features in the trained model's order.
        Missing features are filled with 0.0.
    """
    f = record.features
    eps = 1e-9

    dur         = float(f.get("Flow Duration",           0.0)) / 1e6  # µs → s
    tot_pkts    = max(float(f.get("Total Fwd Packets",    0.0))
                    + float(f.get("Total Bwd Packets",    0.0)), 1.0)
    tot_bytes   = max(float(f.get("Total Length of Fwd Packets", 0.0))
                    + float(f.get("Total Length of Bwd Packets", 0.0)), 1.0)
    src_bytes   = float(f.get("Total Length of Fwd Packets", 0.0))

    bytes_per_pkt  = tot_bytes / (tot_pkts + eps)
    bytes_per_sec  = tot_bytes / (dur + eps)
    pkts_per_sec   = tot_pkts  / (dur + eps)

    iat_mean   = float(f.get("Flow IAT Mean", 0.0)) / 1e6   # µs → s
    iat_std    = float(f.get("Flow IAT Std",  0.0)) / 1e6

    # Beacon timing proxies (same formula as notebook)
    iat_mean_proxy   = dur / (tot_pkts + eps)
    iat_cv_proxy     = bytes_per_pkt / (bytes_per_sec + eps)
    regularity       = 1.0 / (pkts_per_sec + eps + 1.0)
    size_consistency = src_bytes / (tot_bytes + eps)
    flow_efficiency  = tot_pkts  / (dur + eps + 1.0)
    beacon_score_raw = (
        regularity       * 0.4
        + size_consistency * 0.3
        + (1.0 / (iat_mean_proxy + eps + 1.0)) * 0.3
    )

    proto = float(f.get("Protocol", 6.0))
    proto_tcp = 1.0 if proto == 6.0 else 0.0
    proto_udp = 1.0 if proto == 17.0 else 0.0

    bwd_pkts  = float(f.get("Total Bwd Packets", 0.0))
    fwd_pkts  = float(f.get("Total Fwd Packets", 1.0))
    bwd_fwd_ratio = bwd_pkts / (fwd_pkts + eps)

    dst_port = float(f.get("Destination Port", 0.0))
    dir_unidirectional = 1.0 if bwd_pkts == 0.0 else 0.0

    return np.array([
        dur, tot_pkts, tot_bytes, src_bytes,
        bytes_per_pkt, bytes_per_sec, pkts_per_sec,
        iat_mean_proxy, iat_cv_proxy, regularity,
        size_consistency, flow_efficiency, beacon_score_raw,
        proto_tcp, proto_udp, dir_unidirectional, bwd_fwd_ratio,
        iat_mean, iat_std,
        dst_port,
    ], dtype=np.float32)


# PACKET AGENT

# Confidence threshold above which is_threat=True
# TUNED on CICIDS2017 benign vs CTU-13 attack: 0.50 balances FPR and detection
_THREAT_THRESHOLD = 0.50

# Artifact filenames (must match what was saved in Colab)
_FILES = {
    "rf_model":   "packet_rf_ctu.pkl",
    "rf_scaler":  "packet_rf_scaler.pkl",
    "rf_feats":   "packet_rf_features.json",
}


class PacketAgent:
    """
    Runtime Packet Agent — three-layer encrypted traffic detection.

    All three layers operate without any payload decryption.

    Layer 1 and Layer 2 use the live ThreatIntelEngine (intel/threat_feed.py)
    which requires no trained model — it queries the in-memory JA3/JA3S
    threat database built from the live abuse.ch feeds.

    Layer 3 uses the Random Forest trained on CTU-13 in Colab.
    """

    def __init__(
        self,
        rf_model,
        rf_scaler,
        rf_features:  List[str],
        intel:        ThreatIntelEngine,
    ):
        self._rf        = rf_model
        self._rf_scaler = rf_scaler
        self._rf_feats  = rf_features
        self._intel     = intel

    @classmethod
    def load(
        cls,
        models_dir: Path = MODELS_DIR,
        intel:      Optional[ThreatIntelEngine] = None,
    ) -> "PacketAgent":
        """
        Load Layer 3 artifacts from disk and return a ready PacketAgent.

        Layers 1 and 2 use the shared ThreatIntelEngine singleton from
        intel/threat_feed.py — no file loading required for those layers.

        Args:
            models_dir: Directory containing packet_*.pkl / *.json files.
            intel:      ThreatIntelEngine instance. If None, uses the
                        module-level singleton from intel.threat_feed.

        Raises:
            FileNotFoundError: if any required artifact is missing.
        """
        base = Path(models_dir)

        for key, fname in _FILES.items():
            if not (base / fname).exists():
                raise FileNotFoundError(
                    f"PacketAgent: missing {base / fname}\n"
                    "Download from Colab and place in models/ directory."
                )

        rf_model = joblib.load(base / _FILES["rf_model"])
        rf_scaler = joblib.load(base / _FILES["rf_scaler"])
        with open(base / _FILES["rf_feats"],  "r") as f:
            rf_features = json.load(f)

        engine = intel if intel is not None else _default_engine

        logger.info(
            f"PacketAgent: loaded Layer 3 RF "
            f"({len(rf_features)} features) from {base}"
        )
        return cls(
            rf_model   = rf_model,
            rf_scaler  = rf_scaler,
            rf_features = rf_features,
            intel      = engine,
        )

    # ── Core scoring ───────────────────────────────────────────────────────────

    def score(self, record: FlowRecord) -> PacketAlert:
        """
        Score a FlowRecord through all three layers and return a PacketAlert.

        The TLS metadata (ja3_hash, ja3s_hash, tls_ciphers, etc.) must be
        pre-populated on the FlowRecord by the ingestion layer in production.
        For the demo APT scenario, the fields are set in build_apt_scenario().

        Args:
            record: FlowRecord with features and optional TLS fields.

        Returns:
            PacketAlert with confidence, is_threat, active_layers populated.
        """
        scores:       Dict[str, float] = {}
        active:       List[str]        = []
        malware_fam:  Optional[str]    = None

        # ── Layer 1: JA3 client hash lookup ────────────────────────────────
        ja3_hash = record.ja3_hash
        if ja3_hash:
            l1_hit = self._intel.lookup_ja3(ja3_hash)
            if l1_hit:
                scores["L1"] = JA3_FAMILY_HIT_WEIGHT
                active.append("L1")
                malware_fam = l1_hit.malware_family
                logger.debug(
                    f"PacketAgent L1: JA3 match — {l1_hit.malware_family} "
                    f"[{ja3_hash[:12]}…]"
                )

        # C2 IP supplement (boosts L1 confidence)
        c2_hit  = self._intel.is_known_c2(record.dst_ip)
        tor_hit = self._intel.is_tor_exit(record.dst_ip)
        if c2_hit:
            scores["L1"] = scores.get("L1", 0.0) + C2_IP_HIT_WEIGHT
            if "L1" not in active:
                active.append("L1")
        if tor_hit:
            scores["L1"] = scores.get("L1", 0.0) + TOR_EXIT_WEIGHT
            if "L1" not in active:
                active.append("L1")

        # ── Layer 2: JA3S server-side cross-signal ──────────────────────────
        ja3s_hash = record.ja3s_hash
        if ja3s_hash:
            l2_hit = self._intel.lookup_ja3s(ja3s_hash)
            # Cross-signal fires when client is CLEAN but server is malicious
            client_clean = "L1" not in active
            if l2_hit and client_clean:
                scores["L2"] = JA3S_CROSS_CONFIDENCE
                active.append("L2")
                malware_fam = malware_fam or l2_hit.malware_family
                logger.debug(
                    f"PacketAgent L2: JA3S cross-signal — "
                    f"{l2_hit.malware_family} "
                    f"[{ja3s_hash[:12]}…]"
                )

        # ── Layer 3: CTU-13 Random Forest (beacon detector) ─────────────────
        l3_score = self._score_layer3(record)
        if l3_score > 0.0:
            scores["L3"] = l3_score
            active.append("L3")

        # ── Combine layers ───────────────────────────────────────────────────
        # Max pooling: any single layer firing is enough for an alert.
        # Confidence is capped at 1.0.
        confidence = min(max(scores.values(), default=0.0), 1.0)
        is_threat  = confidence >= _THREAT_THRESHOLD

        mitre       = MITRE_C2_TECHNIQUE if is_threat else None
        explanation = self._build_explanation(
            record, scores, active, malware_fam, confidence, is_threat
        )
        feed_age    = self._intel.stats.age_minutes

        alert = PacketAlert(
            src_ip         = record.src_ip,
            dst_ip         = record.dst_ip,
            dst_port       = int(record.features.get("Destination Port", 0)),
            ja3_hash       = ja3_hash,
            ja3s_hash      = ja3s_hash,
            confidence     = confidence,
            is_threat      = is_threat,
            active_layers  = active,
            layer_scores   = scores,
            malware_family = malware_fam,
            mitre_technique = mitre,
            explanation    = explanation,
            ja3_feed_age   = feed_age,
        )
        record.packet_alert = alert
        return alert

    def score_ja3_direct(
        self,
        ja3_hash:   str,
        ja3s_hash:  str,
        dst_ip:     str = "0.0.0.0",
        src_ip:     str = "0.0.0.0",
        dst_port:   int = 443,
    ) -> PacketAlert:
        """
        Score a flow using only JA3/JA3S hashes (no FlowRecord needed).
        Useful for testing Layer 1 and Layer 2 directly.

        Args:
            ja3_hash:  Pre-computed JA3 client fingerprint.
            ja3s_hash: Pre-computed JA3S server fingerprint.
            dst_ip:    Destination IP (checked against C2 blocklist).
            src_ip:    Source IP.
            dst_port:  Destination port.

        Returns:
            PacketAlert with only Layer 1 and Layer 2 populated.
        """
        from pipeline.ingestion import FlowRecord, FLOW_FEATURES
        features = {f: 0.0 for f in FLOW_FEATURES}
        features["Destination Port"] = float(dst_port)
        record = FlowRecord(src_ip, dst_ip, features)
        record.ja3_hash  = ja3_hash
        record.ja3s_hash = ja3s_hash
        return self.score(record)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _score_layer3(self, record: FlowRecord) -> float:
        """
        Layer 3: score a flow using the CTU-13 Random Forest beacon detector.

        Computes beacon features from flow-level statistics and returns the
        probability of the flow being botnet C2 traffic.

        Returns 0.0 if the flow has insufficient data for reliable scoring.
        """
        try:
            raw_feats = compute_beacon_features(record)

            # Align to the trained feature order from ctu13_beacon_features.json
            n_expected = len(self._rf_feats)
            if len(raw_feats) < n_expected:
                padded = np.zeros(n_expected, dtype=np.float32)
                padded[:len(raw_feats)] = raw_feats
                raw_feats = padded
            elif len(raw_feats) > n_expected:
                raw_feats = raw_feats[:n_expected]

            # Replace any inf / nan
            raw_feats = np.nan_to_num(raw_feats, nan=0.0, posinf=0.0, neginf=0.0)

            X_scaled = self._rf_scaler.transform(raw_feats.reshape(1, -1))
            prob     = float(self._rf.predict_proba(X_scaled)[0, 1])
            return prob if prob >= BEACON_IAT_CV_THRESHOLD else 0.0
        except Exception as exc:
            logger.debug(f"PacketAgent L3 scoring error: {exc}")
            return 0.0

    def _build_explanation(
        self,
        record:     FlowRecord,
        scores:     Dict[str, float],
        active:     List[str],
        family:     Optional[str],
        confidence: float,
        is_threat:  bool,
    ) -> str:
        if not is_threat:
            return (
                f"No encrypted threat signal detected for "
                f"{record.src_ip}→{record.dst_ip} "
                f"(conf={confidence:.3f}). "
                f"Feed age: {self._intel.stats.age_minutes:.0f} min."
                if self._intel.stats.age_minutes is not None
                else f"No encrypted threat signal (conf={confidence:.3f})."
            )

        parts = []
        if "L1" in active:
            if family:
                parts.append(f"L1: JA3 hash matches {family}")
            if self._intel.is_known_c2(record.dst_ip):
                parts.append(f"L1: destination IP is known C2 server")
            if self._intel.is_tor_exit(record.dst_ip):
                parts.append(f"L1: destination is Tor exit node")
        if "L2" in active:
            parts.append(
                f"L2: server JA3S cross-signal — client JA3 clean "
                f"but server response matches C2 profile"
            )
        if "L3" in active:
            parts.append(
                f"L3: beacon timing analysis — CTU-13 RF "
                f"prob={scores.get('L3', 0):.3f} "
                f"(zero-day TLS; no fingerprint match required)"
            )

        feed_age = self._intel.stats.age_minutes
        age_str  = (
            f"  Feed age: {feed_age:.0f} min." if feed_age is not None else ""
        )

        return (
            f"C4 THREAT detected — "
            f"{record.src_ip}→{record.dst_ip}:{record.features.get('Destination Port', '?')} "
            f"conf={confidence:.3f}.  "
            + "  ".join(parts)
            + age_str
        )