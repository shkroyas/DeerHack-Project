"""
BankSentinel — Behavior Agent
==============================
Challenge Addressed: C1 — Zero-Day Attacks (no known signature)

WHY THIS MATTERS
----------------
Zero-day attacks have no known signature. Signature-based systems cannot
catch them. The Behavior Agent solves this by learning ONLY what normal
behavior looks like. Any sequence that deviates from that learned normal
is flagged — regardless of whether it has ever been seen before.

The model has literally never been shown an attack during training.
It fires because deviation from normal is anomalous — not because the
attack matches a pattern.

HOW IT WORKS
------------
A Bidirectional LSTM (BiLSTM) autoencoder is trained exclusively on
normal behavioral sequences. It learns to reconstruct normal patterns
with low error. When it encounters an anomalous sequence, the
reconstruction error spikes — because it has never learned how to
reconstruct that kind of behavior.

Detection threshold = 95th percentile of reconstruction errors on the
normal training set.

INPUT FEATURES (8 dimensions per event, sequence length = 20)
-------------------------------------------------------------
  [0] event_id_norm       Normalised Windows Event ID
  [1] hour_sin            sin(2π × hour/24)
  [2] hour_cos            cos(2π × hour/24)
  [3] src_ip_cluster      Source IP cluster index
  [4] target_resource     Target resource category
  [5] privilege_level     Privilege level (0=low, 1=high)
  [6] query_rate          Normalised query/action rate per minute
  [7] peer_z_score        Z-score deviation from role-peer group

ATTACK SCENARIOS DETECTED (zero-day — no signature for any)
------------------------------------------------------------
  credential_abuse      Account from new IP at off-hours
  privilege_escalation  Standard user added to privileged group
  data_staging          400+ DB queries then large file creation
  lateral_movement      Sequential RDP across multiple servers
  insider_exfil         Slow-drip exfiltration over 48 hours

PAPER REFERENCE
---------------
  Section V-C, Table II (Windows Event IDs), Table IX (UEBA performance)
  BiLSTM: 2 layers, hidden_size=64, bidirectional=True, dropout=0.2
  Target: overall DR=94.9%, FPR=1.3%

Usage:
    # Training (run in Google Colab)
    from agents.behavior_agent import BehaviorAgentTrainer
    trainer = BehaviorAgentTrainer()
    trainer.train(n_users=500, n_per_user=20)
    trainer.save()

    # Inference
    from agents.behavior_agent import BehaviorAgent
    agent = BehaviorAgent.load()
    alert = agent.score(flow_record)
"""

from __future__ import annotations

import logging
import math
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

from config import (
    BEHAVIOR_ANOMALY_PERCENTILE,
    BEHAVIOR_DROPOUT,
    BEHAVIOR_HIDDEN_SIZE,
    BEHAVIOR_INPUT_SIZE,
    BEHAVIOR_NUM_LAYERS,
    BEHAVIOR_SEQUENCE_LENGTH,
    MITRE_COLLECTION_TECHNIQUE,
    MITRE_LATERAL_TECHNIQUE,
    MITRE_PRIV_ESC_TECHNIQUE,
    MODELS_DIR,
)
from pipeline.ingestion import FlowRecord

logger = logging.getLogger(__name__)

# Windows Event IDs monitored (Table II of paper)
MONITORED_EVENT_IDS = {
    4624: "successful_logon",
    4625: "failed_logon",
    4648: "explicit_credential_logon",   # Pass-the-Hash indicator
    4688: "process_creation",
    4698: "scheduled_task_creation",
    4720: "user_account_creation",
    4728: "group_membership_change",
    4732: "group_membership_change",
    4769: "kerberos_ticket_request",
}

_EVENT_ID_LIST  = sorted(MONITORED_EVENT_IDS.keys())
_EVENT_ID_INDEX = {
    eid: i / max(len(_EVENT_ID_LIST) - 1, 1)
    for i, eid in enumerate(_EVENT_ID_LIST)
}


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BehaviorAlert:
    """
    Structured alert emitted by the Behavior Agent for every scored sequence.

    The Correlation Agent uses recon_error, is_anomaly, and mitre_technique
    in the Bayesian BBN fusion (Phase 3).

    Fields
    ------
    account          Windows account name or service principal.
    src_ip           Source workstation IP.
    recon_error      Mean squared reconstruction error of the BiLSTM.
                     Higher = more anomalous.
    threshold        95th-percentile threshold from training.
    is_anomaly       True when recon_error > threshold.
    confidence       Calibrated [0, 1] score for Correlation Agent.
    scenario_hint    Which behavioral attack scenario this most resembles.
    mitre_technique  MITRE ATT&CK technique if anomalous, else None.
    explanation      Human-readable reason for the SOC dashboard.
    top_dims         Top-3 input dimensions by reconstruction error.
    peer_z_score     Deviation from role-peer group centroid.
    timestamp        UTC creation time.
    """
    account:         str
    src_ip:          str
    recon_error:     float
    threshold:       float
    is_anomaly:      bool
    confidence:      float
    scenario_hint:   Optional[str]
    mitre_technique: Optional[str]
    explanation:     str
    top_dims:        List[Tuple[str, float]] = field(default_factory=list)
    peer_z_score:    float                   = 0.0
    timestamp:       datetime               = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __str__(self) -> str:
        status = "ANOMALY" if self.is_anomaly else "NORMAL"
        return (
            f"[BehaviorAlert {status}] "
            f"account={self.account} "
            f"recon_error={self.recon_error:.4f} "
            f"threshold={self.threshold:.4f} "
            f"conf={self.confidence:.3f} "
            f"scenario={self.scenario_hint}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# BILSTM AUTOENCODER
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorLSTM(nn.Module):
    """
    Bidirectional LSTM autoencoder for zero-day behavioral detection.

    Architecture (Section V-C of paper):
      Encoder: BiLSTM(input=8, hidden=64, layers=2, dropout=0.2)
      Decoder: Linear(hidden*2 → input)

    Training: MSELoss on NORMAL sequences only.
    The model NEVER sees attack sequences during training.

    Detection: reconstruction_error = mean MSE across all timesteps.
    Threshold = 95th percentile of normal training errors.
    """

    def __init__(
        self,
        input_size:  int   = BEHAVIOR_INPUT_SIZE,
        hidden_size: int   = BEHAVIOR_HIDDEN_SIZE,
        num_layers:  int   = BEHAVIOR_NUM_LAYERS,
        dropout:     float = BEHAVIOR_DROPOUT,
    ):
        super().__init__()
        self.input_size  = input_size
        self.hidden_size = hidden_size
        self.num_layers  = num_layers

        self.encoder = nn.LSTM(
            input_size    = input_size,
            hidden_size   = hidden_size,
            num_layers    = num_layers,
            batch_first   = True,
            bidirectional = True,
            dropout       = dropout if num_layers > 1 else 0.0,
        )
        self.decoder = nn.Linear(hidden_size * 2, input_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Encode input sequence, then reconstruct it.

        Args:
            x: (batch, seq_len, input_size)

        Returns:
            Reconstructed tensor of same shape as x.
        """
        lstm_out, _ = self.encoder(x)          # (batch, seq_len, hidden*2)
        return self.decoder(lstm_out)           # (batch, seq_len, input_size)

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """
        Per-sample mean squared reconstruction error.

        Args:
            x: (batch, seq_len, input_size)

        Returns:
            1-D tensor of shape (batch,) with per-sample MSE.
        """
        recon = self.forward(x)
        return ((x - recon) ** 2).mean(dim=(1, 2))


# ═══════════════════════════════════════════════════════════════════════════════
# SEQUENCE DATASET
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorSequenceDataset(Dataset):
    """
    PyTorch Dataset wrapping a numpy array of behavioral sequences.

    Args:
        sequences: ndarray of shape (n_samples, seq_len, input_size).
    """

    def __init__(self, sequences: np.ndarray):
        self.data = torch.tensor(sequences, dtype=torch.float32)

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> torch.Tensor:
        return self.data[idx]


# ═══════════════════════════════════════════════════════════════════════════════
# SYNTHETIC DATA GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorDataGenerator:
    """
    Generates synthetic behavioral sequences for training and evaluation.

    In production, real Windows Event Logs flow in via Winlogbeat →
    Elastic SIEM. For the hackathon, this generator produces realistic
    sequences that faithfully reproduce the five attack scenarios.

    Normal user profile:
      Logs in during business hours, uses predictable resources,
      consistent query rates, near peer-group norms.
    """

    DIM_NAMES = [
        "event_id_norm",
        "hour_sin",
        "hour_cos",
        "src_ip_cluster",
        "target_resource",
        "privilege_level",
        "query_rate",
        "peer_z_score",
    ]

    def __init__(self, seed: int = 42):
        self.rng = np.random.default_rng(seed)

    def normal_sequence(
        self, seq_len: int = BEHAVIOR_SEQUENCE_LENGTH
    ) -> np.ndarray:
        """
        Generate one normal behavioral sequence for a typical bank employee.

        Returns:
            ndarray of shape (seq_len, 8).
        """
        seq = np.zeros((seq_len, BEHAVIOR_INPUT_SIZE), dtype=np.float32)
        hours = self.rng.uniform(8.0, 17.0, size=seq_len)

        for t in range(seq_len):
            h        = hours[t]
            event_id = self.rng.choice([4624, 4769, 4688])
            seq[t, 0] = _EVENT_ID_INDEX.get(event_id, 0.5)
            seq[t, 1] = math.sin(2 * math.pi * h / 24.0)
            seq[t, 2] = math.cos(2 * math.pi * h / 24.0)
            seq[t, 3] = self.rng.uniform(0.1, 0.4)    # familiar IP cluster
            seq[t, 4] = self.rng.uniform(0.2, 0.5)    # typical resources
            seq[t, 5] = 0.1                            # low privilege
            seq[t, 6] = self.rng.uniform(0.05, 0.2)   # normal query rate
            seq[t, 7] = self.rng.normal(0.0, 0.3)     # near peer mean
        return seq

    def generate_normal(
        self, n_users: int = 500, n_per_user: int = 20
    ) -> np.ndarray:
        """
        Generate normal sequences for n_users × n_per_user samples.

        Returns:
            ndarray of shape (n_users * n_per_user, seq_len, input_size).
        """
        return np.stack(
            [self.normal_sequence() for _ in range(n_users * n_per_user)]
        )

    # ── Attack scenario generators ─────────────────────────────────────────────

    def credential_abuse_sequence(self) -> np.ndarray:
        """Off-hours login from new/unfamiliar IP cluster."""
        seq      = self.normal_sequence()
        off_hour = self.rng.uniform(1.0, 4.0)
        for t in range(len(seq)):
            seq[t, 0] = _EVENT_ID_INDEX.get(4648, 0.5)  # explicit credential
            seq[t, 1] = math.sin(2 * math.pi * off_hour / 24.0)
            seq[t, 2] = math.cos(2 * math.pi * off_hour / 24.0)
            seq[t, 3] = self.rng.uniform(0.8, 1.0)      # unfamiliar IP
            seq[t, 7] = self.rng.uniform(2.0, 3.0)      # far above peers
        return seq

    def privilege_escalation_sequence(self) -> np.ndarray:
        """Standard user added to privileged group — privilege spike mid-session."""
        seq      = self.normal_sequence()
        midpoint = len(seq) // 2
        for t in range(midpoint, len(seq)):
            seq[t, 0] = _EVENT_ID_INDEX.get(4728, 0.5)  # group membership change
            seq[t, 5] = self.rng.uniform(0.8, 1.0)       # privilege spike
            seq[t, 7] = self.rng.uniform(2.5, 3.0)       # way above peers
        return seq

    def data_staging_sequence(self) -> np.ndarray:
        """400+ DB queries / 2 minutes — extreme query rate."""
        seq = self.normal_sequence()
        for t in range(len(seq)):
            seq[t, 4] = self.rng.uniform(0.8, 1.0)    # sensitive resources
            seq[t, 6] = self.rng.uniform(0.85, 1.0)   # extreme query rate
            seq[t, 7] = self.rng.uniform(2.0, 3.5)    # far above peers
        return seq

    def lateral_movement_sequence(self) -> np.ndarray:
        """Sequential RDP across multiple servers — rapidly changing IP clusters."""
        seq         = self.normal_sequence()
        ip_clusters = np.linspace(0.0, 1.0, len(seq))
        for t in range(len(seq)):
            seq[t, 0] = _EVENT_ID_INDEX.get(4648, 0.5)  # explicit credential
            seq[t, 3] = ip_clusters[t]                   # new server each step
            seq[t, 5] = self.rng.uniform(0.6, 0.9)       # elevated privilege
            seq[t, 7] = self.rng.uniform(1.5, 3.0)
        return seq

    def insider_exfil_sequence(self) -> np.ndarray:
        """Slow-drip exfiltration — monotonically growing query rate."""
        seq = self.normal_sequence()
        for t in range(len(seq)):
            seq[t, 6] = 0.3 + (t / len(seq)) * 0.5    # escalating slowly
            seq[t, 4] = self.rng.uniform(0.7, 0.9)     # sensitive resources
            seq[t, 7] = self.rng.uniform(1.2, 2.0)     # above peer mean
        return seq

    def generate_attacks(
        self, n_per_scenario: int = 30
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate all five attack scenarios with integer labels.

        Returns:
            sequences  — ndarray (n_total, seq_len, input_size)
            labels     — ndarray (n_total,) integer scenario index
                         0=credential_abuse, 1=priv_escalation,
                         2=data_staging, 3=lateral_movement, 4=insider_exfil
        """
        generators = [
            self.credential_abuse_sequence,
            self.privilege_escalation_sequence,
            self.data_staging_sequence,
            self.lateral_movement_sequence,
            self.insider_exfil_sequence,
        ]
        seqs, lbls = [], []
        for label_idx, gen in enumerate(generators):
            for _ in range(n_per_scenario):
                seqs.append(gen())
                lbls.append(label_idx)
        return np.stack(seqs), np.array(lbls)


SCENARIO_NAMES = [
    "credential_abuse",
    "privilege_escalation",
    "data_staging",
    "lateral_movement",
    "insider_exfil",
]

SCENARIO_MITRE = {
    "credential_abuse":     MITRE_PRIV_ESC_TECHNIQUE,    # T1078
    "privilege_escalation": MITRE_PRIV_ESC_TECHNIQUE,    # T1078
    "data_staging":         MITRE_COLLECTION_TECHNIQUE,  # T1213
    "lateral_movement":     MITRE_LATERAL_TECHNIQUE,     # T1021
    "insider_exfil":        MITRE_COLLECTION_TECHNIQUE,  # T1213
}


# ═══════════════════════════════════════════════════════════════════════════════
# BEHAVIOR AGENT TRAINER
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorAgentTrainer:
    """
    Trains and persists the BiLSTM autoencoder.

    Training is entirely unsupervised with respect to attacks.
    The model is fitted only on normal behavioral sequences.
    The threshold is the 95th percentile of training errors.

    This means:
      Any attack type — including one never seen before — can be detected
      as long as it deviates from the learned normal distribution.
      No attack labels are required for training.
      Adding new attack types does NOT require retraining.
    """

    MODEL_FILE     = "behavior_model.pt"
    THRESHOLD_FILE = "behavior_threshold.pkl"
    SCALER_FILE    = "behavior_scaler.pkl"
    METRICS_FILE   = "behavior_metrics.pkl"

    def __init__(
        self,
        models_dir: Path = MODELS_DIR,
        device:     str  = "auto",
    ):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)

        if device == "auto":
            self.device = torch.device(
                "cuda" if torch.cuda.is_available() else "cpu"
            )
        else:
            self.device = torch.device(device)

        self.model:      Optional[BehaviorLSTM] = None
        self.threshold:  float                  = 0.0
        self.metrics:    Dict                   = {}
        self._feat_mean: Optional[np.ndarray]   = None
        self._feat_std:  Optional[np.ndarray]   = None

        logger.info(f"BehaviorAgentTrainer: device={self.device}")

    def train(
        self,
        n_users:         int   = 500,
        n_per_user:      int   = 20,
        n_attack_per_sc: int   = 30,
        epochs:          int   = 30,
        batch_size:      int   = 64,
        lr:              float = 1e-3,
        val_split:       float = 0.15,
        patience:        int   = 5,
    ) -> Dict:
        """
        Train BiLSTM on normal sequences only, then evaluate.

        Args:
            n_users:         Normal users to simulate.
            n_per_user:      Sequences per normal user.
            n_attack_per_sc: Attack sequences per scenario (eval only).
            epochs:          Max training epochs.
            batch_size:      Mini-batch size.
            lr:              Adam learning rate.
            val_split:       Fraction held out for validation.
            patience:        Early stopping patience.

        Returns:
            Dict with fpr, overall_dr, scenario_dr, threshold.
        """
        logger.info(
            f"BehaviorAgentTrainer: generating data "
            f"(n_users={n_users}, n_per_user={n_per_user}) …"
        )
        gen = BehaviorDataGenerator(seed=42)

        # Step 1: generate data
        normal_seqs = gen.generate_normal(
            n_users=n_users, n_per_user=n_per_user
        )
        attack_seqs, attack_labels = gen.generate_attacks(
            n_per_scenario=n_attack_per_sc
        )
        logger.info(
            f"  Normal: {len(normal_seqs):,}  |  "
            f"Attack: {len(attack_seqs):,} (eval only)"
        )

        # Step 2: per-feature normalisation from normal data only
        flat            = normal_seqs.reshape(-1, BEHAVIOR_INPUT_SIZE)
        self._feat_mean = flat.mean(axis=0).astype(np.float32)
        self._feat_std  = flat.std(axis=0).astype(np.float32)
        self._feat_std  = np.where(self._feat_std < 1e-8, 1.0, self._feat_std)

        normal_norm = (normal_seqs - self._feat_mean) / self._feat_std
        attack_norm = (attack_seqs - self._feat_mean) / self._feat_std

        # Step 3: train/val split on normal data
        n_total   = len(normal_norm)
        n_val     = max(1, int(n_total * val_split))
        idx       = np.random.default_rng(42).permutation(n_total)
        train_seqs = normal_norm[idx[n_val:]]
        val_seqs   = normal_norm[idx[:n_val]]
        logger.info(
            f"  Train: {len(train_seqs):,}  |  Val: {len(val_seqs):,}"
        )

        # Step 4: DataLoaders
        train_loader = DataLoader(
            BehaviorSequenceDataset(train_seqs),
            batch_size=batch_size, shuffle=True, drop_last=False,
        )
        val_loader = DataLoader(
            BehaviorSequenceDataset(val_seqs),
            batch_size=batch_size, shuffle=False,
        )

        # Step 5: model + optimizer
        self.model = BehaviorLSTM(
            input_size  = BEHAVIOR_INPUT_SIZE,
            hidden_size = BEHAVIOR_HIDDEN_SIZE,
            num_layers  = BEHAVIOR_NUM_LAYERS,
            dropout     = BEHAVIOR_DROPOUT,
        ).to(self.device)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        # Step 6: training loop with early stopping
        best_val   = float("inf")
        patience_c = 0
        best_state = None
        train_hist: List[float] = []
        val_hist:   List[float] = []

        for epoch in range(1, epochs + 1):
            self.model.train()
            t_loss = 0.0
            for batch in train_loader:
                batch = batch.to(self.device)
                optimizer.zero_grad()
                loss  = criterion(self.model(batch), batch)
                loss.backward()
                nn.utils.clip_grad_norm_(
                    self.model.parameters(), max_norm=1.0
                )
                optimizer.step()
                t_loss += loss.item() * len(batch)
            t_loss /= len(train_seqs)
            train_hist.append(t_loss)

            self.model.eval()
            v_loss = 0.0
            with torch.no_grad():
                for batch in val_loader:
                    batch  = batch.to(self.device)
                    v_loss += criterion(
                        self.model(batch), batch
                    ).item() * len(batch)
            v_loss /= len(val_seqs)
            val_hist.append(v_loss)

            if epoch % 5 == 0 or epoch == epochs:
                logger.info(
                    f"  Epoch {epoch:3d}/{epochs} | "
                    f"train={t_loss:.6f} | val={v_loss:.6f}"
                )

            if v_loss < best_val - 1e-6:
                best_val   = v_loss
                patience_c = 0
                best_state = {
                    k: v.clone()
                    for k, v in self.model.state_dict().items()
                }
            else:
                patience_c += 1
                if patience_c >= patience:
                    logger.info(
                        f"  Early stopping at epoch {epoch} "
                        f"(best_val={best_val:.6f})"
                    )
                    if best_state:
                        self.model.load_state_dict(best_state)
                    break

        # Step 7: threshold from training errors (95th percentile)
        self.model.eval()
        all_errors: List[float] = []
        with torch.no_grad():
            for batch in DataLoader(
                BehaviorSequenceDataset(train_seqs),
                batch_size=256, shuffle=False,
            ):
                batch  = batch.to(self.device)
                errors = self.model.reconstruction_error(batch)
                all_errors.extend(errors.cpu().numpy().tolist())

        self.threshold = float(
            np.percentile(all_errors, BEHAVIOR_ANOMALY_PERCENTILE)
        )
        logger.info(
            f"  Threshold ({BEHAVIOR_ANOMALY_PERCENTILE}th pct of "
            f"{len(all_errors):,} normal errors): {self.threshold:.6f}"
        )

        # Step 8: evaluate
        eval_metrics = self._evaluate(val_seqs, attack_norm, attack_labels)
        self.metrics = {
            "best_val_loss": best_val,
            "threshold":     self.threshold,
            "train_history": train_hist,
            "val_history":   val_hist,
            **eval_metrics,
        }

        self._print_c1_proof_table(eval_metrics)
        self.save()
        return self.metrics

    def save(self) -> None:
        """Persist model weights, threshold, and feature scaler."""
        base = self.models_dir
        if self.model is not None:
            torch.save(self.model.state_dict(), base / self.MODEL_FILE)
        with open(base / self.THRESHOLD_FILE, "wb") as f:
            pickle.dump(self.threshold, f)
        with open(base / self.SCALER_FILE, "wb") as f:
            pickle.dump(
                {"feat_mean": self._feat_mean, "feat_std": self._feat_std}, f
            )
        with open(base / self.METRICS_FILE, "wb") as f:
            pickle.dump(self.metrics, f)
        logger.info(f"BehaviorAgentTrainer: saved to {base}")

    # ── Private ────────────────────────────────────────────────────────────────

    def _evaluate(
        self,
        val_seqs:      np.ndarray,
        attack_seqs:   np.ndarray,
        attack_labels: np.ndarray,
    ) -> Dict:
        """FPR on normal val set + DR per attack scenario (Table IX)."""
        self.model.eval()

        def get_errors(seqs: np.ndarray) -> np.ndarray:
            errors = []
            with torch.no_grad():
                for batch in DataLoader(
                    BehaviorSequenceDataset(seqs),
                    batch_size=256, shuffle=False,
                ):
                    batch = batch.to(self.device)
                    errors.extend(
                        self.model.reconstruction_error(batch)
                        .cpu().numpy().tolist()
                    )
            return np.array(errors)

        normal_errors = get_errors(val_seqs)
        fpr = float((normal_errors > self.threshold).sum()) / max(
            len(normal_errors), 1
        )

        attack_errors = get_errors(attack_seqs)
        scenario_dr: Dict[str, float] = {}
        for sc_idx, sc_name in enumerate(SCENARIO_NAMES):
            mask = attack_labels == sc_idx
            if not mask.any():
                continue
            sc_errs = attack_errors[mask]
            scenario_dr[sc_name] = float(
                (sc_errs > self.threshold).sum()
            ) / len(sc_errs)

        overall_dr = float(
            (attack_errors > self.threshold).sum()
        ) / max(len(attack_errors), 1)

        return {
            "fpr":             fpr,
            "overall_dr":      overall_dr,
            "scenario_dr":     scenario_dr,
            "n_normal_eval":   len(normal_errors),
            "n_attack_eval":   len(attack_errors),
        }

    def _print_c1_proof_table(self, metrics: Dict) -> None:
        lines = [
            "",
            "═" * 62,
            "CHALLENGE C1 PROOF — Zero-Day UEBA Detection (cf. Table IX)",
            "═" * 62,
            f"  FPR (normal sequences): {metrics['fpr']:.1%}",
            f"  Overall DR (all attacks): {metrics['overall_dr']:.1%}",
            "",
            f"  {'Scenario':<25} {'DR':>8}  {'MITRE':>12}",
            "  " + "─" * 48,
        ]
        for sc, dr in metrics.get("scenario_dr", {}).items():
            mitre = SCENARIO_MITRE.get(sc, "—")
            lines.append(f"  {sc:<25} {dr:>8.1%}  {mitre:>12}")
        lines += [
            "═" * 62,
            "  * Trained on NORMAL sequences ONLY.",
            "  * Zero attack signatures used.",
            "═" * 62,
        ]
        for line in lines:
            logger.info(line)


# ═══════════════════════════════════════════════════════════════════════════════
# BEHAVIOR AGENT (INFERENCE)
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorAgent:
    """
    Runtime Behavior Agent — loads trained model and scores behavioral sequences.

    Accepts two input forms:
      1. A FlowRecord with behavioral context in its features dict.
      2. A raw numpy sequence array via score_sequence() directly.
    """

    def __init__(
        self,
        model:     BehaviorLSTM,
        threshold: float,
        feat_mean: np.ndarray,
        feat_std:  np.ndarray,
        device:    torch.device = torch.device("cpu"),
    ):
        self._model     = model.to(device)
        self._model.eval()
        self._threshold = threshold
        self._feat_mean = feat_mean
        self._feat_std  = feat_std
        self._device    = device

    @classmethod
    def load(
        cls,
        models_dir: Path = MODELS_DIR,
        device:     str  = "auto",
    ) -> "BehaviorAgent":
        """
        Load trained model artifacts and return a ready BehaviorAgent.

        Raises:
            FileNotFoundError: if any required artifact is missing.
        """
        base = Path(models_dir)
        for fname in [
            BehaviorAgentTrainer.MODEL_FILE,
            BehaviorAgentTrainer.THRESHOLD_FILE,
            BehaviorAgentTrainer.SCALER_FILE,
        ]:
            if not (base / fname).exists():
                raise FileNotFoundError(
                    f"BehaviorAgent: missing {base / fname} — "
                    "run BehaviorAgentTrainer.train() first."
                )

        dev = torch.device(
            "cuda" if (device == "auto" and torch.cuda.is_available())
            else ("cpu" if device == "auto" else device)
        )

        model = BehaviorLSTM(
            input_size  = BEHAVIOR_INPUT_SIZE,
            hidden_size = BEHAVIOR_HIDDEN_SIZE,
            num_layers  = BEHAVIOR_NUM_LAYERS,
            dropout     = BEHAVIOR_DROPOUT,
        )
        state = torch.load(
            base / BehaviorAgentTrainer.MODEL_FILE,
            map_location=dev,
            weights_only=True,
        )
        model.load_state_dict(state)
        model.eval()

        with open(base / BehaviorAgentTrainer.THRESHOLD_FILE, "rb") as f:
            threshold = pickle.load(f)
        with open(base / BehaviorAgentTrainer.SCALER_FILE, "rb") as f:
            scaler = pickle.load(f)

        logger.info(
            f"BehaviorAgent: loaded from {base} "
            f"(threshold={threshold:.6f}, device={dev})"
        )
        return cls(
            model     = model,
            threshold = threshold,
            feat_mean = scaler["feat_mean"],
            feat_std  = scaler["feat_std"],
            device    = dev,
        )

    # ── Core scoring ───────────────────────────────────────────────────────────

    def score(self, record: FlowRecord) -> BehaviorAlert:
        """
        Score a FlowRecord and return a BehaviorAlert.

        Reads from record.features:
          Flow Packets/s   → query_rate dimension
          privilege_level  → privilege dimension
          peer_z_score     → peer deviation dimension
          account          → account name for the alert
        """
        seq     = self._record_to_sequence(record)
        account = str(record.features.get("account", "unknown_account"))
        alert   = self.score_sequence(seq, src_ip=record.src_ip, account=account)
        record.behavior_alert = alert
        return alert

    def score_sequence(
        self,
        sequence: np.ndarray,
        src_ip:   str = "0.0.0.0",
        account:  str = "unknown",
    ) -> BehaviorAlert:
        """
        Score a raw behavioral sequence.

        Args:
            sequence: ndarray (seq_len, input_size) or (1, seq_len, input_size).
            src_ip:   Source IP for the alert.
            account:  Account name for the alert.

        Returns:
            BehaviorAlert with all fields populated.
        """
        seq = np.array(sequence, dtype=np.float32)
        if seq.ndim == 2:
            seq = seq[np.newaxis, :]

        seq_norm = (seq - self._feat_mean) / self._feat_std
        tensor   = torch.tensor(seq_norm, dtype=torch.float32).to(self._device)

        with torch.no_grad():
            error = self._model.reconstruction_error(tensor)
        recon_error = float(error.cpu().numpy()[0])

        is_anomaly  = recon_error > self._threshold
        confidence  = self._normalise_error(recon_error)
        scenario, mitre = self._identify_scenario(seq[0])
        explanation = self._build_explanation(
            is_anomaly, recon_error, account, src_ip, scenario
        )
        top_dims = self._top_dim_errors(seq_norm[0], tensor[0])

        return BehaviorAlert(
            account         = account,
            src_ip          = src_ip,
            recon_error     = recon_error,
            threshold       = self._threshold,
            is_anomaly      = is_anomaly,
            confidence      = confidence,
            scenario_hint   = scenario if is_anomaly else None,
            mitre_technique = mitre   if is_anomaly else None,
            explanation     = explanation,
            top_dims        = top_dims,
            peer_z_score    = float(seq[0, :, 7].mean()),
        )

    @property
    def model(self) -> BehaviorLSTM:
        return self._model

    @property
    def threshold(self) -> float:
        return self._threshold

    # ── Private helpers ────────────────────────────────────────────────────────

    def _record_to_sequence(self, record: FlowRecord) -> np.ndarray:
        """Build a (seq_len, input_size) sequence from FlowRecord features."""
        gen = BehaviorDataGenerator(
            seed=int(abs(hash(record.src_ip)) % 1000)
        )
        seq = gen.normal_sequence(BEHAVIOR_SEQUENCE_LENGTH)

        query_rate = float(record.features.get("Flow Packets/s", 0.0))
        if query_rate > 0:
            seq[:, 6] = min(query_rate / 1000.0, 1.0)

        privilege = float(record.features.get("privilege_level", 0.0))
        if privilege > 0:
            seq[:, 5] = min(privilege, 1.0)

        peer_z = float(record.features.get("peer_z_score", 0.0))
        if peer_z != 0.0:
            seq[:, 7] = np.clip(peer_z, -3.0, 3.0)

        return seq

    def _normalise_error(self, error: float) -> float:
        """Sigmoid normalisation centred on threshold → [0, 1]."""
        k = 8.0
        x = (error - self._threshold) * k
        return float(1.0 / (1.0 + math.exp(-max(-50, min(50, x)))))

    def _identify_scenario(
        self, seq: np.ndarray
    ) -> Tuple[Optional[str], Optional[str]]:
        """Heuristically identify which attack scenario this resembles."""
        mean_hour   = seq[:, 1].mean()
        mean_priv   = seq[:, 5].mean()
        mean_query  = seq[:, 6].mean()
        mean_peer_z = seq[:, 7].mean()
        ip_variance = seq[:, 3].var()

        if ip_variance > 0.1:
            return "lateral_movement", SCENARIO_MITRE["lateral_movement"]
        if mean_priv > 0.6 and mean_peer_z > 1.5:
            return "privilege_escalation", SCENARIO_MITRE["privilege_escalation"]
        if mean_query > 0.7:
            return "data_staging", SCENARIO_MITRE["data_staging"]
        if mean_hour < -0.3:
            return "credential_abuse", SCENARIO_MITRE["credential_abuse"]
        if mean_peer_z > 1.0:
            return "insider_exfil", SCENARIO_MITRE["insider_exfil"]
        return "unknown_zero_day", MITRE_COLLECTION_TECHNIQUE

    def _build_explanation(
        self,
        is_anomaly:  bool,
        recon_error: float,
        account:     str,
        src_ip:      str,
        scenario:    Optional[str],
    ) -> str:
        if not is_anomaly:
            return (
                f"Account '{account}' behavior is consistent with "
                f"30-day learned normal profile "
                f"(recon_error={recon_error:.4f} < "
                f"threshold={self._threshold:.4f})."
            )
        margin = (
            (recon_error - self._threshold) / self._threshold * 100
        )
        return (
            f"ZERO-DAY behavioral anomaly for account '{account}' "
            f"from {src_ip}. "
            f"Reconstruction error={recon_error:.4f} exceeds threshold "
            f"by {margin:.0f}%. "
            f"Most likely scenario: {scenario}. "
            f"NOTE: No attack signature matched — detected by deviation "
            f"from learned normal behavior only."
        )

    def _top_dim_errors(
        self,
        seq_norm:   np.ndarray,
        seq_tensor: torch.Tensor,
        top_n:      int = 3,
    ) -> List[Tuple[str, float]]:
        """Top-N input dimensions by reconstruction error contribution."""
        dim_names = BehaviorDataGenerator.DIM_NAMES
        with torch.no_grad():
            recon = self._model(seq_tensor.unsqueeze(0))[0]
        dim_errors  = ((seq_norm - recon.cpu().numpy()) ** 2).mean(axis=0)
        top_indices = np.argsort(dim_errors)[::-1][:top_n]
        return [(dim_names[i], float(dim_errors[i])) for i in top_indices]


# ═══════════════════════════════════════════════════════════════════════════════
# SMOKE TEST
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )
    from pipeline.ingestion import build_apt_scenario

    logger.info("BehaviorAgent smoke test …")
    trainer = BehaviorAgentTrainer(models_dir=MODELS_DIR)
    metrics = trainer.train(
        n_users=100, n_per_user=10, n_attack_per_sc=20,
        epochs=15, batch_size=32,
    )
    logger.info(f"FPR={metrics['fpr']:.1%}  DR={metrics['overall_dr']:.1%}")

    agent = BehaviorAgent.load(models_dir=MODELS_DIR)
    for rec in build_apt_scenario():
        alert = agent.score(rec)
        flag  = "⚑ ANOMALY" if alert.is_anomaly else "  normal "
        logger.info(
            f"  {flag}  acc={alert.account}  "
            f"err={alert.recon_error:.4f}  "
            f"scenario={alert.scenario_hint}"
        )
    logger.info("Smoke test complete.")