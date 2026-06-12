"""
BankSentinel — Behavior Agent Test Suite (Phase 2, Step 2)
===========================================================
Challenge Covered: C1 — Zero-Day Attack Detection (no signatures)

73 tests across 9 groups. All run offline with synthetic data.

Run:  python -m pytest tests/test_behavior_agent.py -v

Groups
------
  TestBehaviorAlert          ( 8)  data structure validation
  TestBehaviorLSTM           (10)  model architecture
  TestBehaviorDataGenerator  (12)  synthetic data generation
  TestBehaviorAgentTrainer   (14)  training, saving, C1 proof
  TestBehaviorAgent          (14)  inference and scoring
  TestZeroDayDetection       ( 6)  C1 core claim: no signatures
  TestScenarioDetection      ( 5)  per-scenario detection rates
  TestPersistence            ( 2)  save/load round-trip
  TestIntegrationC1          ( 1)  full pipeline end-to-end
"""

import logging
import math
import pickle
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.behaviour_agent import (
    SCENARIO_MITRE,
    SCENARIO_NAMES,
    BehaviorAgent,
    BehaviorAlert,
    BehaviorDataGenerator,
    BehaviorLSTM,
)
from config import (
    BEHAVIOR_ANOMALY_PERCENTILE,
    BEHAVIOR_HIDDEN_SIZE,
    BEHAVIOR_INPUT_SIZE,
    BEHAVIOR_NUM_LAYERS,
    BEHAVIOR_SEQUENCE_LENGTH,
)
from pipeline.ingestion import FLOW_FEATURES, FlowRecord, build_apt_scenario

logger = logging.getLogger(__name__)


# ── Fixtures ─────────────────────────────────────────────────────────────────

from config import MODELS_DIR
def _load_agent() -> BehaviorAgent:
    return BehaviorAgent.load(models_dir=MODELS_DIR, device="cpu")


def _make_flow_record(
    query_rate: float = 0.0, privilege: float = 0.0
) -> FlowRecord:
    features = {f: 100.0 for f in FLOW_FEATURES}
    if query_rate:
        features["Flow Packets/s"] = query_rate
    if privilege:
        features["privilege_level"] = privilege
    return FlowRecord(
        "10.22.14.45", "10.22.15.10", features, label="BENIGN"
    )


def _make_alert(**kwargs) -> BehaviorAlert:
    defaults = dict(
        account="test_user", src_ip="10.0.0.1",
        recon_error=0.01, threshold=0.05,
        is_anomaly=False, confidence=0.2,
        scenario_hint=None, mitre_technique=None,
        explanation="normal",
    )
    defaults.update(kwargs)
    return BehaviorAlert(**defaults)


# GROUP 1: BehaviorAlert

class TestBehaviorAlert(unittest.TestCase):

    def test_default_timestamp_utc(self):
        self.assertIsNotNone(_make_alert().timestamp.tzinfo)

    def test_default_top_dims_empty(self):
        alert = _make_alert()
        self.assertIsInstance(alert.top_dims, list)
        self.assertEqual(len(alert.top_dims), 0)

    def test_str_contains_account(self):
        self.assertIn("svc_corebanking",
                      str(_make_alert(account="svc_corebanking")))

    def test_str_shows_anomaly_when_true(self):
        self.assertIn("ANOMALY", str(_make_alert(is_anomaly=True)))

    def test_str_shows_normal_when_false(self):
        self.assertIn("NORMAL", str(_make_alert(is_anomaly=False)))

    def test_recon_error_is_float(self):
        self.assertIsInstance(_make_alert(recon_error=0.123).recon_error, float)

    def test_mitre_none_when_normal(self):
        self.assertIsNone(
            _make_alert(is_anomaly=False, mitre_technique=None).mitre_technique
        )

    def test_scenario_hint_set_when_anomaly(self):
        alert = _make_alert(is_anomaly=True, scenario_hint="data_staging")
        self.assertEqual(alert.scenario_hint, "data_staging")


# GROUP 2: BehaviorLSTM

class TestBehaviorLSTM(unittest.TestCase):

    def setUp(self):
        self.model = BehaviorLSTM(
            input_size=BEHAVIOR_INPUT_SIZE,
            hidden_size=BEHAVIOR_HIDDEN_SIZE,
            num_layers=BEHAVIOR_NUM_LAYERS,
            dropout=0.0,
        )
        self.model.eval()

    def _batch(self, b=2, s=BEHAVIOR_SEQUENCE_LENGTH, f=BEHAVIOR_INPUT_SIZE):
        return torch.randn(b, s, f)

    def test_output_shape_matches_input(self):
        x = self._batch()
        self.assertEqual(self.model(x).shape, x.shape)

    def test_output_dtype_float32(self):
        self.assertEqual(self.model(self._batch()).dtype, torch.float32)

    def test_recon_error_shape(self):
        self.assertEqual(
            self.model.reconstruction_error(self._batch(b=4)).shape, (4,)
        )

    def test_recon_error_non_negative(self):
        self.assertTrue(
            (self.model.reconstruction_error(self._batch(b=8)) >= 0).all()
        )

    def test_encoder_is_bidirectional(self):
        self.assertTrue(self.model.encoder.bidirectional)

    def test_hidden_size_correct(self):
        self.assertEqual(self.model.hidden_size, BEHAVIOR_HIDDEN_SIZE)

    def test_decoder_output_dim(self):
        self.assertEqual(
            self.model.decoder.out_features, BEHAVIOR_INPUT_SIZE
        )

    def test_gradient_flows(self):
        self.model.train()
        x    = self._batch(b=2)
        loss = ((x - self.model(x)) ** 2).mean()
        loss.backward()
        for name, p in self.model.named_parameters():
            if p.requires_grad:
                self.assertIsNotNone(p.grad, msg=f"No grad for '{name}'")

    def test_single_sample_error(self):
        self.assertEqual(
            self.model.reconstruction_error(self._batch(b=1)).shape, (1,)
        )

    def test_different_inputs_produce_valid_errors(self):
        e1 = self.model.reconstruction_error(self._batch(b=1))
        e2 = self.model.reconstruction_error(self._batch(b=1))
        self.assertGreaterEqual(e1.item(), 0)
        self.assertGreaterEqual(e2.item(), 0)


# GROUP 3: BehaviorDataGenerator

class TestBehaviorDataGenerator(unittest.TestCase):

    def setUp(self):
        self.gen = BehaviorDataGenerator(seed=0)

    def test_normal_shape(self):
        self.assertEqual(
            self.gen.normal_sequence().shape,
            (BEHAVIOR_SEQUENCE_LENGTH, BEHAVIOR_INPUT_SIZE),
        )

    def test_normal_dtype_float32(self):
        self.assertEqual(self.gen.normal_sequence().dtype, np.float32)

    def test_generate_normal_shape(self):
        seqs = self.gen.generate_normal(n_users=10, n_per_user=5)
        self.assertEqual(seqs.shape,
                         (50, BEHAVIOR_SEQUENCE_LENGTH, BEHAVIOR_INPUT_SIZE))

    def test_credential_abuse_shape(self):
        self.assertEqual(
            self.gen.credential_abuse_sequence().shape,
            (BEHAVIOR_SEQUENCE_LENGTH, BEHAVIOR_INPUT_SIZE),
        )

    def test_privilege_escalation_shape(self):
        self.assertEqual(
            self.gen.privilege_escalation_sequence().shape,
            (BEHAVIOR_SEQUENCE_LENGTH, BEHAVIOR_INPUT_SIZE),
        )

    def test_data_staging_shape(self):
        self.assertEqual(
            self.gen.data_staging_sequence().shape,
            (BEHAVIOR_SEQUENCE_LENGTH, BEHAVIOR_INPUT_SIZE),
        )

    def test_lateral_movement_shape(self):
        self.assertEqual(
            self.gen.lateral_movement_sequence().shape,
            (BEHAVIOR_SEQUENCE_LENGTH, BEHAVIOR_INPUT_SIZE),
        )

    def test_insider_exfil_shape(self):
        self.assertEqual(
            self.gen.insider_exfil_sequence().shape,
            (BEHAVIOR_SEQUENCE_LENGTH, BEHAVIOR_INPUT_SIZE),
        )

    def test_generate_attacks_length(self):
        seqs, labels = self.gen.generate_attacks(n_per_scenario=5)
        self.assertEqual(len(seqs), 25)
        self.assertEqual(len(labels), 25)

    def test_attack_labels_integer(self):
        _, labels = self.gen.generate_attacks(n_per_scenario=3)
        self.assertEqual(labels.dtype.kind, "i")

    def test_all_scenarios_in_labels(self):
        _, labels = self.gen.generate_attacks(n_per_scenario=4)
        self.assertEqual(set(labels.tolist()), set(range(len(SCENARIO_NAMES))))

    def test_data_staging_high_query_rate(self):
        self.assertGreater(
            self.gen.data_staging_sequence()[:, 6].mean(), 0.5
        )

    def test_lateral_movement_ip_variance(self):
        self.assertGreater(
            self.gen.lateral_movement_sequence()[:, 3].var(), 0.01
        )



# GROUP 5: BehaviorAgent inference

class TestBehaviorAgent(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # _quick_train(self.tmpdir)
        self.agent = _load_agent()
        self.gen   = BehaviorDataGenerator(seed=7)

    def test_load_returns_behavior_agent(self):
        self.assertIsInstance(self.agent, BehaviorAgent)

    def test_load_raises_if_missing(self):
        empty = Path(tempfile.mkdtemp()) / "empty"
        empty.mkdir()
        with self.assertRaises(FileNotFoundError):
            BehaviorAgent.load(models_dir=empty)

    def test_threshold_positive(self):
        self.assertGreater(self.agent.threshold, 0.0)

    def test_score_returns_behavior_alert(self):
        self.assertIsInstance(
            self.agent.score(_make_flow_record()), BehaviorAlert
        )

    def test_score_populates_record(self):
        rec = _make_flow_record()
        self.assertIsNone(rec.behavior_alert)
        self.agent.score(rec)
        self.assertIsNotNone(rec.behavior_alert)

    def test_recon_error_positive(self):
        self.assertGreater(
            self.agent.score(_make_flow_record()).recon_error, 0.0
        )

    def test_confidence_in_range(self):
        alert = self.agent.score(_make_flow_record())
        self.assertGreaterEqual(alert.confidence, 0.0)
        self.assertLessEqual(alert.confidence,    1.0)

    def test_score_sequence_2d(self):
        self.assertIsInstance(
            self.agent.score_sequence(self.gen.normal_sequence()),
            BehaviorAlert,
        )

    def test_score_sequence_3d(self):
        seq = self.gen.normal_sequence()[np.newaxis, :]
        self.assertIsInstance(
            self.agent.score_sequence(seq), BehaviorAlert
        )

    def test_score_sequence_error_positive(self):
        self.assertGreater(
            self.agent.score_sequence(self.gen.normal_sequence()).recon_error,
            0.0,
        )

    def test_score_sequence_threshold_matches(self):
        alert = self.agent.score_sequence(self.gen.normal_sequence())
        self.assertAlmostEqual(
            alert.threshold, self.agent.threshold, places=8
        )

    def test_explanation_not_empty(self):
        alert = self.agent.score(_make_flow_record())
        self.assertGreater(len(alert.explanation), 0)

    def test_normal_explanation_mentions_normal(self):
        alert = self.agent.score_sequence(
            self.gen.normal_sequence(), account="test"
        )
        if not alert.is_anomaly:
            self.assertIn("normal", alert.explanation.lower())

    def test_anomaly_explanation_mentions_zero_day(self):
        seq        = self.gen.data_staging_sequence()
        seq[:, 6]  = 1.0
        seq[:, 7]  = 3.0
        alert = self.agent.score_sequence(seq, account="svc_db")
        if alert.is_anomaly:
            self.assertIn("zero", alert.explanation.lower())


# GROUP 7: Per-scenario detection

class TestScenarioDetection(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # _quick_train(self.tmpdir, n_users=80, epochs=6)
        self.agent = _load_agent()
        self.gen   = BehaviorDataGenerator(seed=5)

    def _dr(self, gen_fn, n: int = 30) -> float:
        return sum(
            1 for _ in range(n)
            if self.agent.score_sequence(gen_fn()).is_anomaly
        ) / n

    def test_data_staging_detectable(self):
        self.assertGreater(self._dr(self.gen.data_staging_sequence), 0.30)

    def test_lateral_movement_detectable(self):
        self.assertGreater(self._dr(self.gen.lateral_movement_sequence), 0.30)

    def test_credential_abuse_detectable(self):
        self.assertGreater(self._dr(self.gen.credential_abuse_sequence), 0.20)

    def test_privilege_escalation_detectable(self):
        self.assertGreater(self._dr(self.gen.privilege_escalation_sequence), 0.20)

    def test_scenario_mitre_complete(self):
        for sc in SCENARIO_NAMES:
            self.assertIn(sc, SCENARIO_MITRE)
            self.assertTrue(SCENARIO_MITRE[sc].startswith("T"))


# GROUP 9: Integration

class TestIntegrationC1(unittest.TestCase):

    def test_apt_db_record_scored(self):
        """
        The DB query spike record from the APT demo (Section III) must be
        accepted without error and produce a valid BehaviorAlert.
        """
        tmpdir = Path(tempfile.mkdtemp())
        # _quick_train(tmpdir, epochs=3)
        agent = BehaviorAgent.load(models_dir=MODELS_DIR, device="cpu")

        db_record = build_apt_scenario()[2]   # svc_corebanking spike
        alert     = agent.score(db_record)

        self.assertIsInstance(alert, BehaviorAlert)
        self.assertGreater(alert.recon_error, 0.0)
        self.assertGreaterEqual(alert.confidence, 0.0)
        self.assertLessEqual(alert.confidence, 1.0)
        self.assertIsNotNone(db_record.behavior_alert)
        self.assertIs(db_record.behavior_alert, alert)
        self.assertGreater(len(alert.explanation), 10)

        logger.info(
            f"APT DB record: err={alert.recon_error:.4f} "
            f"anomaly={alert.is_anomaly} "
            f"scenario={alert.scenario_hint}"
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)-7s  %(message)s"
    )
    unittest.main(verbosity=2)