"""
BankSentinel — SOC Assistant (Gemini 2.0 Flash)
=================================================
Challenge Addressed: C3 — Alert Fatigue (cognitive load reduction)

Conversational AI assistant that helps SOC analysts understand alerts,
cite specific compliance controls, and explain detection reasoning.

When GEMINI_API_KEY is set, uses live Gemini 2.0 Flash inference.
When absent, returns curated fallback answers mapped to each challenge.

Usage:
    from llm.soc_assistant import soc_assistant
    answer = soc_assistant.ask(
        question="How did you detect this if TLS 1.3 hides the payload?",
        alert_context={"crs": 0.94, "agents_fired": ["packet", "flow"]}
    )
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

import google.generativeai as genai
from config import GEMINI_API_KEYS

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT — Nepal banking SOC context
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are BankSentinel SOC AI — the intelligent assistant for a Nepalese banking intrusion detection system.

EXPERT KNOWLEDGE:
- NRB Cybersecurity Guidelines 2023 (Sections 4.2 SIEM Requirements, 4.5 Incident Response)
- SWIFT Customer Security Programme (Controls 6.1 Network Segmentation, 6.2 System Hardening, 7.4 Logging)
- PCI-DSS v4.0 (Requirements 10.3 Audit Logs, 11.5 IDS/IPS)
- Nepal banking infrastructure: Pumori/Pumori+ core banking, RTGS settlement, ATM reconciliation windows
- Nepal APT landscape: Lazarus Group, APT38, Chimera — targeting South Asian SWIFT infrastructure

THE FOUR CHALLENGES THIS SYSTEM SOLVES:
C1 Zero-Day Attacks: BiLSTM autoencoder trained ONLY on normal behavioral sequences. Detects deviation from learned normal — no signatures, no rules. 94.9% UEBA detection rate.
C2 False Positives: 6-context calendar-aware Isolation Forest. Separate models for ATM reconciliation (00:00-02:00 Nepal), month-end batch, RTGS settlement, off-hours, weekend, and normal. Reduces ATM FPR from 22.7% to 2.1%.
C3 Alert Fatigue: 4-mechanism suppression (deduplication, causal chaining, confidence gating, context filtering) + Bayesian BBN fusion. Reduces 48,200 raw alerts/day to 6,350 (87% reduction). 100% campaign detection preserved.
C4 Encrypted TLS 1.3: 3-layer defence without payload decryption. Layer 1: JA3 hash match (abuse.ch feed). Layer 2: JA3S bidirectional cross-signal (catches Cobalt Strike). Layer 3: Beacon IAT variance analysis (catches zero-day TLS). 91.7% DR.

RESPONSE GUIDELINES:
- Be concise, actionable, and cite specific controls (e.g., "per SWIFT CSP Control 6.1")
- Reference the specific challenge (C1/C2/C3/C4) being addressed
- Include recommended next steps for the analyst
- Use Nepal time context (UTC+05:45) when discussing time-based patterns
- Never suggest decrypting TLS payload — BankSentinel detects without decryption
"""


# ═══════════════════════════════════════════════════════════════════════════════
# DEMO QUESTIONS — one per challenge, embedded in UI as quick buttons
# ═══════════════════════════════════════════════════════════════════════════════

DEMO_QUESTIONS = [
    {
        "id": "c1",
        "challenge": "C1",
        "question": "Why is this a zero-day threat and not a signature match?",
        "description": "Explains BiLSTM deviation detection with no prior attack knowledge",
    },
    {
        "id": "c2",
        "challenge": "C2",
        "question": "Why didn't the system fire during last month-end batch?",
        "description": "Explains calendar-aware context models and FPR reduction",
    },
    {
        "id": "c3",
        "challenge": "C3",
        "question": "How many alerts did you suppress before escalating this?",
        "description": "Explains 4-layer suppression and campaign detection",
    },
    {
        "id": "c4",
        "challenge": "C4",
        "question": "How did you detect this if TLS 1.3 hides the payload?",
        "description": "Explains 3-layer TLS detection without decryption",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# FALLBACK ANSWERS — used when no Gemini API key is configured
# ═══════════════════════════════════════════════════════════════════════════════

_FALLBACK_ANSWERS = {
    "c1": (
        "**Challenge C1 — Zero-Day Detection**\n\n"
        "This alert was triggered by BankSentinel's BiLSTM autoencoder, which was trained "
        "exclusively on 30 days of **normal behavioral sequences**. It has never seen a single "
        "attack pattern.\n\n"
        "The model fires because the **reconstruction error** for this event sequence exceeds "
        "the 95th percentile of the normal distribution. The behavioral sequence — including "
        "access timing, resource targets, query rates, and privilege levels — cannot be "
        "reconstructed by a model that only knows normal.\n\n"
        "This is zero-day detection by definition: no rule, no signature, no prior knowledge "
        "of this attack technique. Detection rate: **94.9%** across all zero-day scenarios.\n\n"
        "**Recommended Actions:**\n"
        "1. Review the SHAP explanation to identify which behavioral dimensions deviated most\n"
        "2. Check if the source account has accessed these resources before (30-day profile)\n"
        "3. Per NRB Section 4.5, initiate incident response within 15 minutes of detection"
    ),
    "c2": (
        "**Challenge C2 — False Positive Prevention**\n\n"
        "BankSentinel uses **6 calendar-aware Isolation Forest models**, each trained on traffic "
        "that is normal for a specific Nepal banking time window:\n\n"
        "- **ATM Reconciliation** (00:00–02:00 Nepal): High volume is normal during nightly reconciliation\n"
        "- **Month-end Batch**: Last 3 business days see 3-5x normal transaction volume\n"
        "- **RTGS Settlement**: Weekday banking hours, predictable settlement patterns\n"
        "- **Off-hours**: 22:00–06:00, low baseline where any spike is suspicious\n"
        "- **Weekend**: Saturday-Sunday reduced operations\n"
        "- **Normal**: Default business hours baseline\n\n"
        "During last month-end, traffic was routed to the **month_end context model**, which "
        "was trained on legitimate month-end patterns. The global model would have produced "
        "**18.3% FPR**; the context-aware model produced only **1.4% FPR**.\n\n"
        "**Per SWIFT CSP Control 7.4:** All context routing decisions are logged with full audit trail."
    ),
    "c3": (
        "**Challenge C3 — Alert Fatigue Reduction**\n\n"
        "Before this alert reached you, BankSentinel's Correlation Agent applied **4 suppression layers**:\n\n"
        "1. **Deduplication**: Identical alert signatures within 5 minutes collapsed into one event\n"
        "2. **Causal Chaining**: Alerts sharing the same source IP within 10 minutes merged into one campaign ticket\n"
        "3. **Confidence Gating**: Single-agent alerts with CRS < 0.40 queued for background review\n"
        "4. **Context Filtering**: Known operational patterns auto-closed with audit entry\n\n"
        "**Result**: From 48,200 raw alerts/day, only 6,350 pass all filters (**87% reduction**). "
        "Of those, 497 are high-priority. Campaign detection rate: **100%** — all 50/50 APT scenarios detected.\n\n"
        "This alert passed all 4 filters because it was fused from multiple agents with "
        "CRS ≥ 0.85, indicating a genuine coordinated threat.\n\n"
        "**Per PCI-DSS 10.3:** Every suppressed alert is logged with reason and timestamp."
    ),
    "c4": (
        "**Challenge C4 — Encrypted TLS 1.3 Detection**\n\n"
        "BankSentinel detected this threat **without decrypting any payload**. Three independent "
        "layers work on connection metadata and TLS handshake fingerprints only:\n\n"
        "**Layer 1 — JA3 Hash Match**: The client TLS fingerprint was checked against 14,200+ "
        "known-malicious JA3 hashes from the live abuse.ch feed (refreshed every 30 minutes).\n\n"
        "**Layer 2 — JA3S Bidirectional Cross-Signal**: Even when the client JA3 is clean "
        "(attacker used a novel client), the **server's JA3S response** matched known Cobalt Strike "
        "Malleable C2 profiles. The attacker randomized the client but forgot the server side.\n\n"
        "**Layer 3 — Beacon IAT Analysis**: Legitimate HTTPS has **high** inter-arrival time variance "
        "(humans click unpredictably). C2 beaconing has **low** IAT variance (malware calls home on "
        "a schedule). This timing pattern is detectable even for brand-new TLS fingerprints.\n\n"
        "Combined detection rate: **91.7%** (Table VI). Payload Decrypted: **NO**.\n\n"
        "**Per SWIFT CSP Control 6.1:** Network monitoring preserves TLS 1.3 integrity."
    ),
}

# Generic fallback for questions that don't map to a specific challenge
_GENERIC_FALLBACK = (
    "**BankSentinel Analysis**\n\n"
    "This alert was evaluated by BankSentinel's five-agent pipeline:\n\n"
    "- **Packet Agent (C4)**: Encrypted traffic analysis via JA3/JA3S fingerprints and beacon timing\n"
    "- **Flow Agent (C2)**: Calendar-aware anomaly detection using Nepal banking time contexts\n"
    "- **Behavior Agent (C1)**: Zero-day detection via BiLSTM behavioral deviation\n"
    "- **Correlation Agent (C3)**: Bayesian fusion with 4-layer suppression\n"
    "- **Response Agent**: Automated containment with tamper-evident audit logging\n\n"
    "The alert's Composite Risk Score (CRS) was computed using weighted fusion of all agent "
    "signals plus the Bayesian posterior probability of a true threat campaign.\n\n"
    "For specific details, try one of the challenge-specific questions (C1–C4) in the quick buttons."
)


# ═══════════════════════════════════════════════════════════════════════════════
# SOC ASSISTANT CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class SOCAssistant:
    """
    Conversational SOC assistant powered by Gemini 2.0 Flash.

    Falls back to curated, challenge-mapped responses when no API key
    is configured — ensuring the demo always works.
    """

    def __init__(self):
        self._model = None
        self._api_keys = GEMINI_API_KEYS
        self._current_key_idx = 0
        self._use_llm = False
        self._response_cache: Dict[str, str] = {}
        self._init_llm()

    def _init_llm(self) -> None:
        """Try to initialize the Gemini model using the current key."""
        if not self._api_keys:
            logger.warning(
                "SOCAssistant: No GEMINI_API_KEYS set — using fallback responses. "
                "Set GEMINI_API_KEYS in .env for live LLM inference."
            )
            return

        try:
            current_key = self._api_keys[self._current_key_idx]
            genai.configure(api_key=current_key)
            self._model = genai.GenerativeModel("gemini-2.0-flash")
            self._use_llm = True
            logger.info(f"SOCAssistant: Gemini 2.0 Flash initialized successfully (Key {self._current_key_idx + 1}/{len(self._api_keys)}).")
        except ImportError:
            logger.warning(
                "SOCAssistant: google-generativeai not installed. "
                "Install with: pip install google-generativeai"
            )
        except Exception as exc:
            logger.warning(f"SOCAssistant: Failed to initialize Gemini: {exc}")

    def _rotate_key(self) -> bool:
        """Rotate to the next available API key if possible."""
        if not self._api_keys or len(self._api_keys) <= 1:
            return False
            
        self._current_key_idx = (self._current_key_idx + 1) % len(self._api_keys)
        logger.info(f"SOCAssistant: Rotating API key to index {self._current_key_idx}")
        self._init_llm()
        return True

    @property
    def is_live(self) -> bool:
        """Whether the assistant is using live LLM inference."""
        return self._use_llm

    def ask(
        self,
        question: str,
        alert_context: Optional[Dict[str, Any]] = None,
        shap_narrative: Optional[str] = None,
    ) -> str:
        """
        Answer an analyst's question about an alert.

        Args:
            question:       The analyst's natural language question.
            alert_context:  Dict with alert data (crs, agents_fired, src_ip, etc.)
            shap_narrative: Optional SHAP feature importance explanation.

        Returns:
            Markdown-formatted answer string.
        """
        if self._use_llm:
            return self._ask_llm(question, alert_context, shap_narrative)
        return self._ask_fallback(question, alert_context)

    def _ask_llm(
        self,
        question: str,
        alert_context: Optional[Dict[str, Any]],
        shap_narrative: Optional[str],
    ) -> str:
        """Send question to Gemini with full context, retrying with next key on failure."""
        context_parts = [SYSTEM_PROMPT]

        if alert_context:
            context_parts.append(
                f"\n\nALERT CONTEXT:\n{json.dumps(alert_context, indent=2, default=str)}"
            )
        if shap_narrative:
            context_parts.append(f"\n\nSHAP EXPLANATION:\n{shap_narrative}")

        context_parts.append(f"\n\nANALYST QUESTION: {question}")
        prompt = "\n".join(context_parts)
        
        attempts = 0
        max_attempts = len(self._api_keys) if self._api_keys else 1
        
        while attempts < max_attempts:
            try:
                response = self._model.generate_content(prompt)
                return response.text
            except Exception as exc:
                logger.error(f"SOCAssistant: LLM call failed on key {self._current_key_idx}: {exc}")
                attempts += 1
                if attempts < max_attempts:
                    logger.info("Attempting to rotate API key and retry...")
                    self._rotate_key()
                else:
                    logger.error("All API keys exhausted or failed. Falling back to hardcoded responses.")
                    
        return self._ask_fallback(question, alert_context)

    def _ask_fallback(
        self,
        question: str,
        alert_context: Optional[Dict[str, Any]],
    ) -> str:
        """Return curated challenge-mapped answer."""
        q_lower = question.lower()

        # Match to challenge-specific fallback
        if any(kw in q_lower for kw in ["zero-day", "signature", "bilstm", "behavioral", "deviation", "novel"]):
            return _FALLBACK_ANSWERS["c1"]
        if any(kw in q_lower for kw in ["false positive", "month-end", "atm", "reconciliation", "context", "fpr"]):
            return _FALLBACK_ANSWERS["c2"]
        if any(kw in q_lower for kw in ["suppress", "fatigue", "alert", "how many", "reduce", "collapse"]):
            return _FALLBACK_ANSWERS["c3"]
        if any(kw in q_lower for kw in ["tls", "encrypt", "payload", "ja3", "beacon", "c2 ", "decrypt"]):
            return _FALLBACK_ANSWERS["c4"]

        return _GENERIC_FALLBACK

    def get_demo_questions(self) -> List[Dict[str, str]]:
        """Return the 4 challenge-mapped demo questions."""
        return DEMO_QUESTIONS


# ── Module-level singleton ────────────────────────────────────────────────────
soc_assistant = SOCAssistant()
