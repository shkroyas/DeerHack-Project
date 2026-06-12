"""
BankSentinel — SOC Assistant API Routes
========================================
POST /soc/ask            — Ask the SOC assistant a question
GET  /soc/demo-questions — Get the 4 challenge-mapped quick questions
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/soc", tags=["SOC Assistant"])


# ── Request / Response Models ─────────────────────────────────────────────────

class SOCQuestionRequest(BaseModel):
    """Request body for asking the SOC assistant."""
    question: str = Field(
        ...,
        min_length=3,
        max_length=2000,
        description="Natural language question from the analyst",
        examples=["How did you detect this if TLS 1.3 hides the payload?"],
    )
    alert_context: Optional[Dict[str, Any]] = Field(
        None,
        description="Alert data for context (crs, agents_fired, src_ip, etc.)",
    )
    shap_narrative: Optional[str] = Field(
        None,
        description="SHAP feature importance explanation text",
    )


class SOCAnswerResponse(BaseModel):
    """Response from the SOC assistant."""
    answer: str
    is_live_llm: bool = Field(
        description="True if answer came from live Gemini, False if fallback"
    )
    challenge: Optional[str] = Field(
        None,
        description="Primary challenge addressed (C1/C2/C3/C4)",
    )


class DemoQuestion(BaseModel):
    """A challenge-mapped demo question."""
    id: str
    challenge: str
    question: str
    description: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/ask", response_model=SOCAnswerResponse)
def soc_ask(req: SOCQuestionRequest):
    """
    Ask the BankSentinel SOC assistant a question about an alert.

    The assistant uses Nepal banking context, NRB/SWIFT/PCI-DSS regulations,
    and the specific alert data to generate an actionable response.

    When GEMINI_API_KEY is configured, uses live Gemini 2.0 Flash inference.
    Otherwise, returns curated challenge-specific fallback responses.
    """
    try:
        from llm.soc_assistant import soc_assistant

        answer = soc_assistant.ask(
            question=req.question,
            alert_context=req.alert_context,
            shap_narrative=req.shap_narrative,
        )

        # Detect which challenge was primarily addressed
        q_lower = req.question.lower()
        challenge = None
        if any(kw in q_lower for kw in ["zero-day", "signature", "bilstm", "deviation"]):
            challenge = "C1"
        elif any(kw in q_lower for kw in ["false positive", "month-end", "atm", "fpr"]):
            challenge = "C2"
        elif any(kw in q_lower for kw in ["suppress", "fatigue", "alert", "reduce"]):
            challenge = "C3"
        elif any(kw in q_lower for kw in ["tls", "encrypt", "payload", "ja3", "beacon"]):
            challenge = "C4"

        return SOCAnswerResponse(
            answer=answer,
            is_live_llm=soc_assistant.is_live,
            challenge=challenge,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"SOC assistant error: {exc}",
        )


@router.get("/demo-questions", response_model=List[DemoQuestion])
def soc_demo_questions():
    """
    Return the 4 challenge-mapped demo questions.

    These are displayed as quick-action buttons in the SOC chat UI,
    letting judges test any challenge with one click.
    """
    from llm.soc_assistant import soc_assistant
    return [DemoQuestion(**q) for q in soc_assistant.get_demo_questions()]
