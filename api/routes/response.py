"""
BankSentinel — Response Agent & Audit Endpoints
=================================================
POST /respond      — execute containment actions
GET  /audit/verify — verify immutable SHA-256 hash chain
GET  /audit/logs   — retrieve recent audit log entries
"""

import sqlite3
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query

from api.dependencies import AgentRegistry, get_registry
from api.schemas import (
    AuditLogEntry,
    AuditVerifyResponse,
    CorrelationResultInput,
    ResponseActionResponse,
)

router = APIRouter(tags=["Response & Audit"])


@router.post("/respond", response_model=ResponseActionResponse)
def execute_response(
    req: CorrelationResultInput,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Execute automated containment based on a correlation result.

    If CRS ≥ 0.85 and the alert is not suppressed, the Response Agent:

    1. **Quarantines** the source host via NAC/EDR (<500ms)
    2. **Blocks** the destination IP at the edge firewall
    3. **Exports** a STIX 2.1 indicator bundle
    4. **Generates** an NRB compliance PDF report
    5. **Logs** the action to the immutable audit chain

    For lower-priority or suppressed alerts, only an audit log entry
    is created.
    """
    if reg.response_agent is None:
        raise HTTPException(
            status_code=503,
            detail="ResponseAgent not available.",
        )

    # Reconstruct a CorrelationResult from the input
    from datetime import datetime, timezone
    from agents.correlation_agent import CorrelationResult

    corr_result = CorrelationResult(
        record_id=req.record_id,
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        crs=req.crs,
        bbn_posterior=req.bbn_posterior,
        priority=req.priority,
        is_suppressed=req.is_suppressed,
        suppression_reason=req.suppression_reason,
        agent_scores=req.agent_scores,
        agents_fired=req.agents_fired,
        campaign_ticket_id=req.campaign_ticket_id,
        dedup_count=req.dedup_count,
        explanation=req.explanation,
        timestamp=req.timestamp or datetime.now(timezone.utc),
    )

    result = reg.response_agent.execute(corr_result)

    return ResponseActionResponse(
        status=result["status"],
        actions=result["actions"],
    )


@router.get("/audit/verify", response_model=AuditVerifyResponse)
def verify_audit_chain(
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Verify the immutable SHA-256 audit hash chain.

    Recalculates H_n = SHA-256(H_{n-1} || action || timestamp)
    for every row in ``forensics/audit.db``.

    Returns ``is_valid=true`` if the chain is intact, or
    ``tampered_at`` with the timestamp of the first broken link.
    """
    if reg.response_agent is None:
        raise HTTPException(
            status_code=503,
            detail="ResponseAgent not available.",
        )

    is_valid, failed_ts = reg.response_agent.verify_chain()
    return AuditVerifyResponse(
        is_valid=is_valid,
        tampered_at=failed_ts,
    )


@router.get("/audit/logs", response_model=List[AuditLogEntry])
def get_audit_logs(
    limit: int = Query(50, ge=1, le=500, description="Max entries to return"),
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Retrieve recent audit log entries from the SQLite database.

    Returns the most recent ``limit`` entries, ordered newest first.
    """
    if reg.response_agent is None:
        raise HTTPException(
            status_code=503,
            detail="ResponseAgent not available.",
        )

    try:
        with sqlite3.connect(reg.response_agent.db_path) as db:
            rows = db.execute(
                "SELECT ts, action, hash, status "
                "FROM audit_log ORDER BY ts DESC LIMIT ?",
                [limit],
            ).fetchall()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read audit log: {exc}",
        )

    return [
        AuditLogEntry(
            timestamp=row[0],
            action=row[1],
            hash=row[2],
            status=row[3],
        )
        for row in rows
    ]
