"""
BankSentinel — Pipeline Endpoints
===================================
Full end-to-end pipeline execution.

POST /pipeline/run      — all 5 agents on one flow
POST /pipeline/apt-demo — built-in 3-record APT attack scenario
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import (
    BehaviorAlertResponse,
    CorrelationResultResponse,
    FlowAlertResponse,
    FlowRecordRequest,
    PacketAlertResponse,
    PipelineResponse,
    ResponseActionResponse,
)
from api.utils import build_flow_record

router = APIRouter(prefix="/pipeline", tags=["Pipeline"])


def _run_pipeline_on_record(record, reg: AgentRegistry) -> PipelineResponse:
    """
    Internal helper — run every available agent on a single FlowRecord
    and build the composite PipelineResponse.
    """
    pkt_resp: Optional[PacketAlertResponse] = None
    flow_resp: Optional[FlowAlertResponse] = None
    beh_resp: Optional[BehaviorAlertResponse] = None
    corr_resp: Optional[CorrelationResultResponse] = None
    resp_resp: Optional[ResponseActionResponse] = None

    # ── Packet Agent ──────────────────────────────────────────────────
    if reg.packet_agent is not None:
        alert = reg.packet_agent.score(record)
        pkt_resp = PacketAlertResponse(
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            dst_port=alert.dst_port,
            ja3_hash=alert.ja3_hash,
            ja3s_hash=alert.ja3s_hash,
            confidence=alert.confidence,
            is_threat=alert.is_threat,
            active_layers=alert.active_layers,
            layer_scores=alert.layer_scores,
            malware_family=alert.malware_family,
            mitre_technique=alert.mitre_technique,
            explanation=alert.explanation,
            ja3_feed_age=alert.ja3_feed_age,
            timestamp=alert.timestamp,
        )

    # ── Flow Agent ────────────────────────────────────────────────────
    if reg.flow_agent is not None:
        alert = reg.flow_agent.score(record)
        flow_resp = FlowAlertResponse(
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            regime=alert.regime,
            anomaly_score=alert.anomaly_score,
            is_anomaly=alert.is_anomaly,
            confidence=alert.confidence,
            mitre_technique=alert.mitre_technique,
            explanation=alert.explanation,
            top_features=[list(t) for t in alert.top_features],
            timestamp=alert.timestamp,
            global_score=alert.global_score,
            context_fpr=alert.context_fpr,
            global_fpr=alert.global_fpr,
            fpr_reduction=alert.fpr_reduction,
        )

    # ── Behavior Agent ────────────────────────────────────────────────
    if reg.behavior_agent is not None:
        alert = reg.behavior_agent.score(record)
        beh_resp = BehaviorAlertResponse(
            account=alert.account,
            src_ip=alert.src_ip,
            recon_error=alert.recon_error,
            threshold=alert.threshold,
            is_anomaly=alert.is_anomaly,
            confidence=alert.confidence,
            scenario_hint=alert.scenario_hint,
            mitre_technique=alert.mitre_technique,
            explanation=alert.explanation,
            top_dims=[list(t) for t in alert.top_dims],
            peer_z_score=alert.peer_z_score,
            timestamp=alert.timestamp,
        )

    # ── Correlation Agent ─────────────────────────────────────────────
    if reg.correlation_agent is not None:
        result = reg.correlation_agent.correlate(record)
        corr_resp = CorrelationResultResponse(
            record_id=result.record_id,
            src_ip=result.src_ip,
            dst_ip=result.dst_ip,
            crs=result.crs,
            bbn_posterior=result.bbn_posterior,
            priority=result.priority,
            is_suppressed=result.is_suppressed,
            suppression_reason=result.suppression_reason,
            agent_scores=result.agent_scores,
            agents_fired=result.agents_fired,
            campaign_ticket_id=result.campaign_ticket_id,
            dedup_count=result.dedup_count,
            explanation=result.explanation,
            timestamp=result.timestamp,
        )

        # Broadcast to WebSocket if CRS > 0
        if result.crs > 0:
            import asyncio
            from api.routes.websocket import broadcast_alert
            alert_data = corr_resp.model_dump(mode="json")
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(broadcast_alert(alert_data))
            except RuntimeError:
                pass # Not in an async context, gracefully ignore or handle

        # ── Response Agent (only for CRITICAL, non-suppressed) ────────
        if (
            reg.response_agent is not None
            and not result.is_suppressed
            and result.priority == "CRITICAL"
        ):
            resp_result = reg.response_agent.execute(result)
            resp_resp = ResponseActionResponse(
                status=resp_result["status"],
                actions=resp_result["actions"],
            )

    return PipelineResponse(
        packet_alert=pkt_resp,
        flow_alert=flow_resp,
        behavior_alert=beh_resp,
        correlation_result=corr_resp,
        response_actions=resp_resp,
    )


@router.post("/run", response_model=PipelineResponse)
def pipeline_run(
    req: FlowRecordRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Full end-to-end pipeline for a single flow.

    Runs **all 5 agents** in sequence:

    1. **Packet Agent** (C4) — encrypted traffic detection
    2. **Flow Agent** (C2) — context-aware anomaly detection
    3. **Behavior Agent** (C1) — zero-day behavioral detection
    4. **Correlation Agent** (C3) — BBN fusion + suppression
    5. **Response Agent** — containment (only if CRITICAL)

    Returns detailed results from every agent that was available.
    """
    record = build_flow_record(req)
    return _run_pipeline_on_record(record, reg)


@router.post("/apt-demo", response_model=List[PipelineResponse])
def pipeline_apt_demo(
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Run the built-in **APT attack scenario** through the full pipeline.

    No input required — uses ``build_apt_scenario()`` to generate
    three FlowRecords representing a coordinated APT campaign:

    - **Record 0** — C2 TLS beacon (Cobalt Strike JA3 fingerprint)
    - **Record 1** — SWIFT subnet lateral movement
    - **Record 2** — Core banking DB query spike (zero-day pattern)

    Returns three ``PipelineResponse`` objects with every agent's
    detailed analysis and the Correlation Agent's fused verdict.
    """
    from pipeline.ingestion import build_apt_scenario

    # Inject Cobalt Strike JA3 into the threat DB so the demo works
    # even if the live abuse.ch feed rotated it out
    if reg.threat_engine is not None:
        reg.threat_engine._ja3_db[
            "0b32309a26951912be7dba376398abc3"
        ] = "CobaltStrike"

    apt_records = build_apt_scenario()
    return [_run_pipeline_on_record(rec, reg) for rec in apt_records]
