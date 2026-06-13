import asyncio
import random
import time
import logging
from typing import Optional

from config import FLOW_FEATURES
from pipeline.ingestion import FlowRecord

logger = logging.getLogger(__name__)

# Global flag to control the simulator
_SIMULATOR_RUNNING = False
_SIMULATOR_TASK: Optional[asyncio.Task] = None

def _make_random_benign_record() -> FlowRecord:
    """Generate a random benign flow record for the simulator."""
    src_ips = ["10.22.14.45", "10.22.15.50", "10.22.18.11", "10.22.16.10"]
    dst_ips = ["10.22.14.1", "10.22.15.10", "10.22.18.1", "10.22.16.1", "8.8.8.8"]
    return FlowRecord(
        src_ip=random.choice(src_ips),
        dst_ip=random.choice(dst_ips),
        features={f: random.uniform(10, 500) for f in FLOW_FEATURES},
        label="BENIGN",
        regime="normal",
        src_port=random.randint(1024, 65535),
        dst_port=random.choice([80, 443, 53, 3389, 1521]),
    )

def _make_random_anomaly_record(reg) -> FlowRecord:
    """Generate a random low-severity anomaly or live threat feed match."""
    dst_ip = "203.0.113.5"
    
    # Randomly select a real C2 IP from the live threat feed if available
    if reg and reg.threat_engine is not None and reg.threat_engine._c2_ips:
        dst_ip = random.choice(list(reg.threat_engine._c2_ips))
        
    rec = FlowRecord(
        src_ip="10.22.14.45",
        dst_ip=dst_ip,
        features={f: random.uniform(1000, 5000) for f in FLOW_FEATURES},
        label="ANOMALY",
        regime="normal",
        src_port=random.randint(1024, 65535),
        dst_port=4444,
    )
    
    # 50% chance to also inject a live malicious JA3 hash to trigger C4 Layer 1
    if reg and reg.threat_engine is not None and reg.threat_engine._ja3_db and random.random() > 0.5:
        rec.ja3_hash = random.choice(list(reg.threat_engine._ja3_db.keys()))
        rec.label = "APT-C2"
        rec.tls_version = 771
        
    return rec

async def traffic_simulator():
    """
    Background task that generates synthetic traffic.
    Pushes benign traffic continuously, and an occasional anomaly.
    """
    global _SIMULATOR_RUNNING
    
    from api.dependencies import get_registry
    from api.routes.pipeline import _run_pipeline_on_record
    import asyncio

    reg = get_registry()
    loop = asyncio.get_event_loop()
    logger.info("Traffic simulator started.")
    
    ticks = 0
    while _SIMULATOR_RUNNING:
        try:
            # Generate 1 to 3 benign records
            for _ in range(random.randint(1, 3)):
                rec = _make_random_benign_record()
                _run_pipeline_on_record(rec, reg, loop, source="simulator")
            
            # Every ~15 seconds inject ALL severities
            if ticks % 15 == 0 and ticks > 0:
                from pipeline.ingestion import build_apt_scenario
                if reg.threat_engine is not None:
                    reg.threat_engine._ja3_db[
                        "0b32309a26951912be7dba376398abc3"
                    ] = "CobaltStrike"
                
                # Collect all demo records (CRITICAL, HIGH, MEDIUM, LOW)
                apt_records = build_apt_scenario()
                rec_anomaly = _make_random_anomaly_record(reg)
                
                all_demo_records = apt_records + [rec_anomaly]
                
                # Shuffle so they appear in random order instead of serially
                random.shuffle(all_demo_records)
                
                for rec in all_demo_records:
                    _run_pipeline_on_record(rec, reg, loop, source="simulator")
                    await asyncio.sleep(0.5)
            
            ticks += 1
            await asyncio.sleep(1.0)
        except Exception as e:
            logger.error(f"Traffic simulator error: {e}")
            await asyncio.sleep(5.0)

def start_simulator():
    """Start the background traffic simulator."""
    global _SIMULATOR_RUNNING, _SIMULATOR_TASK
    if not _SIMULATOR_RUNNING:
        _SIMULATOR_RUNNING = True
        loop = asyncio.get_event_loop()
        _SIMULATOR_TASK = loop.create_task(traffic_simulator())

def stop_simulator():
    """Stop the background traffic simulator."""
    global _SIMULATOR_RUNNING, _SIMULATOR_TASK
    _SIMULATOR_RUNNING = False
    if _SIMULATOR_TASK is not None:
        _SIMULATOR_TASK.cancel()
        _SIMULATOR_TASK = None