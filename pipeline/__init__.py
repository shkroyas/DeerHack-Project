"""BankSentinel — Pipeline package."""
from .ingestion import (
    prepare_cicids,
    load_regime_data,
    assign_regime,
    StreamSimulator,
    FlowRecord,
    build_apt_scenario,
)

__all__ = [
    "prepare_cicids",
    "load_regime_data",
    "assign_regime",
    "StreamSimulator",
    "FlowRecord",
    "build_apt_scenario",
]