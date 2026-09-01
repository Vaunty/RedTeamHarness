"""
Proof-of-Inference (PoI) Consensus Simulation Layer.

This package provides a standalone simulation of the HadAgent consensus
mechanisms for red-teaming purposes.
"""
from core.poi.record import (
    Lane,
    PoIRecord,
    sign_record,
    verify_signature,
    validate_record,
    scale_score
)
from core.poi.block import (
    PoIBlock,
    create_block,
    validate_block,
    merkle_root
)
from core.poi.trust import (
    TrustState,
    TrustManager
)
from core.poi.anomaly import (
    AnomalyMode,
    AnomalyDetector
)
from core.poi.serving import (
    ServingResult,
    TwoTierServer
)
from core.poi.node import (
    NodeBehavior,
    SimulatedNode
)

__all__ = [
    "Lane",
    "PoIRecord",
    "sign_record",
    "verify_signature",
    "validate_record",
    "scale_score",
    "PoIBlock",
    "create_block",
    "validate_block",
    "merkle_root",
    "TrustState",
    "TrustManager",
    "AnomalyMode",
    "AnomalyDetector",
    "ServingResult",
    "TwoTierServer",
    "NodeBehavior",
    "SimulatedNode"
]
