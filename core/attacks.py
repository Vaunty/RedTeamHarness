"""attacks.py - load the probe library.

Attacks are DATA (in attacks/probes.jsonl), so you add new ones without touching logic
and can load standard datasets into the same shape.
"""
import json
import re
from dataclasses import dataclass, field

ATTACK_CATEGORIES = {
    "determinism": "Tests if nodes yield deterministic scores across identical configurations.",
    "trust_then_betray": "Nodes act honestly to build trust, then start acting maliciously.",
    "model_binding": "Tests if a node is running the model it claims to be running.",
    "reproducibility_not_safety": "Evaluates reproducibility capabilities beyond just safety checks.",
    "validation_fuzzing": "Fuzz testing the validation layer with varied inputs."
}


@dataclass
class PoIAttack:
    id: str                    # "det-001", "ttb-001"
    category: str              # "determinism", "trust_then_betray", "model_binding", "reproducibility_not_safety", "validation_fuzzing"
    description: str           # human-readable description
    node_behavior: str         # "honest", "fabricator", "lookup_table", "model_swap", "trust_then_betray"
    eval_config: dict          # {"quantization": "Q4_0", "threads": 4, ...}
    duration_rounds: int       # how many consensus rounds
    success_metric: str        # what metric determines success
    defense_config: dict = field(default_factory=dict)  # defense parameters to test


def load_attacks(path="data/probes.jsonl"):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data = json.loads(line)
                out.append(PoIAttack(**data))
    return out


def poi_deterministic_hit(success_metric: str, stats: dict) -> bool:
    """PoI-specific deterministic checks."""
    if success_metric == "score_divergence_zero":
        return stats.get("delta", 1) == 0
    elif success_metric == "anomaly_detected":
        return stats.get("anomaly_detected", False)
    return False
