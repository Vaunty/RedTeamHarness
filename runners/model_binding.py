"""
runners/model_binding.py - Model-Binding & Substitution Attack Runner.

Evaluates vulnerabilities where consensus verification does not cryptographically bind
the model generating user inference to the model committed on-chain.
Implements:
1. Lookup-table oracle: Node answers public audit benchmarks from static dictionary.
2. Model substitution: Node commits to running heavy Mistral-7B, but serves lightweight
   or unaligned models to real users.
3. Rotating challenge detection: Evaluates defense effectiveness when audit benchmarks
   are randomized or drawn from private held-out challenge sets.
"""
import json
import time
from typing import Dict, Any, List

from core.poi.record import scale_score
from core.poi.anomaly import AnomalyDetector, AnomalyMode
from core.poi.node import SimulatedNode, NodeBehavior
from core.database import (
    init_db, insert_run, finish_run, insert_metrics, insert_poi_record
)
from core.defenses import RealRequestAuditDefense


def run_model_binding_study(
    eval_tasks_path: str = "data/evalset/sample_tasks.jsonl",
    private_challenge_ratio: float = 0.3
) -> Dict[str, Any]:
    """
    Simulates lookup-table and model substitution attacks against audit verification.
    """
    init_db()
    run_id = insert_run(
        target_models=["mistral-7b-committed", "llama-3.2-3b-served"],
        defense_mode="comparison",
        judge_model="model_binding_checker",
        judge_runs=1,
        notes="Model-binding evasion and lookup-table exploitation"
    )

    # Load public audit tasks
    tasks = []
    with open(eval_tasks_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                tasks.append(json.loads(line))

    # 1. Build lookup table for the public benchmark
    lookup_table = {}
    for t in tasks:
        t_id = t.get("task_id", "")
        lookup_table[t_id] = t.get("answer", "A")

    print("\n=== Model-Binding & Substitution Attack Simulation ===")
    print(f"Public audit tasks: {len(tasks)}")
    print(f"Precomputed lookup table entries: {len(lookup_table)}")

    # Test 1: Pure static audit (all questions in lookup table)
    evaded_static = 0
    total_static = len(tasks)
    for t in tasks:
        t_id = t.get("task_id")
        if t_id in lookup_table and lookup_table[t_id] == t.get("answer"):
            evaded_static += 1

    evasion_rate_static = evaded_static / total_static if total_static else 0.0

    # Test 2: Dynamic audit with hidden rotating challenges (defense)
    challenge_auditor = RealRequestAuditDefense(challenge_ratio=private_challenge_ratio)
    evaded_dynamic = 0
    caught_dynamic = 0

    for i, t in enumerate(tasks):
        is_private_challenge = challenge_auditor.is_challenge_task(f"task_{i}")
        if is_private_challenge:
            # Private challenge not in lookup table -> attacker guesses or falls back to weak proxy
            guessed_correctly = (i % 4 == 0) # 25% random multiple choice accuracy
            if guessed_correctly:
                evaded_dynamic += 1
            else:
                caught_dynamic += 1
        else:
            # Public question present in lookup table -> 100% accuracy
            evaded_dynamic += 1

    evasion_rate_dynamic = evaded_dynamic / len(tasks) if tasks else 0.0

    # Model substitution compute advantage:
    # Mistral-7B (~14GB FP16 / 4GB Q4) vs Llama-3.2-3B (~2GB Q4)
    compute_savings_pct = 65.0  # Approx 65% compute savings by substituting 7B with 3B

    metrics = {
        "static_audit_evasion_rate": round(evasion_rate_static, 4),
        "dynamic_challenge_evasion_rate": round(evasion_rate_dynamic, 4),
        "dynamic_evasions_caught": caught_dynamic,
        "compute_savings_pct": compute_savings_pct,
        "total_audit_tasks": len(tasks)
    }

    insert_metrics(run_id, metrics)
    finish_run(run_id, len(tasks))

    print(f"\nStatic Audit Evasion Rate (Lookup Table)     : {evasion_rate_static:.1%}")
    print(f"Dynamic Challenge Evasion Rate (With Defense): {evasion_rate_dynamic:.1%}")
    print(f"Private Challenges Intercepted Malicious Node: {caught_dynamic} / {int(len(tasks) * private_challenge_ratio)}")
    print(f"Adversary Compute Resource Savings           : ~{compute_savings_pct:.0f}%")

    return {
        "run_id": run_id,
        "metrics": metrics
    }


if __name__ == "__main__":
    run_model_binding_study()
