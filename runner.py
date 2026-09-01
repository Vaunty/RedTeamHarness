"""
runner.py - Main Orchestrator for HadAgent Proof-of-Inference Red-Teaming.

Dispatches attack experiments across the five vulnerability categories identified
in the research proposal:
1. determinism: Measures score divergence across execution configs (quantization, threads).
2. trust-then-betray: Tests optimistic execution abuse when trusted nodes serve harmful outputs.
3. model-binding: Evaluates lookup-table oracles and uncommitted proxy model substitution.
4. reproducibility: Demonstrates that reproducible harmful outputs pass consensus, and measures
   ASR reduction when an in-path safety judge is integrated.
5. validation-fuzzing: Fuzzes record and block schemas and reproduces the historical tuple-bug.

Usage:
    python runner.py --attack determinism
    python runner.py --attack trust-then-betray [--defense]
    python runner.py --attack model-binding
    python runner.py --attack reproducibility [--defense]
    python runner.py --attack validation-fuzzing
    python runner.py --attack all
"""
import sys
import argparse
from typing import Dict, Any

from runners.determinism import run_determinism_study
from runners.trust_then_betray import run_trust_then_betray_simulation
from runners.model_binding import run_model_binding_study
from runners.reproducibility import run_reproducibility_vs_safety_study
from runners.validation_fuzzing import run_validation_fuzzing_study
from core.defenses import PoIDefense


def main():
    parser = argparse.ArgumentParser(description="HadAgent Proof-of-Inference Red-Team Suite")
    parser.add_argument(
        "--attack",
        choices=["determinism", "trust-then-betray", "model-binding", "reproducibility", "validation-fuzzing", "all"],
        default="all",
        help="Specific PoI attack scenario to execute (default: all)"
    )
    parser.add_argument("--defense", action="store_true", help="Enable in-path defense mechanisms")
    parser.add_argument("--rounds", type=int, default=12, help="Number of rounds for stateful attack simulations")
    args = parser.parse_args()

    results: Dict[str, Any] = {}

    print("=================================================================")
    print("  HadAgent Proof-of-Inference (PoI) Consensus Red-Teaming Suite  ")
    print("=================================================================")

    if args.attack in ("determinism", "all"):
        print("\n>>> Running Attack 1: Determinism & Score Divergence Analysis <<<")
        results["determinism"] = run_determinism_study()

    if args.attack in ("trust-then-betray", "all"):
        print("\n>>> Running Attack 2: Trust-Then-Betray (Optimistic Serving Abuse) <<<")
        defense = PoIDefense(safety_judge=True, audit_probability=0.33) if args.defense else None
        results["trust_then_betray"] = run_trust_then_betray_simulation(
            rounds=args.rounds,
            betray_at_round=6,
            defense=defense
        )

    if args.attack in ("model-binding", "all"):
        print("\n>>> Running Attack 3: Model Binding & Lookup-Table Audit Evasion <<<")
        results["model_binding"] = run_model_binding_study()

    if args.attack in ("reproducibility", "all"):
        print("\n>>> Running Attack 4: Reproducibility vs Safety Invariant Attack <<<")
        results["reproducibility"] = run_reproducibility_vs_safety_study(use_defense=args.defense)

    if args.attack in ("validation-fuzzing", "all"):
        print("\n>>> Running Attack 5: Property-Based Validation Fuzzing (Tuple Bug) <<<")
        results["validation_fuzzing"] = run_validation_fuzzing_study()

    print("\n=================================================================")
    print("  All requested attack evaluations completed successfully!       ")
    print("  Results logged to SQLite database (harness.db).                ")
    print("=================================================================\n")


if __name__ == "__main__":
    main()
