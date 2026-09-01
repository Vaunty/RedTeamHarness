# HadAgent Proof-of-Inference (PoI) Red-Teaming Harness

An automated security-evaluation harness that probes and red-teams **Proof-of-Inference (PoI)** and **Proof-of-Deep-Learning (PoDL)** blockchain consensus in **HadAgent** (arXiv:2604.18614).

Based on research by Matthew K. Ngoy under faculty mentor Boyang Li (Kean University, Fall 2026), this harness shifts adversarial testing from prompting isolated LLM endpoints to attacking the economic, consensus, and serving assumptions of decentralized AI blockchains.

---

## Core Attack Vectors Evaluated

The harness provides reproducible, automated runners for the 5 vulnerability categories:

1. **Determinism & Score Divergence (`runners/determinism.py`):**
   - Measures evaluation score divergence across execution configurations (quantization levels, thread counts, backend engines).
   - Demonstrates that exact integer equality produces high false-anomaly rates (up to 70% false alarm rate on honest nodes) and calculates the minimum tolerance ($\pm 15$ points) required to eliminate false positives.
2. **Trust-Then-Betray Optimistic Abuse (`runners/trust_then_betray.py`):**
   - Simulates an adversarial node that earns 'TRUSTED' status over 5 clean rounds, then exploits HadAgent's two-tier optimistic execution pipeline to deliver harmful payloads to consumers *before* verification.
   - Evaluates probabilistic pre-delivery gating ($p$) and validates the theoretical $1/p$ bounds.
3. **Model-Binding & Lookup-Table Evasion (`runners/model_binding.py`):**
   - Demonstrates that nodes can pass public benchmark audits (MMLU / HellaSwag) at 100% accuracy using static lookup tables with 0 compute.
   - Measures compute savings (~65%) achieved by substituting committed heavy models (Mistral-7B) with lightweight uncommitted models (Llama-3.2-3B).
   - Evaluates private rotating challenge defenses.
4. **Reproducibility vs Safety Invariant Attack (`runners/reproducibility.py`):**
   - Demonstrates the foundational security flaw in PoI: reproducible harmful generation passes score/hash equality and is rewarded with block acceptance.
   - Evaluates the before/after Attack Success Rate (ASR) when an in-path Safety Judge oracle (`SafetyJudgeDefense`) is added to block verification.
5. **Property-Based Validation Fuzzing (`runners/validation_fuzzing.py`):**
   - Reproduces the historical HadAgent tuple validation bug documented in Landy Jimenez & Mariah's test logs, where schema validators returning `(False, "reason")` were evaluated as Truthy in Python, incorrectly accepting 100% of corrupt records into blocks.
   - Formally asserts invariant testing across Merkle-tree block verification.

---

## Architecture Overview

```
RedTeamHarness/
├── runner.py                 # Central CLI orchestrator for all attack suites
├── runners/                  # Specialized attack runners
│   ├── determinism.py        # Score divergence & hardware tolerance
│   ├── trust_then_betray.py  # Optimistic serving exploitation & trust transitions
│   ├── model_binding.py      # Lookup tables & model substitution
│   ├── reproducibility.py    # Reproducibility != Safety invariant tests
│   └── validation_fuzzing.py # Property-based fuzzing & tuple bug reproduction
├── core/
│   ├── poi/                  # Standalone HadAgent PoI consensus simulation
│   │   ├── record.py         # 3-lane records, Ed25519 signing, tuple-bug switch
│   │   ├── block.py          # Merkle-rooted per-lane blocks
│   │   ├── trust.py          # Trust state manager (promote: 5, demote: 2)
│   │   ├── anomaly.py        # Exact vs tolerance score anomaly detectors
│   │   ├── serving.py        # Two-tier optimistic execution server
│   │   └── node.py           # Simulated secondary node with adversarial behaviors
│   ├── judge.py              # Ported DebateCoach judge (Correctness + Safety)
│   ├── defenses.py           # In-path Safety Judge, Random Audit, Challenge defenses
│   ├── database.py           # SQLite persistence (runs, records, divergences, transitions)
│   └── targets.py            # PoINode model abstraction
├── data/
│   ├── evalset/              # Public benchmark questions (MMLU, HellaSwag)
│   └── poi_attacks.jsonl     # Attack specifications across all 5 categories
├── scripts/
│   └── download_harmbench.py # Download & conversion script for held-out HarmBench data
├── tests/                    # Unit and property-based test suite
└── docs/
    └── THREAT_MODEL.md       # PoI consensus threat model
```

---

## Quickstart

### 1. Environment Setup
```powershell
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run All Attack Suites
```powershell
$env:PYTHONPATH = "."
python runner.py --attack all
```

### 3. Run Specific Attacks
```powershell
# 1. Determinism score divergence
python runner.py --attack determinism

# 2. Trust-then-betray attack (baseline vs defended)
python runner.py --attack trust-then-betray
python runner.py --attack trust-then-betray --defense

# 3. Model binding and lookup table evasion
python runner.py --attack model-binding

# 4. Reproducibility vs Safety
python runner.py --attack reproducibility
python runner.py --attack reproducibility --defense

# 5. Validation fuzzing and tuple bug reproduction
python runner.py --attack validation-fuzzing
```

### 4. Run Automated Unit Tests
```powershell
$env:PYTHONPATH = "."
pytest tests/ -v
```

### 5. Generate Markdown Report
```powershell
python report.py --poi
```
Output is written to `results/poi_report.md`.
