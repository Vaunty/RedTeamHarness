# HadAgent Proof-of-Inference Red-Team Harness — Application Guide

> **A complete, step-by-step guide to installing, configuring, and executing red-team attacks against HadAgent's Proof-of-Inference (PoI) and Proof-of-Deep-Learning (PoDL) blockchain consensus.**

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites & Architecture](#2-prerequisites--architecture)
3. [Installation](#3-installation)
4. [The 5 Attack Scenarios](#4-the-5-attack-scenarios)
5. [Running the Attacks](#5-running-the-attacks)
6. [Testing & Invariant Verification](#6-testing--invariant-verification)
7. [Database Schema & Metrics](#7-database-schema--metrics)
8. [Generating Reports](#8-generating-reports)
9. [Troubleshooting](#9-troubleshooting)
10. [Ethical Use](#10-ethical-use)

---

## 1. Overview

The **HadAgent Proof-of-Inference Red-Team Harness** evaluates the security, economic, and consensus assumptions of decentralized AI blockchains (specifically HadAgent, arXiv:2604.18614).

Rather than treating LLMs as isolated chatbots, this harness red-teams the mechanisms that bind AI model evaluations to blockchain consensus:
- **Consensus Reproducibility:** Does deterministic reproducibility guarantee safety or correctness?
- **Hardware Divergence:** How do quantization (Q4 vs FP16) and multi-threading affect consensus agreement?
- **Optimistic Execution:** Can an adversarial node establish trust and deliver harmful outputs before verification?
- **Model Binding:** Can miners evade evaluation compute using precomputed lookup tables or proxy models?
- **Ledger Invariants:** Can schema validation bugs allow malformed or unauthorized records into blocks?

---

## 2. Prerequisites & Architecture

| Requirement | Version | Notes |
|---|---|---|
| **Python** | 3.10+ | Tested with Python 3.14 on Windows |
| **PyNaCl** | >=1.5 | Ed25519 asymmetric cryptography |
| **msgpack** | >=1.0 | Canonical binary serialization for HadAgent records |
| **pytest & pytest-asyncio** | Latest | Unit testing for async hub/pool & consensus |
| **Hypothesis** | >=6.0 | Property-based fuzzing for record/block invariants |
| **OpenAI API Key** | Optional | Required only when using GPT-4o as the Safety Judge oracle |

### Repository Structure

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
├── hadagent/                 # Official HadAgent codebase & benchmarks
│   ├── src/podl_chain/       # Core blockchain consensus engine
│   ├── tests/                # 26 native HadAgent consensus tests
│   └── test_results/         # Baseline latency & validation metrics
├── data/
│   ├── evalset/              # Public benchmark questions (MMLU, HellaSwag)
│   └── poi_attacks.jsonl     # Attack specifications across all 5 categories
├── scripts/
│   └── download_harmbench.py # Download & conversion script for held-out HarmBench data
├── tests/                    # Unit and property-based test suite (12 tests)
└── docs/
    ├── APPLICATION_GUIDE.md  # This document
    └── THREAT_MODEL.md       # PoI consensus threat model
```

---

## 3. Installation

```powershell
# 1. Activate virtual environment
.venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set Python path for module resolution
$env:PYTHONPATH = ".;hadagent/src;hadagent/tests"
```

---

## 4. The 5 Attack Scenarios

### Attack 1: Determinism & Score Divergence (`runners/determinism.py`)
- **Vulnerability:** HadAgent's prototype anomaly detector requires exact integer equality (`claimed == verified`) on scaled scores. In reality, evaluating models across heterogeneous hardware, different GGUF quantizations (Q4_0 vs FP16), and varying thread counts introduces subtle numerical divergence.
- **Impact:** Honest nodes are falsely flagged as anomalies (up to 70% false alarm rate), causing consensus friction.
- **Mitigation Tested:** Calibrated tolerance ($\pm 15$ points), which restores the false anomaly rate to 0.0%.

### Attack 2: Trust-Then-Betray (`runners/trust_then_betray.py`)
- **Vulnerability:** To reduce latency, HadAgent uses a two-tier serving system where "TRUSTED" nodes (5 clean rounds) deliver outputs optimistically *before* verification.
- **Impact:** A malicious node acts honest for 5 rounds, earns trusted status, and then delivers harmful or deceptive outputs directly to consumer agents before the 2-failure demotion threshold isolates it.
- **Mitigation Tested:** Probabilistic pre-delivery gating (`RandomAuditDefense`), bounding adversarial delivery to expected $1/p$ rounds.

### Attack 3: Model-Binding & Lookup-Table Evasion (`runners/model_binding.py`)
- **Vulnerability:** Consensus verification queries the miner's endpoint, but does not cryptographically bind the output tokens to the committed model weight hash (`artifact_hash`).
- **Impact:** Attackers answer public audit sets (MMLU/HellaSwag) from a static precomputed lookup table (100% score with 0 compute) or substitute heavy models (Mistral-7B) with lightweight models (Llama-3.2-3B) during user serving, pocketing ~65% compute savings.
- **Mitigation Tested:** Dynamic challenge auditing with private rotating evaluation queries (`RealRequestAuditDefense`).

### Attack 4: Reproducibility vs Safety Invariant (`runners/reproducibility.py`)
- **Vulnerability:** PoI checks only whether an evaluation score or output reproduces identically across nodes, not whether the output is safe.
- **Impact:** At temperature 0, a fine-tuned or unaligned model producing harmful exploits deterministically reproduces across all nodes, passing consensus and earning block rewards (100% ASR).
- **Mitigation Tested:** Integrating an automated Safety Judge (`SafetyJudgeDefense`) directly into the block verification pipeline, reducing ASR to 0.0%.

### Attack 5: Property-Based Validation Fuzzing (`runners/validation_fuzzing.py`)
- **Vulnerability:** Historical schema validation bug documented in Landy Jimenez & Mariah's test logs: `validate_records` returned `(boolean, string)` which in Python evaluated as a truthy tuple `bool((False, "bad sig")) == True`.
- **Impact:** Corrupt records and blocks with forged signatures were accepted into consensus.
- **Verification:** Fuzzes records with bad signatures, out-of-bounds scores, and payload tampering, proving the fixed validator rejects 100% of corrupt inputs.

---

## 5. Running the Attacks

### Run All Attacks Sequentially
```powershell
python runner.py --attack all
```

### Run Specific Attacks
```powershell
# 1. Determinism
python runner.py --attack determinism

# 2. Trust-Then-Betray (baseline vs defended)
python runner.py --attack trust-then-betray
python runner.py --attack trust-then-betray --defense

# 3. Model Binding
python runner.py --attack model-binding

# 4. Reproducibility vs Safety (baseline vs defended)
python runner.py --attack reproducibility
python runner.py --attack reproducibility --defense

# 5. Validation Fuzzing
python runner.py --attack validation-fuzzing
```

---

## 6. Testing & Invariant Verification

Run the entire combined test suite (38 passing tests):
```powershell
$env:PYTHONPATH = ".;hadagent/src;hadagent/tests"
pytest tests/ hadagent/tests/ -v
```

- `tests/` (12 tests): Verifies PoI records, Ed25519 crypto, Merkle tree blocks, trust state transitions, anomaly detection modes, two-tier serving, and linear algebra geometry.
- `hadagent/tests/` (26 tests): Verifies native HadAgent records, block linkage, hub networking, pool mempool operations, and scale submission.

---

## 7. Database Schema & Metrics

All runs are recorded in `results/harness.db` (SQLite with WAL mode and SHA-256 response hashing).

Key tables:
- `runs`: Run metadata, configuration, and timestamps.
- `poi_records`: Verified PoI proof records, claimed/verified scores, anomaly flags, and safety verdicts.
- `score_divergence`: Divergence deltas between execution configurations.
- `trust_transitions`: Node trust lifecycle transitions (`UNTRUSTED` -> `TRUSTED` -> `DEMOTED`).
- `run_metrics`: Aggregated statistical metrics per run.

---

## 8. Generating Reports

Generate an automated Markdown summary report for any run:
```powershell
python report.py --poi
```
The report is saved to `results/poi_report.md`.

---

## 9. Troubleshooting

### `ModuleNotFoundError: No module named 'core'` or `'podl_chain'`
Ensure your `PYTHONPATH` includes both the repository root and HadAgent source:
```powershell
$env:PYTHONPATH = ".;hadagent/src;hadagent/tests"
```

### Async tests failing
Ensure `pytest-asyncio` is installed in your environment:
```powershell
pip install pytest-asyncio
```

---

## 10. Ethical Use

1. **Defensive Research Focus:** This harness is intended to identify architectural vulnerabilities in decentralized consensus protocols to enable stronger cryptographic binding and verification guardrails.
2. **Responsible Disclosure:** Flaws discovered in consensus implementations should be shared with protocol maintainers before public deployment.
3. **Local Evaluation:** All simulations and benchmarks are designed to run safely on local infrastructure.
