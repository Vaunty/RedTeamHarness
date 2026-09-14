# HadAgent Proof-of-Inference (PoI) Red-Teaming Harness

An automated security-evaluation harness that probes and red-teams **Proof-of-Inference (PoI)** and **Proof-of-Deep-Learning (PoDL)** blockchain consensus in **HadAgent** (arXiv:2604.18614).

Based on research by Matthew K. Ngoy under faculty mentor Boyang Li (Kean University, Fall 2026), this harness shifts adversarial testing from prompting isolated LLM endpoints to attacking the economic, consensus, and serving assumptions of decentralized AI blockchains.

---

## Status (as of September 14, 2026)

This is early-semester scaffolding. Read the numbers below with that in mind.

**Verified against the real HadAgent code and history**
- The tuple validation bug is real. In the HadAgent repo, commit `1a8d490` (2026-03-31) changed `validate_record` to return `(bool, reason)` while `block.py` still tested `if not validate_record(r):`, so every invalid record passed block validation until the fix in `a4ec9da` (2026-04-13). `runners/validation_fuzzing.py` reproduces the same bug pattern in `core/poi/record.py` behind a `LEGACY_VALIDATION` switch.
- The provided prototype (`hadagent/src/podl_chain/`, unchanged from the files I was given) contains the consensus core only. The anomaly detector, trust manager, two-tier serving, and heartbeat monitor described in the paper are not in the code. `core/poi/` is my re-implementation of those pieces, following the paper's rules, so the attacks have something to run against.
- Proof verification in the prototype (`pdl.py`) POSTs eval prompts to the endpoint URL taken from the miner's own record and requires exact integer score equality. That is the model-binding gap the proposal targets.

**Simulated, not yet measured (no model inference runs yet)**
- Determinism: score jitter between configurations is drawn from a hand-picked list in `runners/determinism.py`, so the false-anomaly rate (60-72% across runs) and the +/-15 tolerance are properties of that list, not of a real quantized model.
- Model binding: the lookup table is built from the same 20-question sample it is graded on, and the ~65% compute-savings figure is a constant in the runner.
- Reproducibility vs. safety: the harmful outputs and their matching scores are a fixed list in `runners/reproducibility.py`; the 100% baseline acceptance follows by construction. The defended run needs a judge API key.
- Trust-then-betray: node scores are fixed offsets in `core/poi/node.py`.

**Next**: replace the synthetic scores with real runs (Llama-3.2-3B via llama.cpp at two quantizations, HarmBench subset through the judge) per the proposal timeline. The validation fuzzer currently uses hand-written cases; moving it to Hypothesis strategies is on the list.

---

## Core Attack Vectors Evaluated

The harness provides reproducible, automated runners for the 5 vulnerability categories:

1. **Determinism & Score Divergence (`runners/determinism.py`):**
   - Measures evaluation score divergence across execution configurations (quantization levels, thread counts, backend engines).
   - With simulated score jitter, exact integer equality produces high false-anomaly rates (60-72% on honest nodes) and the runner reports the minimum tolerance ($\pm 15$ points) that removes them. Real-inference measurement is pending.
2. **Trust-Then-Betray Optimistic Abuse (`runners/trust_then_betray.py`):**
   - Simulates an adversarial node that earns 'TRUSTED' status over 5 clean rounds, then exploits HadAgent's two-tier optimistic execution pipeline to deliver harmful payloads to consumers *before* verification.
   - Evaluates probabilistic pre-delivery gating ($p$) and validates the theoretical $1/p$ bounds.
3. **Model-Binding & Lookup-Table Evasion (`runners/model_binding.py`):**
   - Shows that a static lookup table over a public audit set passes the audit at 100% with no compute (sample evalset, 20 questions).
   - Uses an assumed ~65% compute saving for substituting Mistral-7B with Llama-3.2-3B; this is a placeholder constant, not a measurement.
   - Evaluates private rotating challenge defenses.
4. **Reproducibility vs Safety Invariant Attack (`runners/reproducibility.py`):**
   - Illustrates the core PoI gap with a fixed set of reproducible harmful outputs: score equality passes them into blocks.
   - Evaluates the before/after Attack Success Rate (ASR) when an in-path Safety Judge oracle (`SafetyJudgeDefense`) is added to block verification.
5. **Validation Fuzzing (`runners/validation_fuzzing.py`):**
   - Reproduces the historical HadAgent tuple validation bug (commits `1a8d490` to `a4ec9da` in the HadAgent repo), where `(False, "reason")` was evaluated as truthy and corrupt records were accepted into blocks.
   - Hand-written corpus today (40 records: valid, bad signature, out-of-bounds score, tampered after signing); Hypothesis-based property tests are the next step.

---

## Architecture Overview

The active Proof-of-Inference pipeline is `runner.py`, `runners/`, `core/poi/`,
`core/judge.py`, `core/defenses.py`, `core/database.py`, `hadagent/` (the vendored
prototype under evaluation), `data/`, `tests/`, and `docs/`.

Code from an earlier LLM/VLM red-teaming phase that the PoI work does not use (the
`web/` dashboard, `api/`, `core/attacks.py`, `core/embed.py`, `core/geometry.py`,
`core/targets.py`, and `tests/test_geometry.py`) has been retired to
`legacy/retired_llm_phase/`, which is not tracked in git. It is kept locally for
reference and can be revived if needed.

```
RedTeamHarness/
├── runner.py                 # CLI orchestrator for the five attack runners
├── runners/                  # Attack runners
│   ├── determinism.py        # Score divergence & anomaly tolerance
│   ├── trust_then_betray.py  # Optimistic serving abuse & trust transitions
│   ├── model_binding.py      # Lookup tables & model substitution
│   ├── reproducibility.py    # Reproducibility-is-not-safety
│   └── validation_fuzzing.py # Hand-written corpus fuzzing & tuple-bug reproduction
├── core/
│   ├── poi/                  # PoI consensus simulation (my re-implementation)
│   │   ├── record.py         # 3-lane records, Ed25519 signing, tuple-bug switch
│   │   ├── block.py          # Merkle-rooted per-lane blocks
│   │   ├── trust.py          # Trust manager (promote after 5, demote after 2)
│   │   ├── anomaly.py        # Exact vs tolerance score anomaly detectors
│   │   ├── serving.py        # Two-tier optimistic execution server
│   │   └── node.py           # Simulated secondary node with adversarial behaviors
│   ├── judge.py              # Correctness-and-safety judge (from DebateCoach)
│   ├── defenses.py           # Safety-judge, random-audit, rotating-challenge defenses
│   └── database.py           # SQLite persistence (runs, poi_records, divergence, trust)
├── hadagent/                 # Vendored HadAgent prototype under evaluation (not mine)
├── data/
│   ├── evalset/              # Sample public benchmark questions (MMLU/HellaSwag)
│   └── poi_attacks.jsonl     # Attack spec catalog (reference; not loaded by runners yet)
├── scripts/download_harmbench.py  # Fetch/convert held-out HarmBench data
├── tests/                    # Unit tests for the PoI simulation (12)
└── docs/
    ├── THREAT_MODEL.md          # PoI consensus threat model
    ├── DESIGN_model_binding.md  # Model-substitution attack + binding design note
    └── RESEARCH_LOG.md          # Meeting notes, timeline, bi-weekly progress
```

---

## Quickstart

### 1. Environment Setup
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # then add a judge API key; .env is gitignored
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
