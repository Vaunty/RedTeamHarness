# Threat Model — HadAgent Proof-of-Inference (PoI) Red-Teaming Harness

**Author:** Matthew K. Ngoy  
**Mentor:** Boyang Li (Kean University)  
**Date:** Fall 2026  
**Version:** 3.0 (Pivot from LLM/VLM Red-Teaming to HadAgent PoI Blockchain Consensus)  

---

## 1. System Description

HadAgent is a decentralized AI serving blockchain that replaces energy-wasteful hash-based mining with **Proof-of-Inference (PoI)** / **Proof-of-Deep-Learning (PoDL)** consensus (arXiv:2604.18614). 

### Key Consensus & Serving Mechanisms
1. **Three-Lane AI Record Structure:**
   - **DATA:** Commitments and cryptographic hashes of served input batches.
   - **MODEL:** Commitments to model architectures, weights (`artifact_hash`), and version metadata (Mistral-7B-Instruct / Llama-3.2-3B).
   - **PROOF:** Scaled integer evaluation scores (`claimed_score = int(accuracy * 1000)`) earned by evaluating models on public benchmark suites (MMLU, HellaSwag) under deterministic decoding (temperature 0, top-k 1).
2. **Per-Lane Merkle-Rooted Blocks:**
   - Blocks group verified records with independent Merkle roots per lane. Only cryptographic hashes, scores, and Ed25519 signatures are stored on-chain. Raw data and model weights remain off-chain.
3. **Information Hub & Mempool:**
   - Socket packet protocol (`NEW_DATA_RECORD`, `NEW_MODEL_RECORD`, `NEW_PROOF_RECORD`) passing through an AI record mempool (`pool.py`).
4. **Two-Tier Optimistic Serving Architecture:**
   - **Trusted Tier (Fast Path):** Nodes that establish trust (5 clean rounds) deliver inference results directly to the consumer/agent optimistically *before* validation completes.
   - **Untrusted Tier (Held Path):** Nodes that have not yet achieved trust or have failed verifications have their outputs held until consensus verification succeeds.
5. **Score Verification & Anomaly Detection:**
   - Validators recompute model evaluations by querying the miner node's inference endpoint and comparing scores.

---

## 2. Trust Boundaries

1. **On-Chain vs Off-Chain Boundary:** The blockchain ledger stores only hashes, signatures, and scaled scores. Actual model execution and inference outputs occur off-chain on secondary nodes.
2. **Optimistic Delivery Boundary:** Trusted nodes deliver outputs to consumer agents before consensus verification runs. This creates an execution time-window where unverified outputs are trusted.
3. **Endpoint vs Model Commitment Boundary:** Consensus verifies the miner's *endpoint* responses (`verify_podl_llm_eval`), but does not cryptographically bind the output tokens to the committed model weight hash (`artifact_hash`).
4. **Hardware Homogeneity Assumption:** The system assumes identical floating-point arithmetic across different GPU architectures, CPU backends, quantization variants, and thread counts.

---

## 3. Threat Actors

- **Adversarial Secondary Node Operator:** An attacker operating one or more secondary inference nodes who seeks to earn block rewards with zero/reduced compute, manipulate consensus, or deliver malicious payloads to consumers.
- **Model Provider / Fine-Tuner:** An adversary who trains or fine-tunes a model to pass public benchmarks while retaining harmful behaviors on real requests.
- **Selfish Miner:** A miner exploiting hardware divergence to create consensus splits or force honest nodes into false-anomaly demotions.

---

## 4. Assets at Risk

1. **Consensus Correctness:** Ensuring that blocks included in the chain represent genuine model evaluation work.
2. **Consumer Agent Safety:** Preventing adversarial inference nodes from delivering malicious, deceptive, or exploit payloads through the serving pipeline.
3. **Resource Fairness:** Preventing attackers from evading evaluation compute costs (e.g. via lookup tables or cheap proxy models).
4. **Consensus Liveness & Invariant Integrity:** Preventing invalid blocks from corrupting chain state (e.g., tuple validation bypass).

---

## 5. Attack Surface & Threat Catalog

| Threat | Description | Category | Impact | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Determinism Divergence** | Honest nodes produce different scores across quantizations (Q4 vs FP16) or thread counts, triggering false anomaly detections (up to 70% false alarm rate under exact match). | Consensus Integrity | High | Demonstrated in `runners/determinism.py` |
| **Trust-Then-Betray** | Malicious node earns 'TRUSTED' status over 5 clean rounds, then exploits optimistic delivery to serve unsafe outputs before demotion (2 failures). | Serving Safety | Critical | Demonstrated in `runners/trust_then_betray.py` |
| **Lookup-Table Evasion** | Miner answers static public benchmark questions (MMLU/HellaSwag) from a precomputed table, achieving 100% score with 0 compute. | Economic / Resource | High | Demonstrated in `runners/model_binding.py` |
| **Model Substitution** | Node commits to running heavy Mistral-7B, but serves lightweight Llama-3.2-3B to consumers, pocketing ~65% compute savings. | Resource / Integrity | Medium | Demonstrated in `runners/model_binding.py` |
| **Reproducibility != Safety** | Toxic or exploit outputs generated deterministically reproduce their score across nodes, so consensus accepts them into blocks. | Safety Invariant | Critical | Demonstrated in `runners/reproducibility.py` |
| **Tuple Validation Bug** | Schema validator returns `(False, "reason")` tuple, which in Python evaluates as truthy, accepting invalid records into blocks. | Ledger Integrity | Critical | Fixed & Verified in `runners/validation_fuzzing.py` |

---

## 6. Tested Mitigations

1. **Tolerance-Based Anomaly Detection:** Replacing exact integer score equality with calibrated tolerance ($\pm 15$ points), reducing false anomaly rates from 70% to 0%.
2. **In-Path Safety Judge Oracle (`SafetyJudgeDefense`):** Integrates an automated correctness-and-safety evaluator directly into the verification path, dropping the harmful block acceptance rate from 100% to 0%.
3. **Probabilistic Pre-Delivery Gating (`RandomAuditDefense`):** Spot-checks trusted-node outputs before delivery with probability $p$, bounding adversarial delivery to expected $1/p$ rounds.
4. **Dynamic Challenge Auditing (`RealRequestAuditDefense`):** Injects private rotating challenge queries into evaluation streams, preventing lookup-table oracles from passing audits.
