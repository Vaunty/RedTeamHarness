# CHANGELOG — LLM Red-Team Harness

A living log of all changes, decisions, and important project context.
Entries are reverse-chronological. Categories: [SETUP], [FEATURE], [CHANGE], [FIX], [NOTE], [DECISION], [TODO]

---

## 2026-06-29 — Phase 2 (VLM Red-Teaming & Geometry of Attacks)

### [DECISION] Research Pivot — Unified Platform
- After attending Alissa Knight's keynote at NJ SECON 2026 and reviewing the Ares co-evolutionary framework, decided to unify three threads into one integrated research platform:
  1. The existing harness (probe orchestration, metrics, dashboard)
  2. Geometry of Attacks (embedding-space analysis, PCA/SVD, linear attack detector)
  3. VLM red-teaming (multimodal jailbreak research using structural coercion)
- The research question: does structural coercion (rigid formatting, role-play scaffolding) bypass VLM safety alignment more effectively than overtly toxic prompts?

### [DECISION] Model Selection — Cut InternVL2, Added Moondream
- **Cut InternVL2-2B**: Not natively available in Ollama. Would have required a separate LMDeploy/Transformers pipeline, fragmenting the tooling.
- **Added Moondream 2 (1.8B)**: Runs natively via `ollama run moondream`. Fast on CPU (~8-15 tok/sec). Gives us a small-vs-large model comparison (1.8B vs 7B) to test whether model scale affects vulnerability to structural coercion.
- **Primary VLM target remains LLaVA 1.5 7B** via `ollama run llava:7b-v1.5`.

### [FEATURE] Geometry of Attacks Engine (Planned)
- `core/embed.py` — text → 384-dim vector embeddings via all-MiniLM-L6-v2
- `core/geometry.py` — hand-rolled PCA via SVD, cosine similarity matrix, difference-of-means attack direction, logistic regression cross-check
- `core/detector.py` — embedding-based attack detector that plugs into defenses.py, replacing the brittle keyword filter
- Centerpiece visualization: PCA scatter plot showing attack prompts migrating across embedding space as intensity escalates L1 → L5

### [FEATURE] VLM Structural Coercion Pipeline (Planned)
- `core/vlm_targets.py` — multimodal (image+text) interface for Ollama vision models
- `core/intensity.py` — Ghost-100 5-Level Prompt Intensity Framework implementation
- Datasets: Ghost-100 (hallucination benchmark), MMSafeAware subset (multimodal safety), AdvBench + JailbreakBench (labeled prompts for the embedding probe)

### [CHANGE] Documentation
- Updated README with Phase 2 research direction, new file listings, VLM model setup
- Updated THREAT_MODEL to v2.0: expanded attack surface to multimodal vectors, structural coercion, multi-model orchestration, and embedding-based defense
- Added Alissa Knight / Assail and Ghost-100 paper to Acknowledgments

### [NOTE] Architecture Insight
- Alissa Knight's Ares framework focuses on API/web/mobile penetration testing. This project applies the co-evolutionary philosophy to a frontier Ares doesn't cover: vision-language model safety. The Geometry of Attacks math engine serves as both the visualization layer and the defense target in the co-evolutionary loop.

---

## 2026-06-06 — Phase 1.75 (True Multi-Turn) & Creator Probes

### [FEATURE] Multi-Turn Conversational Attacks
- Upgraded `runner.py` and `Target` interface to maintain conversation history.
- `Attack` dataclass now supports `turns: list[str]`. Legacy single-turn datasets are automatically normalized.
- Upgraded LLM Judge (`judge.py`) to process full conversation transcripts instead of isolated responses.
- Added Crescendo and Compliance Training multi-turn attacks to `probes.jsonl`.

### [FEATURE] Advanced Creator Probes
- Added **Emoji Smuggling** and **Markdown Link Smuggling** probes (inspired by NetworkChuck).
- Added **WTF CTF Wrapper** probe (inspired by The Cyber Mentor).
- Added **Glitch Token / Encoding bypass** probe (inspired by LiveOverflow).

### [NOTE] Documentation & Git
- Updated README with accurate MITRE mappings, multi-turn architecture, and creator citations.
- Prepping transition to Phase 2 (Web Dashboard).

---

## 2026-06-06 — Phase 1.5 (Probes & 8-Layer Defenses)

### [FEATURE] Probe Library Expansion
- Expanded `probes.jsonl` from 6 to 28 core probes across 6 categories.
- Added test coverage for: System Prompt Extraction, Privilege Escalation, Harmful Content.

### [FEATURE] 8-Layer Defense System
- Completely overhauled `defenses.py`.
- Added structural pattern matching, input sanitization, and system prompt leakage detection.
- Added **Harmful Content Policy layer** to detect educational/roleplay bypasses.
- ASR (Attack Success Rate) reduced from 32.1% to 10.7% on Llama 3.2 3B.

### [NOTE] General Polish
- Standardized documentation style across all project files to ensure a clean, professional tone.

---

## 2026-06-06 — Initial Build

### [SETUP] Project initialized
- Initial project structure and core modules
- Core modules: targets.py, attacks.py, judge.py, runner.py, metrics.py, defenses.py, report.py
- Attack probes: 6 benign proxy probes in attacks/probes.jsonl
- Environment: Python 3.14.5, Ollama (local), OpenAI API (judge)
- Machine: i5-12600K, 16 GB RAM, no GPU (CPU inference)

### [FEATURE] SQLite database layer (database.py)
- Added structured persistence: runs, results, run_metrics tables
- SHA-256 response hashing for integrity verification
- Replaces flat JSONL as primary storage; JSONL kept for backward compatibility
- Design decision: SQLite chosen for zero-infrastructure, single-file portability

### [FEATURE] MITRE ATT&CK / ATLAS mapping
- Added `mitre` field to Attack dataclass and all probes
- Maps: data_leak → AML.T0024, prompt_injection → AML.T0051, jailbreak → AML.T0054
- Provides dual-framework coverage (OWASP LLM Top 10 + MITRE ATLAS)

### [CHANGE] runner.py — database integration
- Runner now writes to both SQLite (primary) and JSONL (backward-compatible)
- Each run gets a UUID; each result includes SHA-256 response hash
- Metrics auto-computed and stored at end of run

### [CHANGE] metrics.py — database-aware
- Added load_from_db() and store_metrics() functions
- Original JSONL loading preserved

### [CHANGE] report.py — database-aware reporting
- Can now accept run_id instead of file path
- New: comparison_report() for baseline vs defended delta

### [NOTE] Documentation created
- APPLICATION_GUIDE.md: User-facing how-to guide
- THREAT_MODEL.md: Professional threat model document
- CHANGELOG.md: This file
- .gitignore: Comprehensive Python project patterns

### [DECISION] Own API key for judge
- Using personal OpenAI API key since this is an independent project

### [DECISION] Benign proxies as ground truth
- Deterministic checks (contains BANANA-42, etc.) serve as ground truth for judge calibration
- Published datasets (garak, JailbreakBench) planned as future extension for breadth
- Calibration metric: judge_vs_deterministic agreement rate

### [TODO] Status
- [x] Load published probe datasets (garak, JailbreakBench, HarmBench)
- [x] Multi-turn attack chains
- [ ] Async runner for faster batch execution
- [x] Web dashboard for results visualization
- [ ] Integration with NVIDIA garak / Microsoft PyRIT
- [ ] Geometry of Attacks: embed.py, geometry.py, detector.py
- [ ] VLM pipeline: vlm_targets.py, intensity.py
- [ ] Ghost-100 intensity sweep (LLaVA + Moondream)
- [ ] Embedding detector vs. keyword filter head-to-head
- [ ] PCA migration visualization (centerpiece figure)
