# CHANGELOG — LLM Red-Team Harness

A living log of all changes, decisions, and important project context.
Entries are reverse-chronological. Categories: [SETUP], [FEATURE], [CHANGE], [FIX], [NOTE], [DECISION], [TODO]

---

## 2026-06-06 — Initial Build

### [SETUP] Project initialized
- Deployed source files from redteam-harness.zip to project root
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
- Using personal OpenAI API key (not CRA key) since this is an independent project
- May lead to own research contributions

### [DECISION] Benign proxies as ground truth
- Deterministic checks (contains BANANA-42, etc.) serve as ground truth for judge calibration
- Published datasets (garak, JailbreakBench) planned as future extension for breadth
- Calibration metric: judge_vs_deterministic agreement rate

### [TODO] Future enhancements
- [ ] Load published probe datasets (garak, JailbreakBench, HarmBench)
- [ ] Multi-turn attack chains
- [ ] Async runner for faster batch execution
- [ ] Web dashboard for results visualization
- [ ] Integration with NVIDIA garak / Microsoft PyRIT
