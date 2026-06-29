# LLM Red-Team Harness

An automated harness that probes language models for **prompt injection, jailbreaks, and
data leakage** — now expanding into **multimodal VLM red-teaming** and **embedding-space attack analysis**. Everything maps to both the **OWASP Top 10 for LLM Applications** and **MITRE ATLAS**. It supports single-turn, **true multi-turn conversational attacks**, and (Phase 2) **structural coercion sweeps against vision-language models**.

The harness scores attack success with a **calibrated LLM-as-judge**, measures how defense layers lower that success rate, and uses **linear algebra (PCA/SVD)** to visualize the geometry of attack prompts in embedding space — turning that math into a smarter detector than any keyword filter.

The judge (`judge.py`) is a Python port of the GPT-4-as-judge system from the *DebateCoach*
HCI research project: it keeps the structured-JSON + reasoning output, the rubric-with-exemplars,
the **neutralization** (anonymization) and **self-consistency voting** rigor techniques, and
swaps the rubric from debate-quality to safety-compliance.

Everything runs on a normal laptop/desktop CPU (no GPU): small models run locally via Ollama,
and only the judge uses an API (grading is benign).

## Quick start

```bash
# 1. environment
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. local target models (no GPU needed)
#    install Ollama from ollama.com, then:
ollama pull llama3.2:3b
ollama pull qwen2.5:3b

# VLM models (Phase 2 — multimodal red-teaming)
ollama pull llava:7b-v1.5
ollama pull moondream

# 3. judge config
cp .env.example .env        # then edit .env and add your judge API key
#    (load it: `set -a; source .env; set +a`  on macOS/Linux)

# 4. sanity-check the judge on benign proxies (no harmful content)
python core/judge.py

# 5. run the harness, then read the results
python runner.py llama3.2:3b qwen2.5:3b
python metrics.py            # reads the latest run from the SQLite database
python report.py             # writes results/report.md from the database

# 6. measure your 8-layer defenses (before/after)
python -c "from runner import run; from core.defenses import Defense; \
b=run(['llama3.2:3b']); d=run(['llama3.2:3b'], defense=Defense()); \
from metrics import asr; print('ASR before', asr(b), 'after', asr(d))"
```

## Files
- `core/targets.py` - one OpenAI-compatible interface for local Ollama models or any hosted API
- `core/vlm_targets.py` - multimodal (image+text) interface for VLM models via Ollama
- `core/attacks.py` + `data/probes.jsonl` - the probe library (single-turn and multi-turn attacks)
- `core/judge.py` - the LLM-as-judge (ported from DebateCoach)
- `core/database.py` - SQLite persistence with SHA-256 response hashing
- `core/embed.py` - text → vector embeddings (all-MiniLM-L6-v2, 384-dim)
- `core/geometry.py` - the linear algebra engine (cosine similarity, PCA/SVD, attack direction)
- `core/detector.py` - embedding-based attack detector (replaces keyword filter)
- `core/visual_detector.py` - CLIP-based zero-shot latent space visual prompt injection detector
- `core/ocr.py` - Decoupled OCR pre-screening engine (EasyOCR, PyTesseract, and LLaVA fallback)
- `core/intensity.py` - Ghost-100 5-Level Prompt Intensity Framework for VLM coercion sweeps
- `runner.py` - the main loop; logs deterministic checks + judge verdicts to the database
- `metrics.py` - ASR, refusal rate, MITRE/OWASP breakdowns, judge calibration
- `core/defenses.py` - 8-layer defense system (hardening, sanitization, token redaction, visual detection, embedding check)
- `report.py` - Automated Markdown report generation
- `docs/APPLICATION_GUIDE.md` - the full build-and-understand user guide
- `docs/THREAT_MODEL.md` - comprehensive threat modeling framework
- `CHANGELOG.md` - project history and decisions

See `docs/APPLICATION_GUIDE.md` for the detailed walkthrough, the responsible-use rules, and how to swap the
benign proxies for published datasets (garak / JailbreakBench / AdvBench / MMSafeAware / Ghost-100).

## Research Direction

Phase 2 investigates **structural coercion as a jailbreak vector against vision-language models** — the idea that rigid formatting, role-play scaffolding, and multi-model orchestration can bypass safety alignment more effectively than overtly toxic prompts. This builds on the Ghost-100 5-Level Prompt Intensity Framework and uses the Geometry of Attacks embedding analysis to both visualize the attack landscape and build a mathematically-grounded defense.

The architecture draws inspiration from Alissa Knight's Ares co-evolutionary framework (agentic adversarial self-play for autonomous red-teaming), applied to a frontier the Ares paper doesn't cover: multimodal VLM safety.

## Acknowledgments & References

This project builds upon the research, methodologies, and technical insights of the following creators and projects:

- **DebateCoach Project (CRA UR2PhD)**: The core LLM-as-a-judge architecture (`core/judge.py`), including self-consistency voting and neutralization, was ported from this research project.
- **Alissa Knight / Assail**: The Ares framework's co-evolutionary architecture and Darwinian offensive methodology inspired the Phase 2 agentic red-teaming pipeline.
- **Ghost-100 / "Tone Matters" Paper**: The 5-Level Prompt Intensity Framework that structures the VLM structural coercion experiments.
- **[NetworkChuck](https://www.youtube.com/@NetworkChuck)**: Inspired advanced payload delivery mechanisms, specifically Emoji Smuggling and Markdown Link Smuggling techniques for data exfiltration bypasses.
- **[The Cyber Mentor (Heath Adams)](https://www.youtube.com/@TCMSecurityAcademy)**: Inspired practical CTF-style bypasses and complex prompt wrappers.
- **[LiveOverflow](https://www.youtube.com/@LiveOverflow)**: Deep-dive mechanistic interpretability and token-level manipulation that form the mathematical basis for bypassing attention mechanisms.
- **[Simply Cyber (Dr. Gerald Auger)](https://www.youtube.com/@SimplyCyber)**: GRC insights that informed the dashboard's mapping of ASR metrics to enterprise reporting frameworks.
- **[3Blue1Brown (Grant Sanderson)](https://www.youtube.com/@3blue1brown)**: His visual Deep Learning series on Transformers and Attention provided the foundational mathematics for the Geometry of Attacks and the latent space embedding analysis.
