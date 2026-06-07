# LLM Red-Team Harness

An automated harness that probes language models for **prompt injection, jailbreaks, and
data leakage** (mapped to the OWASP Top 10 for LLM Applications), scores attack success with a
**calibrated LLM-as-judge**, and measures how a defensive layer lowers that success rate.

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

# 3. judge config
cp .env.example .env        # then edit .env and add your judge API key
#    (load it: `set -a; source .env; set +a`  on macOS/Linux)

# 4. sanity-check the judge on benign proxies (no harmful content)
python judge.py

# 5. run the harness, then read the results
python runner.py llama3.2:3b qwen2.5:3b
python metrics.py results/run_*.jsonl
python report.py  results/run_*.jsonl       # writes results/report.md

# 6. measure your defenses (before/after)
python -c "from runner import run; from defenses import Defense; \
import glob; b=run(['llama3.2:3b']); d=run(['llama3.2:3b'], defense=Defense()); \
from metrics import load, asr; print('ASR before', asr(load(b)), 'after', asr(load(d)))"
```

## Files
- `targets.py` - one OpenAI-compatible interface for local Ollama models or any hosted API
- `attacks.py` + `attacks/probes.jsonl` - the probe library (starts with benign proxies)
- `judge.py` - the LLM-as-judge (ported from DebateCoach)
- `runner.py` - the main loop; logs deterministic check + judge verdict to `results/`
- `metrics.py` - ASR, refusal rate, breakdowns, judge calibration
- `defenses.py` - hardened prompt + input/output filters
- `report.py` - Markdown report
- `docs/APPLICATION_GUIDE.md` - the full build-and-understand guide
- `DECISIONS.md` - design-decision log

See `docs/APPLICATION_GUIDE.md` for the detailed walkthrough, the responsible-use rules, and how to swap the
benign proxies for published datasets (garak / JailbreakBench / AdvBench / MMSafeAware).

## Acknowledgments & References

This project builds upon the research, methodologies, and technical insights of the following creators and projects:

- **DebateCoach Project (CRA UR2PhD)**: The core LLM-as-a-judge architecture (`judge.py`), including self-consistency voting and neutralization, was ported from this research project.
- **[NetworkChuck](https://www.youtube.com/@NetworkChuck)**: Inspired advanced payload delivery mechanisms, specifically Emoji Smuggling and Markdown Link Smuggling techniques for data exfiltration bypasses.
- **[The Cyber Mentor (Heath Adams)](https://www.youtube.com/@TCMSecurityAcademy)**: Inspired practical CTF-style bypasses and complex "WTF" prompt wrappers.
- **[LiveOverflow](https://www.youtube.com/@LiveOverflow)**: Deep-dive mechanistic interpretability and token-level manipulation (glitch tokens) that form the mathematical basis for bypassing attention mechanisms.
- **[Simply Cyber (Dr. Gerald Auger)](https://www.youtube.com/@SimplyCyber)**: GRC insights that shaped the mapping of Attack Success Rates (ASR) to the **NIST AI Risk Management Framework (AI RMF)** for enterprise reporting.
- **[3Blue1Brown (Grant Sanderson)](https://www.youtube.com/@3blue1brown)**: His visual Deep Learning series on Transformers and Attention provided the foundational mathematics for Phase 3 (The Geometry of Attacks) and the latent space embedding analysis.
