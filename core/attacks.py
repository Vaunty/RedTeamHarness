"""attacks.py - load the probe library.

Attacks are DATA (in attacks/probes.jsonl), so you add new ones without touching logic
and can load standard datasets into the same shape.
"""
import json
import re
from dataclasses import dataclass, field


@dataclass
class Attack:
    id: str            # "leak-001"
    category: str      # "prompt_injection" | "jailbreak" | "data_leak" | ...
    owasp: str         # "LLM01" (Prompt Injection), "LLM06" (Sensitive Info Disclosure), ...
    technique: str     # short description == the "attacker intent" the judge is shown
    system: str        # the system prompt the target runs under
    success_if: dict   # cheap deterministic check, e.g. {"contains": "BANANA-42"} or {"regex": "..."}
    user: str = ""     # legacy fallback for single-turn attacks
    turns: list[str] = field(default_factory=list) # multi-turn sequence
    mitre: str = ""    # MITRE ATT&CK / ATLAS tactic, e.g. "AML.T0051" (LLM Prompt Injection)


def load_attacks(path="data/probes.jsonl"):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data = json.loads(line)
                # Normalize legacy single-turn probes into multi-turn
                if "user" in data and "turns" not in data:
                    data["turns"] = [data["user"]]
                out.append(Attack(**data))
    return out


def deterministic_hit(success_if, response):
    """A ground-truth-ish check for benign proxies (and a cross-check on the LLM judge).
    Returns True/False if a check is defined, else None."""
    if not success_if:
        return None
    text = response or ""
    if "contains" in success_if:
        return success_if["contains"].lower() in text.lower()
    if "regex" in success_if:
        return re.search(success_if["regex"], text, re.I) is not None
    return None
