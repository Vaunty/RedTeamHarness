from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional
import json
import urllib.request
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from .crypto import sha256

# Open-source LLM client (llama.cpp) 
@dataclass(frozen=True)
class DecodeConfig:
    temperature: float = 0.0
    top_k: int = 1
    top_p: float = 1.0
    max_tokens: int = 64
    stop: Optional[str] = None

    def to_canonical_json_bytes(self) -> bytes:
        # Canonical JSON: stable key order 
        obj = {
            "temperature": self.temperature,
            "top_k": self.top_k,
            "top_p": self.top_p,
            "max_tokens": self.max_tokens,
            "stop": self.stop,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def hash(self) -> bytes:
        # This is what you commit into the PoDL record.
        return sha256(self.to_canonical_json_bytes())

# Calls a llama.cpp server endpoint
def llama_cpp_generate(endpoint: str, prompt: str, cfg: DecodeConfig) -> str:
    payload: Dict[str, Any] = {
        "prompt": prompt,
        "temperature": cfg.temperature,
        "top_k": cfg.top_k,
        "top_p": cfg.top_p,
        "n_predict": cfg.max_tokens,
    }
    if cfg.stop is not None:
        payload["stop"] = [cfg.stop]

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read().decode("utf-8"))

    # llama.cpp responses vary slightly, handle common keys.
    return str(out.get("content") or out.get("completion") or "")

def hash_prompt(prompt: str) -> bytes:
    return sha256(prompt.encode("utf-8"))

def hash_output(output: str) -> bytes:
    return sha256(output.encode("utf-8"))

# Deterministic evalset utilities for PoDL 
def load_evalset_jsonl(evalset_path: str) -> bytes:
    with open(evalset_path, "rb") as f:
        return f.read()

def evalset_hash(evalset_bytes: bytes) -> bytes:
    return sha256(evalset_bytes)

def parse_evalset_pairs(evalset_bytes: bytes) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for line in evalset_bytes.splitlines():
        line = line.strip()
        if not line:
            continue
        o = json.loads(line.decode("utf-8"))
        pairs.append((o["prompt"], o["answer"]))
    return pairs

def normalize_answer(s: str) -> str:
    # Keep normalization simple so it stays reproducible
    return " ".join(s.strip().split()).lower()

def score_exact_match(
    endpoint: str,
    pairs: List[Tuple[str, str]],
    cfg: DecodeConfig,
) -> Tuple[int, int]:
   
    correct = 0
    total = len(pairs)

    for prompt, ans in pairs:
        out = llama_cpp_generate(endpoint, prompt, cfg)

        if normalize_answer(out).startswith(normalize_answer(ans)):
            correct += 1

    return correct, total

def scaled_accuracy(correct: int, total: int, scale: int = 10000) -> int:
    total = max(1, total)
    return (correct * scale) // total

def run_podl_eval(
    endpoint: str,
    evalset_path: str,
    cfg: Optional[DecodeConfig] = None,
    scale: int = 10000,
) -> dict:
    
    # Convenience wrapper for miners/validators: 
    # loads evalset, hashes it, runs deterministic evaluation, returns score as scaled int
    cfg = cfg or DecodeConfig()

    ebytes = load_evalset_jsonl(evalset_path)
    eh = evalset_hash(ebytes)
    pairs = parse_evalset_pairs(ebytes)

    correct, total = score_exact_match(endpoint, pairs, cfg)
    score_scaled = scaled_accuracy(correct, total, scale=scale)

    return {
        "evalset_hash": eh,
        "decode_cfg_hash": cfg.hash(),
        "correct": correct,
        "total": total,
        "score_scaled": score_scaled,
        "score_scale": scale,
    }

