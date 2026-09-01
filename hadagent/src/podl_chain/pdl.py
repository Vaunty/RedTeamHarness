from __future__ import annotations
import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple
from .crypto import sha256

@dataclass(frozen=True)
class DecodeConfig:
    temperature: float = 0.0
    top_k: int = 1
    top_p: float = 1.0
    max_tokens: int = 64
    stop: str | None = None

    def to_canonical_json(self) -> bytes:
        obj = {
            "temperature": self.temperature,
            "top_k": self.top_k,
            "top_p": self.top_p,
            "max_tokens": self.max_tokens,
            "stop": self.stop,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def hash(self) -> bytes:
        return sha256(self.to_canonical_json())

def llama_cpp_completion(endpoint: str, prompt: str, cfg: DecodeConfig) -> str:
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

    # Different llama.cpp builds return different keys.
    text = out.get("content") or out.get("completion") or ""
    return str(text)


def load_evalset_bytes(evalset_path: str) -> bytes:
    with open(evalset_path, "rb") as f:
        return f.read()

def evalset_hash(evalset_bytes: bytes) -> bytes:
    return sha256(evalset_bytes)

def parse_evalset_jsonl(evalset_bytes: bytes) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for line in evalset_bytes.splitlines():
        line = line.strip()
        if not line:
            continue
        o = json.loads(line.decode("utf-8"))
        pairs.append((o["prompt"], o["answer"]))
    return pairs

def normalize_answer(s: str) -> str:
    return " ".join(s.strip().split()).lower()

def score_exact_match(endpoint: str, pairs: List[Tuple[str, str]], cfg: DecodeConfig) -> int:
    correct = 0
    for prompt, ans in pairs:
        out = llama_cpp_completion(endpoint, prompt, cfg)
        if normalize_answer(out).startswith(normalize_answer(ans)):
            correct += 1
    return correct

# payload_obj is unpacked msgpack dict from the PoDL record payload
# required_min_score_scaled: consensus threshold
def verify_podl_llm_eval(
    payload_obj: dict,
    evalset_path: str,
    required_min_score_scaled: int,
) -> tuple[bool, str]:
    
    if payload_obj["provider"] != "llama.cpp":
        return False, "unsupported provider"

    # Check evalset hash matches local evalset bytes
    ebytes = load_evalset_bytes(evalset_path)
    if sha256(ebytes) != payload_obj["evalset_hash"]:
        return False, "evalset hash mismatch"

    # Recreate decode config from a fixed, agreed config
    cfg = DecodeConfig(
        temperature=0.0,
        top_k=1,
        top_p=1.0,
        max_tokens=64,
        stop=None,
    )
    if cfg.hash() != payload_obj["decode_cfg_hash"]:
        return False, "decode config hash mismatch"

    # Deterministic evaluation
    pairs = parse_evalset_jsonl(ebytes)
    correct = score_exact_match(payload_obj["endpoint"], pairs, cfg)
    total = max(1, len(pairs))

    # scaled accuracy = correct/total * scale
    scale = int(payload_obj["score_scale"])
    computed_scaled = (correct * scale) // total

    # Check miner’s claim is honest and meets threshold
    if computed_scaled != int(payload_obj["claimed_score_scaled"]):
        return False, f"claimed score mismatch (computed {computed_scaled})"

    if computed_scaled < required_min_score_scaled:
        return False, f"score below target ({computed_scaled} < {required_min_score_scaled})"

    return True, "ok"