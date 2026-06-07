# compare.py
from runner import run
from core.defenses import Defense
from metrics import load, asr, breakdown
import sys

# We only want to test llama3.2:3b for speed
model = "llama3.2:3b"

print("--- Running Baseline ---")
baseline_path = run([model])

print("\n--- Running Defended ---")
defended_path = run([model], defense=Defense())

b, d = load(baseline_path), load(defended_path)
print("\n=== Results ===")
print(f"ASR  baseline: {asr(b):.1%}  ->  defended: {asr(d):.1%}")
print(f"Delta: {asr(b) - asr(d):+.1%}")
print(f"\nBaseline by category: {breakdown(b, 'category')}")
print(f"Defended by category: {breakdown(d, 'category')}")
