"""runner.py - the main loop: targets x attacks -> responses -> judge -> log.

Logs BOTH the cheap deterministic check and the LLM judge verdict, so you can
calibrate the judge against ground truth on the benign proxies (see metrics.py).

Results are stored in:
  1. SQLite database (primary) — structured, queryable, with SHA-256 response hashing
  2. JSONL file (secondary) — backward-compatible flat-file export

Usage:
    python runner.py llama3.2:3b qwen2.5:3b
"""
import json
import time
import pathlib
from core.targets import ollama_target
from core.attacks import load_attacks, deterministic_hit
from core.judge import Judge
from core.database import init_db, insert_run, insert_result, finish_run


def run(target_models, attacks_path="data/probes.jsonl", defense=None, judge_runs=3):
    init_db()
    attacks = load_attacks(attacks_path)
    judge = Judge(runs=judge_runs)
    targets = [ollama_target(m) for m in target_models]

    # --- JSONL output (backward-compatible) ---
    out = pathlib.Path(f"results/run_{int(time.time())}.jsonl")
    out.parent.mkdir(exist_ok=True)
    flag = "DEFENDED" if defense else "BASELINE"

    # --- Database run record ---
    defense_mode = "defended" if defense else "baseline"
    run_id = insert_run(
        target_models, defense_mode,
        judge.model, judge.runs
    )
    count = 0

    with out.open("w", encoding="utf-8") as f:
        for tgt in targets:
            for atk in attacks:
                system, user = atk.system, atk.user
                if defense:
                    system, user = defense.apply(system, user)
                response = tgt.generate(system, user)
                if defense:
                    response = defense.filter_output(response)

                hit = deterministic_hit(atk.success_if, response)   # cheap cross-check
                v = judge.judge(atk.technique, atk.system, response)  # the LLM-as-judge verdict

                rec = {
                    "model": tgt.name, "attack": atk.id, "category": atk.category,
                    "owasp": atk.owasp, "mitre": atk.mitre,
                    "technique": atk.technique,
                    "verdict": v.verdict, "severity": v.severity,
                    "deterministic_hit": hit, "votes": v.votes,
                    "reason": v.reason, "response": response,
                }

                # Write to both JSONL and database
                f.write(json.dumps(rec) + "\n")
                insert_result(run_id, rec)
                count += 1
                print(f"[{flag}] {tgt.name:16} {atk.id:8} -> {v.verdict:9} (sev {v.severity})")

    # --- Finalize the run and store metrics ---
    finish_run(run_id, count)

    # Compute and store metrics in the database
    from metrics import asr, refusal_rate, breakdown, judge_vs_deterministic, store_metrics
    from core.database import load_run_results
    recs = load_run_results(run_id)
    store_metrics(run_id, recs)

    print(f"\nWrote {out}  |  DB run: {run_id[:8]}...")
    return str(out), run_id


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    
    defense = None
    if "--defense" in args:
        from core.defenses import Defense
        defense = Defense()
        args.remove("--defense")
        
    models = args or ["llama3.2:3b"]
    run(models, defense=defense)
