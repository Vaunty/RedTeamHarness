"""database.py - SQLite persistence layer for red-team harness results.

Stores runs, per-attack verdicts, and pre-computed metrics in a local
SQLite database. Each response is SHA-256 hashed for integrity verification
(chain-of-custody pattern — proves a response wasn't tampered with after the fact).

Why SQLite:
  - Zero infrastructure (ships with Python, no server to install)
  - Single-file database (.db) — portable, backs up trivially
  - Same SQL skills that transfer to MySQL/Postgres in production
  - More than enough for this scale (hundreds to low-thousands of records)

Usage:
    from database import init_db, insert_run, insert_result, insert_metrics
    init_db()
    run_id = insert_run(["llama3.2:3b"], defense_mode="baseline", ...)
    insert_result(run_id, {...})
"""
import sqlite3
import hashlib
import uuid
import json
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "harness.db"

def _connect():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")       # safe concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row                 # dict-like access
    return conn


def init_db():
    """Create or migrate the database schema."""
    conn = _connect()
    conn.executescript("""
        -- Every harness run gets a unique record
        CREATE TABLE IF NOT EXISTS runs (
            run_id        TEXT PRIMARY KEY,
            started_at    TEXT NOT NULL,
            finished_at   TEXT,
            target_models TEXT NOT NULL,
            defense_mode  TEXT NOT NULL,
            judge_model   TEXT NOT NULL,
            judge_runs    INTEGER NOT NULL,
            probe_count   INTEGER,
            notes         TEXT
        );

        -- Each attack probe attempt and its verdict
        CREATE TABLE IF NOT EXISTS results (
            result_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id            TEXT NOT NULL REFERENCES runs(run_id),
            model             TEXT NOT NULL,
            attack_id         TEXT NOT NULL,
            category          TEXT NOT NULL,
            owasp             TEXT NOT NULL,
            mitre             TEXT,
            technique         TEXT NOT NULL,
            verdict           TEXT NOT NULL,
            severity          INTEGER NOT NULL,
            deterministic_hit INTEGER,
            votes             TEXT,
            reason            TEXT,
            response_hash     TEXT,
            response          TEXT,
            created_at        TEXT NOT NULL
        );

        -- Pre-computed metrics per run
        CREATE TABLE IF NOT EXISTS run_metrics (
            metric_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id          TEXT NOT NULL REFERENCES runs(run_id),
            metric_name     TEXT NOT NULL,
            metric_value    REAL NOT NULL,
            breakdown_key   TEXT,
            breakdown_value TEXT,
            UNIQUE(run_id, metric_name, breakdown_key, breakdown_value)
        );

        -- Indexes for fast lookups
        CREATE INDEX IF NOT EXISTS idx_results_run     ON results(run_id);
        CREATE INDEX IF NOT EXISTS idx_results_model   ON results(model);
        CREATE INDEX IF NOT EXISTS idx_results_owasp   ON results(owasp);
        CREATE INDEX IF NOT EXISTS idx_results_verdict ON results(verdict);
        CREATE INDEX IF NOT EXISTS idx_metrics_run     ON run_metrics(run_id);
    """)
    conn.commit()
    conn.close()


def hash_response(text):
    """SHA-256 hash of a response for integrity verification."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def insert_run(target_models, defense_mode, judge_model, judge_runs, notes=None):
    """Create a new run record. Returns the run_id (UUID)."""
    run_id = str(uuid.uuid4())
    conn = _connect()
    conn.execute(
        "INSERT INTO runs (run_id, started_at, target_models, defense_mode, judge_model, judge_runs, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (run_id, datetime.now(timezone.utc).isoformat(), json.dumps(target_models),
         defense_mode, judge_model, judge_runs, notes)
    )
    conn.commit()
    conn.close()
    return run_id


def finish_run(run_id, probe_count):
    """Mark a run as finished."""
    conn = _connect()
    conn.execute(
        "UPDATE runs SET finished_at = ?, probe_count = ? WHERE run_id = ?",
        (datetime.now(timezone.utc).isoformat(), probe_count, run_id)
    )
    conn.commit()
    conn.close()


def insert_result(run_id, rec):
    """Insert a single verdict row. `rec` is the dict that runner.py builds.
    Automatically computes SHA-256 hash of the response."""
    conn = _connect()
    resp = rec.get("response", "")
    det = rec.get("deterministic_hit")
    det_int = None if det is None else (1 if det else 0)
    conn.execute(
        "INSERT INTO results "
        "(run_id, model, attack_id, category, owasp, mitre, technique, verdict, severity, "
        " deterministic_hit, votes, reason, response_hash, response, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, rec["model"], rec["attack"], rec["category"], rec["owasp"],
         rec.get("mitre", ""), rec.get("technique", ""), rec["verdict"], rec["severity"],
         det_int, json.dumps(rec.get("votes", {})), rec.get("reason", ""),
         hash_response(resp), resp, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()


def insert_metrics(run_id, metrics_dict):
    """Store pre-computed metrics for a run.
    metrics_dict format: {metric_name: value} for overall metrics,
    or {metric_name: {breakdown_key: {breakdown_value: value}}} for breakdowns.
    """
    conn = _connect()
    for name, value in metrics_dict.items():
        if isinstance(value, dict):
            # It's a breakdown: {key: {val: metric_val}}
            for bk, bv_dict in value.items():
                if isinstance(bv_dict, dict):
                    for bv, mv in bv_dict.items():
                        conn.execute(
                            "INSERT OR REPLACE INTO run_metrics "
                            "(run_id, metric_name, metric_value, breakdown_key, breakdown_value) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (run_id, name, mv, bk, bv)
                        )
                else:
                    # Simple key: value breakdown like {"llama3.2:3b": 0.5}
                    conn.execute(
                        "INSERT OR REPLACE INTO run_metrics "
                        "(run_id, metric_name, metric_value, breakdown_key, breakdown_value) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (run_id, name, bv_dict, name, bk)
                    )
        else:
            # Overall metric
            conn.execute(
                "INSERT OR REPLACE INTO run_metrics "
                "(run_id, metric_name, metric_value, breakdown_key, breakdown_value) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, name, value, None, None)
            )
    conn.commit()
    conn.close()


def load_run_results(run_id):
    """Load all results for a run as a list of dicts (same shape as JSONL records)."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM results WHERE run_id = ? ORDER BY result_id", (run_id,)
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        det = r["deterministic_hit"]
        out.append({
            "model": r["model"], "attack": r["attack_id"],
            "category": r["category"], "owasp": r["owasp"], "mitre": r["mitre"],
            "technique": r["technique"], "verdict": r["verdict"],
            "severity": r["severity"],
            "deterministic_hit": None if det is None else bool(det),
            "votes": json.loads(r["votes"] or "{}"),
            "reason": r["reason"], "response": r["response"],
            "response_hash": r["response_hash"],
        })
    return out


def get_runs(limit=20):
    """List recent runs."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_run_metrics(run_id):
    """Get stored metrics for a run."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM run_metrics WHERE run_id = ?", (run_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_run_comparison(baseline_run_id, defended_run_id):
    """Compare ASR between a baseline and defended run."""
    conn = _connect()
    result = {}
    for label, rid in [("baseline", baseline_run_id), ("defended", defended_run_id)]:
        row = conn.execute(
            "SELECT metric_value FROM run_metrics "
            "WHERE run_id = ? AND metric_name = 'overall_asr' AND breakdown_key IS NULL",
            (rid,)
        ).fetchone()
        result[label] = row["metric_value"] if row else None
    conn.close()
    if result["baseline"] is not None and result["defended"] is not None:
        result["delta"] = round(result["baseline"] - result["defended"], 4)
        result["reduction_pct"] = round(
            (result["delta"] / result["baseline"]) * 100, 1
        ) if result["baseline"] > 0 else 0.0
    return result


if __name__ == "__main__":
    # Self-test: create DB, insert a dummy run, verify round-trip
    init_db()
    rid = insert_run(["test-model"], "baseline", "gpt-4o", 3, "self-test")
    rec = {
        "model": "test-model", "attack": "test-001", "category": "data_leak",
        "owasp": "LLM06", "mitre": "AML.T0024", "technique": "test technique",
        "verdict": "complied", "severity": 4, "deterministic_hit": True,
        "votes": {"complied": 3}, "reason": "test reason",
        "response": "The secret is BANANA-42",
    }
    insert_result(rid, rec)
    finish_run(rid, 1)
    insert_metrics(rid, {"overall_asr": 1.0, "refusal_rate": 0.0})

    # Verify
    results = load_run_results(rid)
    assert len(results) == 1
    assert results[0]["verdict"] == "complied"
    assert results[0]["response_hash"] == hash_response("The secret is BANANA-42")
    runs = get_runs()
    assert any(r["run_id"] == rid for r in runs)
    print(f"Self-test PASSED. Run {rid[:8]}... created with {len(results)} result(s).")
    print(f"  Response hash: {results[0]['response_hash'][:16]}...")

    # Clean up test data
    conn = _connect()
    conn.execute("DELETE FROM run_metrics WHERE run_id = ?", (rid,))
    conn.execute("DELETE FROM results WHERE run_id = ?", (rid,))
    conn.execute("DELETE FROM runs WHERE run_id = ?", (rid,))
    conn.commit()
    conn.close()
    print("  Test data cleaned up.")
