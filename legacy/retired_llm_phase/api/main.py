"""api/main.py - FastAPI backend for the Red-Team Harness web dashboard.

Serves harness run data from the SQLite database over a clean REST API.
The React frontend consumes these endpoints to render the dashboard views.

Usage:
    uvicorn api.main:app --reload --port 8000
"""
import sys
from pathlib import Path

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from core.database import (
    init_db, get_runs, load_run_results,
    get_run_metrics, get_run_comparison, _connect
)

app = FastAPI(
    title="Red-Team Harness API",
    description="REST API serving LLM red-teaming results, metrics, and compliance data.",
    version="2.0.0",
)

# Allow the Vite dev server to talk to us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


# ── Runs ─────────────────────────────────────────────────────────────────

@app.get("/api/runs")
def list_runs(limit: int = Query(default=50, le=200)):
    """List all runs, most recent first."""
    runs = get_runs(limit=limit)
    import json
    for r in runs:
        try:
            r["target_models"] = json.loads(r["target_models"])
        except (json.JSONDecodeError, TypeError):
            pass
    return runs


@app.get("/api/runs/compare")
def compare_runs(
    baseline: str = Query(..., description="Run ID for the baseline (undefended) run"),
    defended: str = Query(..., description="Run ID for the defended run"),
):
    """Compare ASR between a baseline and defended run."""
    comparison = get_run_comparison(baseline, defended)
    if comparison.get("baseline") is None:
        raise HTTPException(status_code=404, detail="Baseline run metrics not found")
    if comparison.get("defended") is None:
        raise HTTPException(status_code=404, detail="Defended run metrics not found")
    return comparison


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    """Get metadata for a single run."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    import json
    result = dict(row)
    try:
        result["target_models"] = json.loads(result["target_models"])
    except (json.JSONDecodeError, TypeError):
        pass
    return result


# ── Results ──────────────────────────────────────────────────────────────

@app.get("/api/runs/{run_id}/results")
def get_results(run_id: str):
    """Get all verdict rows for a run (transcripts, verdicts, severity)."""
    results = load_run_results(run_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"No results found for run {run_id}")
    return results


# ── Metrics ──────────────────────────────────────────────────────────────

@app.get("/api/runs/{run_id}/metrics")
def get_metrics(run_id: str):
    """Get pre-computed metrics for a run.

    Returns a structured object with overall metrics and breakdowns
    organized for easy frontend consumption.
    """
    raw_metrics = get_run_metrics(run_id)
    if not raw_metrics:
        raise HTTPException(status_code=404, detail=f"No metrics found for run {run_id}")

    # Restructure the flat metric rows into a nested object
    overall = {}
    breakdowns = {}

    for m in raw_metrics:
        name = m["metric_name"]
        value = m["metric_value"]
        bk = m.get("breakdown_key")
        bv = m.get("breakdown_value")

        if bk is None and bv is None:
            # Overall metric (e.g., overall_asr, refusal_rate)
            overall[name] = value
        else:
            # Breakdown metric
            if name not in breakdowns:
                breakdowns[name] = {}
            
            if bk == name:
                # Simple breakdown (database inserted bk as the metric_name)
                breakdowns[name][bv] = value
            else:
                # Nested breakdown (e.g., scatter_asr -> category -> severity)
                if bk not in breakdowns[name]:
                    breakdowns[name][bk] = {}
                breakdowns[name][bk][bv] = value

    return {"overall": overall, "breakdowns": breakdowns}


# ── Health ───────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    """Health check endpoint."""
    conn = _connect()
    run_count = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    result_count = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
    conn.close()
    return {
        "status": "healthy",
        "runs": run_count,
        "results": result_count,
    }
