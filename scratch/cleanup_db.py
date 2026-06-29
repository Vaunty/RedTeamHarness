"""cleanup_db.py - Clean up harness database by removing redundant, incomplete, and superseded runs.
"""
import sqlite3

RUNS_TO_DELETE = [
    # Redundant/superseded text runs
    "d5b51b30-62d9-41f1-b18a-47a54edabc74",
    "fb680e0a-a721-4b58-8a90-55a01cc6e2f3",
    "c5061f4d-5e07-4a60-98b6-60834ba33aaa",
    "8165d51e-cf27-4d81-801c-39248541b1a7",
    
    # Redundant/incomplete VLM runs
    "4be542e8-e97f-40dc-bd44-b11f3c6356ea",
    "a3500b91-baf2-45f9-b436-7e0325f3c159",
    "fa1b902d-9d57-41c7-8514-3dde79acfcdf",
    "60ce327c-0e1d-4935-b6ef-32873b1f96cd"
]

def main():
    conn = sqlite3.connect("harness.db")
    # Temporarily disable foreign key constraints to prevent deletion block,
    # or just delete child rows manually (cleaner).
    conn.execute("PRAGMA foreign_keys = OFF;")
    cursor = conn.cursor()
    
    print("=== Database Cleanup ===")
    
    # 1. Print existing counts
    runs_count = cursor.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    results_count = cursor.execute("SELECT COUNT(*) FROM results").fetchone()[0]
    metrics_count = cursor.execute("SELECT COUNT(*) FROM run_metrics").fetchone()[0]
    print(f"Pre-cleanup counts: Runs: {runs_count}, Results: {results_count}, Metrics: {metrics_count}\n")
    
    for run_id in RUNS_TO_DELETE:
        print(f"Deleting run {run_id}...")
        cursor.execute("DELETE FROM run_metrics WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM results WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        
    conn.commit()
    
    # 2. Print post-cleanup counts
    runs_count_post = cursor.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    results_count_post = cursor.execute("SELECT COUNT(*) FROM results").fetchone()[0]
    metrics_count_post = cursor.execute("SELECT COUNT(*) FROM run_metrics").fetchone()[0]
    
    print(f"\nPost-cleanup counts: Runs: {runs_count_post}, Results: {results_count_post}, Metrics: {metrics_count_post}")
    print(f"Removed: Runs: {runs_count - runs_count_post}, Results: {results_count - results_count_post}, Metrics: {metrics_count - metrics_count_post}")
    
    # List remaining runs
    print("\n=== Remaining Runs ===")
    remaining = cursor.execute("SELECT run_id, target_models, defense_mode, started_at FROM runs").fetchall()
    for r in remaining:
        print(f"Run ID: {r[0]} | Models: {r[1]} | Defense: {r[2]} | Started: {r[3]}")
        
    conn.close()

if __name__ == "__main__":
    main()
