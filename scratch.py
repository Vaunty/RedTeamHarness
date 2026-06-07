from core.database import get_runs
import subprocess, sys

runs = get_runs(4)
# Find the most recent baseline and defended runs
baseline = None
defended = None
for r in runs:
    if r['defense_mode'] == 'baseline' and baseline is None:
        baseline = r['run_id']
    if r['defense_mode'] == 'defended' and defended is None:
        defended = r['run_id']

print(f"Baseline: {baseline[:8]}...")
print(f"Defended: {defended[:8]}...")
subprocess.run([sys.executable, "report.py", "--compare", baseline, defended])
subprocess.run([sys.executable, "report.py", "--run-id", baseline])
