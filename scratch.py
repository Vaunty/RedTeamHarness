from database import get_runs
import os

runs = get_runs(2)
baseline = runs[1]['run_id']
defended = runs[0]['run_id']
os.system(f".\\.venv\\Scripts\\python.exe report.py --compare {baseline} {defended}")
