import json
from pathlib import Path
import matplotlib.pyplot as plt

# Load baseline metrics
metrics_path = Path("test_results/baseline_metrics.json")
with metrics_path.open("r") as f:
    data = json.load(f)

cases = data["cases"]

# Group latencies by category
grouped = {
    "record": [],
    "block": [],
    "hub": [],
    "pool": [],
}

for case in cases:
    category = case["category"]
    latency = case["latency_ms"]
    if category in grouped:
        grouped[category].append(latency)

# Define line styles for each category
line_styles = {
    "record": "-",
    "block": "--",
    "hub": ":",
    "pool": "-.",
}

plt.figure(figsize=(8, 4.5))

for category, latencies in grouped.items():
    if latencies:
        x = list(range(1, len(latencies) + 1))
        plt.plot(
            x,
            latencies,
            linestyle=line_styles[category],   # different line types
            marker="o",
            linewidth=2.5,                    # thicker lines
            markersize=5,
            label=category.capitalize()
        )

plt.xlabel("Test Case Index")
plt.ylabel("Latency (ms)")
plt.title("Baseline Validation Latency by Test Category")

plt.legend(handlelength=3)
plt.grid(True, alpha=0.3)
plt.tight_layout()

plt.savefig("baseline_latency.png", dpi=300)
plt.show()