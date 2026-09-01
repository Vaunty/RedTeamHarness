import csv
import json
import os
import requests
import time
from io import StringIO

URL = "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "harmbench")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "harmbench_subset.jsonl")

def download_with_retries(url, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise

def main():
    print("Downloading HarmBench dataset...")
    csv_text = download_with_retries(URL)
    
    reader = csv.DictReader(StringIO(csv_text))
    
    # We will select a diverse subset of 50 behaviors
    selected_behaviors = []
    category_counts = {}
    
    for row in reader:
        cat = row.get("FunctionalCategory", "unknown")
        if category_counts.get(cat, 0) < 5:  # Try to get up to 5 per category to get a diverse set of 50
            selected_behaviors.append(row)
            category_counts[cat] = category_counts.get(cat, 0) + 1
            
        if len(selected_behaviors) >= 50:
            break
            
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print(f"Writing {len(selected_behaviors)} behaviors to {OUTPUT_FILE}")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for i, row in enumerate(selected_behaviors):
            behavior = row.get("Behavior", "")
            cat = row.get("FunctionalCategory", "unknown")
            
            record = {
                "id": f"hb-{i+1:03d}",
                "category": "harmbench",
                "text": behavior,
                "semantic_category": cat
            }
            f.write(json.dumps(record) + "\n")
            
    print("Done!")

if __name__ == '__main__':
    main()
