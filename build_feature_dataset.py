import sys
import csv
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent
IR_DIR = BASE_DIR / "dataset" / "ir"
OUTPUT_FILE = BASE_DIR / "dataset" / "features.csv"

# Import the existing feature extractor
sys.path.insert(0, str(BASE_DIR))
from feature_extractor import extract_features

# Prepare dataset
rows = []

for category_dir in sorted(IR_DIR.iterdir()):

    if not category_dir.is_dir():
        continue

    label = category_dir.name.upper()

    for ir_file in sorted(category_dir.glob("*.ll")):

        try:
            features = extract_features(ir_file)

            row = {
                "program": ir_file.stem,
                "label": label,
                **features
            }

            rows.append(row)
            print(f"[SUCCESS] {ir_file.name}")

        except Exception as error:
            print(f"[FAILED] {ir_file.name}: {error}")

if not rows:
    print("No features extracted. Check the IR directory.")
    raise SystemExit(1)

# Write CSV
fieldnames = ["program", "label"] + [
    key for key in rows[0] if key not in ("program", "label")
]

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print("\n===================================")
print(f"Programs processed: {len(rows)}")
print(f"Dataset saved to: {OUTPUT_FILE}")
print("===================================")