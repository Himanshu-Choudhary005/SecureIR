import pandas as pd
from pathlib import Path

# Dataset location
dataset_path = Path("dataset/security_dataset.csv")

# Check if dataset exists
if not dataset_path.exists():
    print("Error: Dataset file not found!")
    raise SystemExit(1)

# Load dataset
df = pd.read_csv(dataset_path)

print("\n========== SecureIR Dataset ==========")

print("\nFirst 5 records:")
print(df.head())

print("\nDataset shape:")
print(f"Rows: {df.shape[0]}")
print(f"Columns: {df.shape[1]}")

print("\nMissing values:")
print(df.isnull().sum())

print("\nClass distribution:")
print(df["label"].value_counts())

print("\nDataset loaded successfully!")