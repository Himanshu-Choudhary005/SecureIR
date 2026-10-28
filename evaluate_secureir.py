import csv
import subprocess
import sys
from pathlib import Path

import pandas as pd
from joblib import load

from feature_extractor import extract_features
from static_analyzer import analyze_ir_security


ROOT = Path(__file__).resolve().parent
SOURCE_DIR = ROOT / "dataset" / "source"
IR_DIR = ROOT / "dataset" / "ir"
REPORT_DIR = ROOT / "reports"
MODEL_PATH = ROOT / "secureir_model.joblib"
OUTPUT_CSV = ROOT / "dataset" / "automated_evaluation.csv"

CLANG = Path(
    r"C:\Users\HIMANSHU CHOUDHARY\Downloads"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc.tar"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc"
    r"\bin\clang.exe"
)

LABEL_MAP = {
    "safe": "SAFE",
    "memory_risk": "MEMORY_RISK",
    "integer_risk": "INTEGER_RISK",
}


def get_ir_path(source_file):
    category = source_file.parent.name.lower()
    return IR_DIR / category / f"{source_file.stem}.ll"


def compile_to_ir(source_file, ir_file):
    ir_file.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(CLANG),
        "-S",
        "-emit-llvm",
        "-O0",
        "-Wno-everything",
        str(source_file),
        "-o",
        str(ir_file),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
    )

    return result.returncode == 0, result.stderr.strip()


def main():
    if not MODEL_PATH.exists():
        print(f"ERROR: Model not found: {MODEL_PATH}")
        sys.exit(1)

    if not CLANG.exists():
        print(f"ERROR: Clang not found: {CLANG}")
        sys.exit(1)

    if not SOURCE_DIR.exists():
        print(f"ERROR: Source directory not found: {SOURCE_DIR}")
        sys.exit(1)

    model = load(MODEL_PATH)
    source_files = sorted(SOURCE_DIR.rglob("*.c"))

    if not source_files:
        print(f"ERROR: No C programs found in {SOURCE_DIR}")
        sys.exit(1)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    results = []
    successful = 0
    failed = 0
    correct = 0

    print("=" * 65)
    print("          SecureIR Automated Evaluation")
    print("=" * 65)
    print(f"Programs found: {len(source_files)}")
    print("Programs will be compiled for IR analysis, not executed.")
    print()

    for source_file in source_files:
        category = source_file.parent.name.lower()
        actual_label = LABEL_MAP.get(category, "UNKNOWN")
        ir_file = get_ir_path(source_file)

        try:
            compiled, error = compile_to_ir(source_file, ir_file)

            if not compiled:
                failed += 1

                results.append({
                    "program": source_file.stem,
                    "actual_label": actual_label,
                    "predicted_label": "",
                    "prediction_correct": "",
                    "compile_success": False,
                    "static_findings_count": "",
                    "review_findings_count": "",
                    "analysis_success": False,
                    "error": error,
                })

                print(
                    f"[FAILED] {source_file.stem}: "
                    "LLVM IR compilation failed"
                )
                continue

            features = extract_features(ir_file)

            feature_values = pd.DataFrame(
                [[features[name] for name in model.feature_names_in_]],
                columns=model.feature_names_in_,
            )

            prediction = model.predict(feature_values)[0]
            findings = analyze_ir_security(ir_file)

            review_count = sum(
                finding["severity"] == "REVIEW"
                for finding in findings
            )

            prediction_correct = prediction == actual_label

            successful += 1

            if prediction_correct:
                correct += 1

            results.append({
                "program": source_file.stem,
                "actual_label": actual_label,
                "predicted_label": prediction,
                "prediction_correct": prediction_correct,
                "compile_success": True,
                "static_findings_count": len(findings),
                "review_findings_count": review_count,
                "analysis_success": True,
                "error": "",
            })

            status = "CORRECT" if prediction_correct else "MISMATCH"

            print(
                f"[{status}] {source_file.stem}: "
                f"actual={actual_label}, predicted={prediction}"
            )

        except Exception as exc:
            failed += 1

            results.append({
                "program": source_file.stem,
                "actual_label": actual_label,
                "predicted_label": "",
                "prediction_correct": "",
                "compile_success": False,
                "static_findings_count": "",
                "review_findings_count": "",
                "analysis_success": False,
                "error": str(exc),
            })

            print(f"[FAILED] {source_file.stem}: {exc}")

    fieldnames = [
        "program",
        "actual_label",
        "predicted_label",
        "prediction_correct",
        "compile_success",
        "static_findings_count",
        "review_findings_count",
        "analysis_success",
        "error",
    ]

    with OUTPUT_CSV.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print()
    print("=" * 65)
    print("                  Evaluation Summary")
    print("=" * 65)
    print(f"Programs found      : {len(source_files)}")
    print(f"Analyses successful : {successful}")
    print(f"Failed analyses     : {failed}")

    if successful > 0:
        accuracy = (correct / successful) * 100

        print(f"Correct predictions : {correct}/{successful}")
        print(f"Accuracy on analyzed programs: {accuracy:.2f}%")

    print()
    print(f"CSV saved to: {OUTPUT_CSV}")
    print()
    print(
        "WARNING: These source programs were used to build "
        "the current dataset. This result is not independent "
        "test accuracy."
    )


if __name__ == "__main__":
    main()