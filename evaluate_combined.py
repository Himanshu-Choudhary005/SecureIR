
import csv
import sys
from pathlib import Path

from secureir_analyzer import compile_c_to_ir, analyze_ir


ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = ROOT / "independent_test" / "source"
OUTPUT_CSV = ROOT / "independent_test" / "combined_evaluation.csv"

CATEGORIES = {
    "safe": "SAFE",
    "memory_risk": "MEMORY_RISK",
    "integer_risk": "INTEGER_RISK",
}


def main():
    rows = []

    for folder, actual_class in CATEGORIES.items():
        category_dir = SOURCE_ROOT / folder

        if not category_dir.exists():
            print(f"[WARNING] Folder not found: {category_dir}")
            continue

        for source_path in sorted(category_dir.glob("*.c")):
            print(f"\nAnalyzing: {source_path.name}")

            try:
                # Compile to LLVM IR; do not execute the C program.
                ir_path = compile_c_to_ir(source_path)

                # Run the existing combined analyzer.
                # This prints and saves its normal report.
                analyze_ir(ir_path)

                # Read the generated report to collect results.
                report_path = (
                    ROOT / "reports" / f"{ir_path.stem}_report.txt"
                )

                # Reports may have numbered names if the base name exists.
                candidates = sorted(
                    (ROOT / "reports").glob(
                        f"{ir_path.stem}_report*.txt"
                    ),
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                )

                if not candidates:
                    raise FileNotFoundError(
                        f"No report found for {source_path.name}"
                    )

                report_text = candidates[0].read_text(
                    encoding="utf-8"
                )

                prediction = ""
                assessment = ""
                review_count = 0

                for line in report_text.splitlines():
                    if line.startswith("ML Predicted Class :"):
                        prediction = line.split(":", 1)[1].strip()

                    elif line.startswith("--- Overall Security Assessment ---"):
                        continue

                    elif line.startswith("POTENTIAL RISK -"):
                        assessment = "POTENTIAL RISK"

                    elif line.startswith("ML FLAGGED RISK -"):
                        assessment = "ML FLAGGED RISK"

                    elif line.startswith(
                        "NO CONFIGURED REVIEW PATTERNS DETECTED -"
                    ):
                        assessment = "NO REVIEW PATTERNS DETECTED"

                    elif line.startswith("Review findings"):
                        try:
                            review_count = int(
                                line.split(":", 1)[1].strip()
                            )
                        except ValueError:
                            pass

                rows.append({
                    "program": source_path.name,
                    "actual_class": actual_class,
                    "ml_prediction": prediction,
                    "ml_correct": prediction == actual_class,
                    "review_findings": review_count,
                    "overall_assessment": assessment,
                    "analysis_success": bool(prediction and assessment),
                    "error": "",
                })

                print(
                    f"Result: actual={actual_class}, "
                    f"ML={prediction}, "
                    f"review_findings={review_count}, "
                    f"assessment={assessment}"
                )

            except Exception as exc:
                rows.append({
                    "program": source_path.name,
                    "actual_class": actual_class,
                    "ml_prediction": "",
                    "ml_correct": "",
                    "review_findings": "",
                    "overall_assessment": "",
                    "analysis_success": False,
                    "error": str(exc),
                })

                print(f"[FAILED] {source_path.name}: {exc}")

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "program",
        "actual_class",
        "ml_prediction",
        "ml_correct",
        "review_findings",
        "overall_assessment",
        "analysis_success",
        "error",
    ]

    with OUTPUT_CSV.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    successful = [
        row for row in rows if row["analysis_success"]
    ]

    correct = sum(
        row["ml_correct"] is True
        for row in successful
    )

    print("\n" + "=" * 60)
    print("SecureIR Combined Evaluation Summary")
    print("=" * 60)
    print(f"Programs found       : {len(rows)}")
    print(f"Successful analyses  : {len(successful)}")
    print(f"Failed analyses      : {len(rows) - len(successful)}")

    if successful:
        print(
            f"ML accuracy on successful analyses: "
            f"{correct / len(successful) * 100:.2f}%"
        )

    print(f"\nCSV saved to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
