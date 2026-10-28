import csv
import subprocess
import sys
from pathlib import Path

import pandas as pd
from joblib import load
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

from feature_extractor import extract_features


# ============================================================
# SecureIR: Independent Test Dataset and Evaluation
# ============================================================

ROOT = Path(__file__).resolve().parent

MODEL_PATH = ROOT / "secureir_model.joblib"

TEST_ROOT = ROOT / "independent_test"
SOURCE_ROOT = TEST_ROOT / "source"
IR_ROOT = TEST_ROOT / "ir"

PREDICTIONS_CSV = TEST_ROOT / "independent_predictions.csv"
REPORT_FILE = TEST_ROOT / "evaluation_report.txt"

CLANG = Path(
    r"C:\Users\HIMANSHU CHOUDHARY\Downloads"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc.tar"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc"
    r"\bin\clang.exe"
)

LABELS = ["INTEGER_RISK", "MEMORY_RISK", "SAFE"]

# New examples. These are compiled for analysis only.
# Risky programs must NEVER be executed.


TEST_PROGRAMS = {
    "safe": {
        "safe_test_01.c": r"""
int main(void) {
    int a = 10;
    int b = 20;
    int result = a + b;
    return result == 30 ? 0 : 1;
}
""",
        "safe_test_02.c": r"""
int main(void) {
    int values[4] = {2, 4, 6, 8};
    int total = 0;

    for (int i = 0; i < 4; i++) {
        total += values[i];
    }

    return total == 20 ? 0 : 1;
}
""",
        "safe_test_03.c": r"""
int square(int value) {
    return value * value;
}

int main(void) {
    return square(5) == 25 ? 0 : 1;
}
""",
        "safe_test_04.c": r"""
int main(void) {
    int temperature = 25;

    if (temperature > 0) {
        return 0;
    }

    return 1;
}
""",
    },

    "memory_risk": {
        "memory_test_01.c": r"""
int main(void) {
    int *ptr = 0;
    return *ptr;
}
""",
        "memory_test_02.c": r"""
int *make_pointer(void) {
    int local_value = 100;
    return &local_value;
}

int main(void) {
    int *ptr = make_pointer();
    return *ptr;
}
""",
        "memory_test_03.c": r"""
int main(void) {
    int values[3] = {10, 20, 30};
    int index = 5;
    return values[index];
}
""",
        "memory_test_04.c": r"""
int main(void) {
    int *ptr = 0;
    int *alias = ptr;

    if (alias == 0) {
        return *alias;
    }

    return 0;
}
""",
    },

    "integer_risk": {
        "integer_test_01.c": r"""
int main(void) {
    volatile int value = 2147483647;
    return value + 1;
}
""",
        "integer_test_02.c": r"""
int divide_values(int numerator, int denominator) {
    return numerator / denominator;
}

int main(void) {
    volatile int denominator = 0;
    return divide_values(100, denominator);
}
""",
        "integer_test_03.c": r"""
int main(void) {
    volatile unsigned int value = 1U;
    volatile unsigned int shift = 32U;
    return value << shift;
}
""",
        "integer_test_04.c": r"""
int main(void) {
    volatile int numerator = -2147483647 - 1;
    volatile int denominator = -1;
    return numerator / denominator;
}
""",
    },
}


def create_test_dataset():
    """Create a new source dataset separate from the training folders."""

    for category, programs in TEST_PROGRAMS.items():
        category_dir = SOURCE_ROOT / category
        category_dir.mkdir(parents=True, exist_ok=True)

        for filename, source_code in programs.items():
            source_path = category_dir / filename
            source_path.write_text(
                source_code.strip() + "\n",
                encoding="utf-8",
            )

    print("Created independent test source files.")


def compile_to_ir(source_path, ir_path):
    """Compile C source into LLVM IR. Never execute the program."""

    ir_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(CLANG),
        "-S",
        "-emit-llvm",
        "-O0",
        "-Wno-everything",
        str(source_path),
        "-o",
        str(ir_path),
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

    model = load(MODEL_PATH)

    if not hasattr(model, "feature_names_in_"):
        print(
            "ERROR: The model does not expose feature_names_in_. "
            "Check how train_model.py trains the model."
        )
        sys.exit(1)

    create_test_dataset()

    results = []
    failures = 0

    print()
    print("=" * 65)
    print("       SecureIR Independent Evaluation")
    print("=" * 65)
    print("Training dataset: dataset/source/")
    print("Independent test dataset: independent_test/source/")
    print("Programs will be compiled, not executed.")
    print()

    for category, programs in TEST_PROGRAMS.items():
        actual_label = {
            "safe": "SAFE",
            "memory_risk": "MEMORY_RISK",
            "integer_risk": "INTEGER_RISK",
        }[category]

        for filename in programs:
            source_path = SOURCE_ROOT / category / filename
            ir_path = IR_ROOT / category / (Path(filename).stem + ".ll")

            try:
                compiled, compile_error = compile_to_ir(
                    source_path,
                    ir_path,
                )

                if not compiled:
                    failures += 1
                    results.append({
                        "program": Path(filename).stem,
                        "actual_label": actual_label,
                        "predicted_label": "",
                        "correct": "",
                        "compile_success": False,
                        "error": compile_error,
                    })

                    print(f"[COMPILE FAILED] {filename}")
                    continue

                features = extract_features(ir_path)

                feature_names = list(model.feature_names_in_)

                missing = [
                    name for name in feature_names
                    if name not in features
                ]

                if missing:
                    raise ValueError(
                        "Missing model features: " + ", ".join(missing)
                    )

                feature_frame = pd.DataFrame(
                    [[features[name] for name in feature_names]],
                    columns=feature_names,
                )

                prediction = str(model.predict(feature_frame)[0])
                is_correct = prediction == actual_label

                results.append({
                    "program": Path(filename).stem,
                    "actual_label": actual_label,
                    "predicted_label": prediction,
                    "correct": is_correct,
                    "compile_success": True,
                    "error": "",
                })

                status = "CORRECT" if is_correct else "MISMATCH"

                print(
                    f"[{status}] {Path(filename).stem}: "
                    f"actual={actual_label}, predicted={prediction}"
                )

            except Exception as exc:
                failures += 1

                results.append({
                    "program": Path(filename).stem,
                    "actual_label": actual_label,
                    "predicted_label": "",
                    "correct": "",
                    "compile_success": False,
                    "error": str(exc),
                })

                print(f"[FAILED] {filename}: {exc}")

    PREDICTIONS_CSV.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "program",
        "actual_label",
        "predicted_label",
        "correct",
        "compile_success",
        "error",
    ]

    with PREDICTIONS_CSV.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    valid_results = [
        row for row in results
        if row["compile_success"]
        and row["predicted_label"] != ""
    ]

    y_true = [row["actual_label"] for row in valid_results]
    y_pred = [row["predicted_label"] for row in valid_results]

    report_lines = []

    report_lines.append("=" * 65)
    report_lines.append("SecureIR Independent Evaluation Report")
    report_lines.append("=" * 65)
    report_lines.append(f"Test programs defined: {sum(map(len, TEST_PROGRAMS.values()))}")
    report_lines.append(f"Successful predictions: {len(valid_results)}")
    report_lines.append(f"Failed analyses: {failures}")
    report_lines.append("")

    if valid_results:
        accuracy = accuracy_score(y_true, y_pred)

        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true,
            y_pred,
            labels=LABELS,
            average="macro",
            zero_division=0,
        )

        report_lines.append(f"Accuracy:  {accuracy:.4f} ({accuracy * 100:.2f}%)")
        report_lines.append(f"Macro Precision: {precision:.4f}")
        report_lines.append(f"Macro Recall:    {recall:.4f}")
        report_lines.append(f"Macro F1-score:  {f1:.4f}")
        report_lines.append("")
        report_lines.append("Classification Report:")
        report_lines.append(
            classification_report(
                y_true,
                y_pred,
                labels=LABELS,
                zero_division=0,
            )
        )
        report_lines.append("Confusion Matrix (rows=actual, columns=predicted):")
        report_lines.append(f"Label order: {LABELS}")
        report_lines.append(str(
            confusion_matrix(
                y_true,
                y_pred,
                labels=LABELS,
            )
        ))

    report_lines.append("")
    report_lines.append(
        "LIMITATION: This is a small, manually designed test set. "
        "The labels describe intended risk categories, not a formal "
        "proof that each program contains or does not contain a vulnerability. "
        "Results may be affected by overlap in patterns with training data."
    )

    report_text = "\n".join(report_lines)

    REPORT_FILE.write_text(report_text, encoding="utf-8")

    print()
    print(report_text)
    print()
    print(f"Predictions CSV: {PREDICTIONS_CSV}")
    print(f"Evaluation report: {REPORT_FILE}")


if __name__ == "__main__":
    main()