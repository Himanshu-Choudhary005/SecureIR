from pathlib import Path
import subprocess
import sys

import joblib
import pandas as pd

from feature_extractor import extract_features
from static_analyzer import analyze_ir_security
from ir_dataflow_checks import run_dataflow_checks


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "secureir_model.joblib"

CLANG_PATH = Path(
    r"C:\Users\HIMANSHU CHOUDHARY\Downloads"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc.tar"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc"
    r"\bin\clang.exe"
)

REPORT_DIR = BASE_DIR / "reports"


def compile_c_to_ir(source_path):
    """Compile a C source file into LLVM IR."""

    source_path = Path(source_path).resolve()

    if not source_path.exists():
        raise FileNotFoundError(
            f"C source file not found: {source_path}"
        )

    if source_path.suffix.lower() != ".c":
        raise ValueError(
            "Input file must have a .c extension."
        )

    if not CLANG_PATH.exists():
        raise FileNotFoundError(
            f"Clang not found: {CLANG_PATH}"
        )

    ir_dir = BASE_DIR / "generated_ir"
    ir_dir.mkdir(parents=True, exist_ok=True)

    ir_path = ir_dir / f"{source_path.stem}.ll"

    command = [
        str(CLANG_PATH),
        "-S",
        "-emit-llvm",
        "-O0",
        "-Xclang",
        "-disable-O0-optnone",
        "-Wno-everything",
        str(source_path),
        "-o",
        str(ir_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Clang compilation failed:\n" + result.stderr
        )

    if not ir_path.exists() or ir_path.stat().st_size == 0:
        raise RuntimeError(
            "Clang did not generate a valid LLVM IR file."
        )

    print(f"\n[SUCCESS] LLVM IR generated: {ir_path}")

    if result.stderr.strip():
        print("\nCompiler diagnostics:")
        print(result.stderr)

    return ir_path



def build_report(ir_path, prediction, features, findings):
    """Build the combined ML and static-analysis report."""

    lines = []

    # Count findings by severity.
    review_count = sum(
        finding.get("severity") == "REVIEW"
        for finding in findings
    )

    info_count = sum(
        finding.get("severity") == "INFO"
        for finding in findings
    )

    # Determine the overall assessment.
    if review_count > 0:
        assessment = "POTENTIAL RISK - MANUAL REVIEW REQUIRED"
        assessment_reason = (
            f"{review_count} finding(s) require manual review."
        )

    elif prediction != "SAFE":
        assessment = "ML FLAGGED RISK - MANUAL REVIEW REQUIRED"
        assessment_reason = (
            f"The ML model classified this program as {prediction}. "
            "This prediction is experimental and needs verification."
        )

    else:
        assessment = (
            "NO CONFIGURED REVIEW PATTERNS DETECTED - "
            "NOT A SAFETY GUARANTEE"
        )
        assessment_reason = (
            "No REVIEW findings were generated, and the ML model "
            "predicted SAFE. Undetected risks may still exist."
        )

    lines.append("=" * 60)
    lines.append("             SecureIR Analysis Report")
    lines.append("=" * 60)

    lines.append(f"IR File            : {Path(ir_path).name}")
    lines.append(f"ML Predicted Class : {prediction}")

    lines.append("")
    lines.append("--- Overall Security Assessment ---")
    lines.append(assessment)
    lines.append(f"Reason: {assessment_reason}")

    lines.append("")
    lines.append("--- Extracted IR Features ---")

    for name, value in features.items():
        lines.append(f"{name:35}: {value}")

    lines.append("")
    lines.append("--- Combined Security Findings ---")

    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.append("")
            lines.append(f"Finding {index}: {finding['title']}")
            lines.append(
                f"Severity: {finding.get('severity', 'INFO')}"
            )
            lines.append(
                f"Source  : {finding.get('source', 'Static analysis')}"
            )
            lines.append(
                f"Details : {finding.get('details', 'No details available.')}"
            )
    else:
        lines.append(
            "No findings were reported by the configured rules."
        )

    lines.append("")
    lines.append("--- Summary ---")
    lines.append(f"Total findings       : {len(findings)}")
    lines.append(f"Review findings      : {review_count}")
    lines.append(f"Informational findings: {info_count}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("Analysis completed.")
    lines.append("ML prediction is experimental.")
    lines.append(
        "Static and data-flow findings are preliminary indicators, "
        "not confirmed vulnerabilities."
    )
    lines.append(
        "Absence of findings does not prove that a program is secure."
    )
    lines.append("=" * 60)

    return "\n".join(lines)


def save_report(ir_path, report_text):
    """Save the report without overwriting an existing report."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report_path = REPORT_DIR / f"{Path(ir_path).stem}_report.txt"

    counter = 2

    while report_path.exists():
        report_path = REPORT_DIR / (
            f"{Path(ir_path).stem}_report_{counter}.txt"
        )
        counter += 1

    report_path.write_text(
        report_text,
        encoding="utf-8",
    )

    return report_path


def analyze_ir(ir_path):
    """Run ML prediction, static analysis, and data-flow checks."""

    ir_path = Path(ir_path).resolve()

    if not ir_path.exists():
        raise FileNotFoundError(
            f"LLVM IR file not found: {ir_path}"
        )

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "ML model not found. Run: python train_model.py"
        )

    model = joblib.load(MODEL_PATH)

    # 1. Extract features.
    features = extract_features(ir_path)

    feature_df = pd.DataFrame([features])

    # 2. Match model's expected feature columns.
    if hasattr(model, "feature_names_in_"):
        feature_df = feature_df.reindex(
            columns=model.feature_names_in_,
            fill_value=0,
        )

    # 3. Predict program risk category.
    prediction = model.predict(feature_df)[0]

    # 4. Run existing static checks.
    static_findings = analyze_ir_security(ir_path)

    for finding in static_findings:
        finding["source"] = "Static analysis"

    # 5. Run new LLVM IR data-flow checks.
    dataflow_findings = run_dataflow_checks(ir_path)

    for finding in dataflow_findings:
        finding["source"] = "IR data-flow analysis"

    # 6. Combine findings.
    findings = static_findings + dataflow_findings

    # 7. Build and display report.
    report_text = build_report(
        ir_path,
        prediction,
        features,
        findings,
    )

    print("\n" + report_text)

    # 8. Save report.
    report_path = save_report(
        ir_path,
        report_text,
    )

    print(f"\n[SUCCESS] Report saved: {report_path}")


def main():
    if len(sys.argv) != 2:
        print("SecureIR - ML-Based IR Security Analysis")
        print("\nUsage:")
        print("  python secureir_analyzer.py <source.c>")
        print("  python secureir_analyzer.py <input.ll>")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    if not input_path.is_absolute():
        input_path = BASE_DIR / input_path

    if not input_path.exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    try:
        extension = input_path.suffix.lower()

        if extension == ".c":
            ir_path = compile_c_to_ir(input_path)
        elif extension == ".ll":
            ir_path = input_path
        else:
            raise ValueError(
                "Unsupported file type. Provide a .c or .ll file."
            )

        analyze_ir(ir_path)

    except (
        FileNotFoundError,
        RuntimeError,
        ValueError,
    ) as error:
        print(f"\nError: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()