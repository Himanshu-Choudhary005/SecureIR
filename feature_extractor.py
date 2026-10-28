
import re
from pathlib import Path


def extract_features(ir_path):
    """
    Extract basic and security-relevant indicators from LLVM IR.

    These features are indicators for ML classification.
    They do not independently prove a vulnerability.
    """

    ir_path = Path(ir_path)

    if not ir_path.exists():
        raise FileNotFoundError(f"IR file not found: {ir_path}")

    ir_code = ir_path.read_text(encoding="utf-8")

    # Remove full-line LLVM comments.
    lines = []

    for line in ir_code.splitlines():
        if line.lstrip().startswith(";"):
            continue
        lines.append(line)

    ir_code = "\n".join(lines)

    # Basic LLVM IR instruction counts.
    patterns = {
        "load_count": r"\bload\b",
        "store_count": r"\bstore\b",
        "alloca_count": r"\balloca\b",
        "add_count": r"\badd\b",
        "sub_count": r"\bsub\b",
        "mul_count": r"\bmul\b",
        "call_count": r"\bcall\b",
        "branch_count": r"\bbr\b",

        # Count GEP instructions separately.
        "getelementptr_count": r"\bgetelementptr\b",

        "comparison_count": r"\bicmp\b|\bfcmp\b",
        "select_count": r"\bselect\b",
        "phi_count": r"\bphi\b",
        "volatile_count": r"\bvolatile\b",
        "atomic_count": r"\batomic\b|\bcmpxchg\b|\batomicrmw\b",
        "integer_division_count": r"\b[su]div\b|\b[su]rem\b",
        "shift_count": r"\b[ls]hr\b|\bshl\b",
        "trunc_count": r"\btrunc\b",
        "extension_count": r"\b(?:zext|sext)\b",
        "return_count": r"\bret\b",
        "unreachable_count": r"\bunreachable\b",
    }

    features = {}

    for feature_name, pattern in patterns.items():
        features[feature_name] = len(
            re.findall(pattern, ir_code)
        )

    # Count pointer-typed operands/instructions.
    # This is a rough indicator, not a count of unique pointers.
    features["pointer_count"] = len(
        re.findall(r"\bptr\b", ir_code)
    )

    # Count explicit null pointer stores.
    features["null_pointer_store_count"] = len(
        re.findall(
            r"\bstore\b[^,\n]*\bptr\s+null\b",
            ir_code
        )
    )

    # Count return instructions whose returned value is pointer-typed.
    # Example: ret ptr %1
    features["pointer_return_count"] = len(
        re.findall(
            r"^\s*ret\s+ptr\b",
            ir_code,
            flags=re.MULTILINE
        )
    )

    # Preliminary indicator only.
    features["has_bounds_related_operations"] = int(
        features["getelementptr_count"] > 0
        and features["comparison_count"] > 0
        and features["branch_count"] > 0
    )

    features["has_integer_arithmetic"] = int(
        features["add_count"] > 0
        or features["sub_count"] > 0
        or features["mul_count"] > 0
        or features["integer_division_count"] > 0
    )

    return features


if __name__ == "__main__":

    ir_file = Path("sample.ll")

    if not ir_file.exists():
        print(
            f"Test file not found: {ir_file.resolve()}\n"
            "Run the feature extractor through the dataset pipeline "
            "or provide an existing LLVM IR file."
        )
    else:
        features = extract_features(ir_file)

        print("\n===== SecureIR Feature Extraction =====")

        for name, value in features.items():
            print(f"{name:35}: {value}")

        print("\nFeature extraction completed.")

