import re
from pathlib import Path

# Read the LLVM IR file
ir_file = Path("sample.ll")

if not ir_file.exists():
    print("Error: sample.ll not found!")
    raise SystemExit(1)

ir_code = ir_file.read_text(encoding="utf-8")

# LLVM instruction patterns
instructions = {
    "alloca": r"\balloca\b",
    "load": r"\bload\b",
    "store": r"\bstore\b",
    "add": r"\badd\b",
    "sub": r"\bsub\b",
    "mul": r"\bmul\b",
    "call": r"\bcall\b",
    "branch": r"\bbr\b",
    "return": r"\bret\b",
    "pointer_operations": r"\bgetelementptr\b"
}

print("\n================================")
print("       SecureIR Analyzer")
print("================================")

for name, pattern in instructions.items():
    count = len(re.findall(pattern, ir_code))
    print(f"{name:25}: {count}")

print("================================")
print("IR Analysis Completed!")