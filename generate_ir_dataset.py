import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SOURCE_DIR = BASE_DIR / "dataset" / "source"
IR_DIR = BASE_DIR / "dataset" / "ir"

CLANG = Path(
    r"C:\Users\HIMANSHU CHOUDHARY\Downloads"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc.tar"
    r"\clang+llvm-23.1.0-x86_64-pc-windows-msvc"
    r"\bin\clang.exe"
)

if not CLANG.exists():
    print("ERROR: Clang executable not found.")
    raise SystemExit(1)

source_files = sorted(SOURCE_DIR.rglob("*.c"))

if not source_files:
    print("ERROR: No C source files found.")
    raise SystemExit(1)

success = 0
failed = 0

for source_file in source_files:

    category = source_file.parent.name

    output_dir = IR_DIR / category
    output_dir.mkdir(parents=True, exist_ok=True)

    ir_file = output_dir / f"{source_file.stem}.ll"

    command = [
        str(CLANG),
        "-S",
        "-emit-llvm",
        "-O0",
        "-Wno-array-bounds",
        str(source_file),
        "-o",
        str(ir_file)
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[FAILED] {source_file.name}")
        print(result.stderr)
        failed += 1
        continue

    # Verify that the IR contains a function definition.
    ir_text = ir_file.read_text(encoding="utf-8")

    if "define " not in ir_text:
        print(f"[INVALID IR] {source_file.name}")
        print("IR file:", ir_file)
        print("IR content:")
        print(ir_text[:1500])
        failed += 1
        continue

    print(f"[SUCCESS] {source_file.name}")
    success += 1

print("\n========== SecureIR ==========")
print(f"Successful: {success}")
print(f"Failed: {failed}")
print("==============================")