import re
import sys
from pathlib import Path


SSA = r"%[-a-zA-Z$._0-9]+"

def strip_comments(text):
    return "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith(";")
    )


def split_functions(ir_code):
    """Extract simple LLVM function definitions."""
    pattern = re.compile(
        r"define\b[^@\n]*@([-a-zA-Z$._0-9]+)"
        r"\(([^)]*)\)[^{]*\{(.*?)^\}",
        re.MULTILINE | re.DOTALL,
    )

    functions = {}

    for match in pattern.finditer(ir_code):
        functions[match.group(1)] = {
            "params": match.group(2),
            "body": match.group(3),
        }

    return functions


def resolve_constants(body):
    """
    Resolve simple integer constants through stores, loads,
    casts, and basic SSA references.

    This is deliberately limited. It is not a complete LLVM
    interpreter or general-purpose data-flow engine.
    """
    values = {}
    slots = {}

    lines = body.splitlines()

    # Repeated passes allow values to flow through simple chains.
    for _ in range(5):
        changed = False

        for line in lines:
            line = line.strip()

            # Store a constant or known SSA value into a stack slot.
            store_match = re.match(
                rf"store(?:\s+volatile)?\s+i\d+\s+"
                rf"({SSA}|-?\d+),\s*ptr\s+({SSA})",
                line,
            )

            if store_match:
                value, slot = store_match.groups()

                if re.fullmatch(r"-?\d+", value):
                    resolved = int(value)
                elif value in values:
                    resolved = values[value]
                else:
                    continue

                if slots.get(slot) != resolved:
                    slots[slot] = resolved
                    changed = True

                continue

            # Load an integer value from a known stack slot.
            load_match = re.match(
                rf"({SSA})\s*=\s*load(?:\s+atomic)?"
                rf"(?:\s+volatile)?\s+i\d+,\s*ptr\s+({SSA})",
                line,
            )

            if load_match:
                result, slot = load_match.groups()

                if slot in slots and values.get(result) != slots[slot]:
                    values[result] = slots[slot]
                    changed = True

                continue

            # Resolve integer casts such as sext and zext.
            cast_match = re.match(
                rf"({SSA})\s*=\s*(?:sext|zext|trunc)\s+"
                rf"i\d+\s+({SSA})\s+to\s+i\d+",
                line,
            )

            if cast_match:
                result, operand = cast_match.groups()

                if operand in values and values.get(result) != values[operand]:
                    values[result] = values[operand]
                    changed = True

                continue

            # Resolve simple arithmetic on known constants.
            arithmetic_match = re.match(
                rf"({SSA})\s*=\s*(add|sub|mul)\s+"
                rf"(?:nuw\s+|nsw\s+)*i\d+\s+"
                rf"({SSA}|-?\d+),\s*({SSA}|-?\d+)",
                line,
            )

            if arithmetic_match:
                result, operation, left, right = arithmetic_match.groups()

                def get_value(operand):
                    if re.fullmatch(r"-?\d+", operand):
                        return int(operand)
                    return values.get(operand)

                a = get_value(left)
                b = get_value(right)

                if a is None or b is None:
                    continue

                if operation == "add":
                    computed = a + b
                elif operation == "sub":
                    computed = a - b
                else:
                    computed = a * b

                if values.get(result) != computed:
                    values[result] = computed
                    changed = True

        if not changed:
            break

    return values, slots


def check_array_bounds(ir_code):
    findings = []

    functions = split_functions(ir_code)

    for function_name, function in functions.items():
        body = function["body"]
        values, _ = resolve_constants(body)

        # Match a GEP with a literal array dimension and two indexes.
        gep_pattern = re.compile(
            rf"({SSA})\s*=\s*getelementptr(?:\s+inbounds)?\s+"
            rf"\[(\d+)\s+x\s+[^\]]+\],\s*ptr\s+[^,]+,"
            rf"\s*i\d+\s+(-?\d+),\s*i\d+\s+({SSA}|-?\d+)"
        )

        for match in gep_pattern.finditer(body):
            result, length_text, first_index_text, element_text = (
                match.groups()
            )

            length = int(length_text)
            first_index = int(first_index_text)

            if re.fullmatch(r"-?\d+", element_text):
                element_index = int(element_text)
            else:
                element_index = values.get(element_text)

            if element_index is None:
                continue

            if first_index == 0 and not 0 <= element_index < length:
                findings.append({
                    "severity": "REVIEW",
                    "title": "Possible constant out-of-bounds array access",
                    "details": (
                        f"In function @{function_name}, GEP result "
                        f"{result} indexes an array of {length} elements "
                        f"using index {element_index}. Valid indexes are "
                        f"0 through {length - 1}. Review the access."
                    ),
                })

    return findings


def check_literal_zero_division(ir_code):
    findings = []

    functions = split_functions(ir_code)

    for function_name, function in functions.items():
        body = function["body"]
        values, _ = resolve_constants(body)

        division_pattern = re.compile(
            rf"({SSA})\s*=\s*(sdiv|udiv|srem|urem)\s+i\d+\s+"
            rf"([^,\n]+),\s*({SSA}|-?\d+)"
        )

        for match in division_pattern.finditer(body):
            result, operation, numerator, divisor = match.groups()

            if re.fullmatch(r"-?\d+", divisor):
                divisor_value = int(divisor)
            else:
                divisor_value = values.get(divisor)

            if divisor_value == 0:
                findings.append({
                    "severity": "REVIEW",
                    "title": "Possible integer division by zero",
                    "details": (
                        f"In function @{function_name}, instruction "
                        f"{result} uses {operation} with a divisor "
                        "resolved to constant zero by the simple "
                        "constant-propagation analysis."
                    ),
                })

    return findings


def check_simple_interprocedural_zero_division(ir_code):
    """
    Detect a simple zero argument flowing through a callee parameter,
    stack slot, load, and integer division/remainder instruction.
    """

    findings = []
    functions = split_functions(ir_code)

    ssa = r"%[-a-zA-Z$._0-9]+"

    call_pattern = re.compile(
        rf"\bcall\b[^@\n]*@([-a-zA-Z$._0-9]+)\(([^)]*)\)"
    )

    for caller_name, caller in functions.items():
        caller_body = caller["body"]
        caller_values, _ = resolve_constants(caller_body)

        for call_match in call_pattern.finditer(caller_body):
            callee_name, args_text = call_match.groups()
            callee = functions.get(callee_name)

            if callee is None:
                continue

            params = [
                p.strip()
                for p in callee["params"].split(",")
                if p.strip()
            ]
            args = [
                a.strip()
                for a in args_text.split(",")
                if a.strip()
            ]

            if len(params) != len(args):
                continue

            callee_body = callee["body"]

            for param, arg in zip(params, args):
                pm = re.search(rf"({ssa})\s*$", param)
                am = re.search(
                    rf"\bi\d+\s+(?:noundef\s+)?({ssa}|-?\d+)\s*$",
                    arg,
                )

                if not pm or not am:
                    continue

                param_name = pm.group(1)
                arg_value = am.group(1)

                if re.fullmatch(r"-?\d+", arg_value):
                    resolved_arg = int(arg_value)
                else:
                    resolved_arg = caller_values.get(arg_value)

                if resolved_arg != 0:
                    continue

                # Find the stack slot that stores this parameter.
                store_pattern = re.compile(
                    rf"store\s+i\d+\s+{re.escape(param_name)},"
                    rf"\s*ptr\s+({ssa})"
                )

                slots = store_pattern.findall(callee_body)

                for slot in slots:
                    # Find loads from this exact slot.
                    load_pattern = re.compile(
                        rf"({ssa})\s*=\s*load"
                        rf"(?:\s+atomic)?(?:\s+volatile)?"
                        rf"\s+i\d+,\s*ptr\s+{re.escape(slot)}"
                    )

                    loaded_values = load_pattern.findall(callee_body)

                    for loaded in loaded_values:
                        # Check if this loaded value is used as a divisor.
                        division_pattern = re.compile(
                            rf"({ssa})\s*=\s*(sdiv|udiv|srem|urem)"
                            rf"\s+i\d+\s+[^,\n]+,\s*"
                            rf"{re.escape(loaded)}(?:\s|,|$)"
                        )

                        division_match = division_pattern.search(
                            callee_body
                        )

                        if division_match:
                            findings.append({
                                "severity": "REVIEW",
                                "title": (
                                    "Possible interprocedural division by zero"
                                ),
                                "details": (
                                    f"Function @{caller_name} passes a "
                                    f"value resolved to zero into parameter "
                                    f"{param_name} of @{callee_name}. The "
                                    "parameter is stored, loaded, and used "
                                    "as the divisor of an integer "
                                    "division/remainder instruction. "
                                    "This is a review finding, not a "
                                    "general proof for arbitrary control flow."
                                ),
                            })
                            break

                    if findings:
                        break

                if findings:
                    break

            if findings:
                break

    return findings

def run_dataflow_checks(ir_path):
    ir_path = Path(ir_path)

    if not ir_path.exists():
        raise FileNotFoundError(f"IR file not found: {ir_path}")

    ir_code = strip_comments(
        ir_path.read_text(encoding="utf-8")
    )

    findings = []
    findings.extend(check_array_bounds(ir_code))
    findings.extend(check_literal_zero_division(ir_code))
    findings.extend(check_simple_interprocedural_zero_division(ir_code))

    # Avoid duplicate findings with identical titles.
    unique = []
    seen = set()

    for finding in findings:
        key = (finding["title"], finding["details"])
        if key not in seen:
            unique.append(finding)
            seen.add(key)

    return unique


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ir_dataflow_checks.py <LLVM-IR-file>")
        sys.exit(1)

    results = run_dataflow_checks(sys.argv[1])

    if not results:
        print("No configured data-flow patterns detected.")

    for finding in results:
        print(f"\n[{finding['severity']}] {finding['title']}")
        print(finding["details"])

    print("\nIR data-flow checks completed.")
    print("Findings are preliminary indicators, not confirmed vulnerabilities.")