import re
from pathlib import Path


def analyze_ir_security(ir_path):
    """
    Preliminary pattern-based LLVM IR security analysis.

    Findings are review indicators, not confirmed vulnerabilities.
    Regex-based checks are not a substitute for full data-flow analysis.
    """

    ir_path = Path(ir_path)

    if not ir_path.exists():
        raise FileNotFoundError(f"IR file not found: {ir_path}")

    ir_code = ir_path.read_text(encoding="utf-8")

    # Remove complete LLVM comment lines.
    lines = [
        line for line in ir_code.splitlines()
        if not line.lstrip().startswith(";")
    ]
    ir_code = "\n".join(lines)

    findings = []

    def add_finding(severity, title, details):
        # Avoid duplicate findings with the same title.
        if not any(item["title"] == title for item in findings):
            findings.append({
                "severity": severity,
                "title": title,
                "details": details,
            })

    # -------------------------------------------------
    # 1. Arithmetic instructions with overflow flags
    # -------------------------------------------------

    overflow_pattern = (
        r"\b(?:add|sub|mul)\s+"
        r"(?:nuw|nsw)(?:\s+(?:nuw|nsw))*\b"
    )

    if re.search(overflow_pattern, ir_code):
        add_finding(
            "INFO",
            "Overflow-related arithmetic flags detected",
            (
                "Arithmetic instructions use nuw or nsw flags. "
                "These express assumptions about overflow; their "
                "presence alone does not establish a vulnerability."
            ),
        )

    # -------------------------------------------------
    # 2. Integer division and remainder
    # -------------------------------------------------

    division_pattern = (
        r"^\s*%[-a-zA-Z$._0-9]+\s*=\s*"
        r"(?:sdiv|udiv|srem|urem)\b"
    )

    division_instructions = re.findall(
        division_pattern, ir_code, re.MULTILINE
    )

    if division_instructions:
        add_finding(
            "REVIEW",
            "Integer division or remainder detected",
            (
                f"Found {len(division_instructions)} integer "
                "division/remainder instruction(s). Review divisor "
                "values and input validation. This check does not "
                "prove that a divisor can be zero."
            ),
        )

    # Conservative check for literal zero operands.
    # Examples include: sdiv i32 %value, 0
    literal_zero_division = re.search(
        r"\b(?:sdiv|udiv|srem|urem)\s+"
        r"i\d+\s+[^,\n]+,\s*0(?:\s|,|$)",
        ir_code,
    )

    if literal_zero_division:
        add_finding(
            "REVIEW",
            "Possible division by literal zero",
            (
                "An integer division/remainder instruction appears "
                "to use literal zero as its divisor. Confirm the "
                "exact instruction and LLVM IR semantics."
            ),
        )

    # -------------------------------------------------
    # 3. Pointer calculations and array indexing
    # -------------------------------------------------

    gep_lines = re.findall(
        r"^\s*%[-a-zA-Z$._0-9]+\s*=\s*getelementptr\b[^\n]*",
        ir_code,
        re.MULTILINE,
    )

    if gep_lines:
        add_finding(
            "INFO",
            "Pointer calculation detected",
            (
                f"Found {len(gep_lines)} getelementptr instruction(s). "
                "Review indexes, object sizes, and memory accesses. "
                "These instructions alone do not prove an out-of-bounds access."
            ),
        )

    # Look for an obvious constant array-index pattern.
    #
    # This is only a screening heuristic. The IR type, allocation size,
    # nested aggregate layout, and index interpretation must be checked
    # before declaring a real out-of-bounds access.

    constant_index_candidates = []

    for line in gep_lines:
        indices = re.findall(
            r"\bi\d+\s+(-?\d+)\b",
            line,
        )

        # Ignore the first index: for a pointer to an aggregate,
        # it commonly selects the object itself or performs pointer arithmetic.
        # Remaining indexes may represent array/aggregate indexes.
        for index_text in indices[1:]:
            index_value = int(index_text)

            if index_value < 0:
                constant_index_candidates.append(
                    (line.strip(), index_value)
                )

    if constant_index_candidates:
        add_finding(
            "REVIEW",
            "Suspicious negative constant GEP index",
            (
                "A getelementptr instruction contains a negative "
                "constant index after its first index. Depending on "
                "the pointer and aggregate type, this may be valid "
                "pointer arithmetic or an invalid access. Inspect "
                "the source object and access before drawing conclusions."
            ),
        )

    # -------------------------------------------------
    # 4. Null pointer representations
    # -------------------------------------------------

    has_null = bool(
        re.search(r"\bnull\b", ir_code)
        or re.search(r"\binttoptr\s*\(\s*i\d+\s+0\b", ir_code)
    )

    if has_null:
        add_finding(
            "INFO",
            "Null-pointer representation detected",
            (
                "A null-pointer representation appears in the IR. "
                "Its presence alone does not prove a dereference."
            ),
        )

    # -------------------------------------------------
    # 5B. Limited null-pointer alias review heuristic
    # -------------------------------------------------

    # Trace a simple null pointer copy through stack storage, then
    # check whether the null-comparison true branch dereferences it.
    # This is a conservative regex heuristic, not full data-flow analysis.

    null_stores = re.findall(
        r"^\s*store\s+ptr\s+null\s*,\s*ptr\s+"
        r"(%[-a-zA-Z$._0-9]+)\b",
        ir_code,
        re.MULTILINE,
    )

    null_alias_finding = False

    for null_storage in null_stores:
        escaped_storage = re.escape(null_storage)

        # Find pointer values loaded from storage that was assigned null.
        null_values = re.findall(
            r"^\s*(%[-a-zA-Z$._0-9]+)\s*=\s*load\s+ptr\s*,\s*ptr\s+"
            + escaped_storage + r"\b",
            ir_code,
            re.MULTILINE,
        )

        for null_value in null_values:
            escaped_value = re.escape(null_value)

            # Find another storage location that receives that pointer.
            copied_storages = re.findall(
                r"^\s*store\s+ptr\s+" + escaped_value
                + r"\s*,\s*ptr\s+(%[-a-zA-Z$._0-9]+)\b",
                ir_code,
                re.MULTILINE,
            )

            for copied_storage in copied_storages:
                escaped_copy = re.escape(copied_storage)

                # Find pointer values loaded from the copied storage.
                aliases = re.findall(
                    r"^\s*(%[-a-zA-Z$._0-9]+)\s*=\s*load\s+ptr\s*,\s*ptr\s+"
                    + escaped_copy + r"\b",
                    ir_code,
                    re.MULTILINE,
                )

                for alias in aliases:
                    escaped_alias = re.escape(alias)

                    null_check = re.search(
                        r"^\s*(%[-a-zA-Z$._0-9]+)\s*=\s*icmp\s+eq\s+ptr\s+"
                        + escaped_alias + r",\s*null\b",
                        ir_code,
                        re.MULTILINE,
                    )
                    if not null_check:
                        continue

                    branch = re.search(
                        r"^\s*br\s+i1\s+"
                        + re.escape(null_check.group(1))
                        + r",\s*label\s+(%[-a-zA-Z$._0-9]+)"
                        + r",\s*label\s+(%[-a-zA-Z$._0-9]+)",
                        ir_code,
                        re.MULTILINE,
                    )
                    if not branch:
                        continue

                    # LLVM branch operands use %7, but the block definition
                    # is written as "7:", so remove the leading percent sign.
                    true_label = branch.group(1).lstrip("%")

                    block_start = re.search(
                        r"(?m)^\s*" + re.escape(true_label) + r"\s*:(?:[^\n]*)\n",
                        ir_code,
                    )
                    if not block_start:
                        continue

                    remaining_ir = ir_code[block_start.end():]
                    next_block = re.search(
                        r"(?m)^\s*[-a-zA-Z$._0-9]+\s*:(?:[^\n]*)$",
                        remaining_ir,
                    )
                    true_block = (
                        remaining_ir[:next_block.start()]
                        if next_block
                        else remaining_ir
                    )

                    # The branch may reload the alias into a fresh SSA
                    # pointer (e.g. %8), and dereference that new value.
                    pointer_loads_in_block = re.findall(
                        r"^\s*(%[-a-zA-Z$._0-9]+)\s*=\s*load\s+ptr\s*,\s*ptr\s+"
                        + escaped_copy + r"\b",
                        true_block,
                        re.MULTILINE,
                    )

                    pointer_candidates = set(pointer_loads_in_block)
                    pointer_candidates.add(alias)

                    for loaded_pointer in pointer_candidates:
                        if re.search(
                            r"^\s*%[-a-zA-Z$._0-9]+\s*=\s*"
                            r"load\s+(?!ptr\b)[^,\n]+,\s*ptr\s+"
                            + re.escape(loaded_pointer) + r"\b",
                            true_block,
                            re.MULTILINE,
                        ):
                            add_finding(
                                "REVIEW",
                                "Possible null-pointer alias dereference",
                                (
                                    "A pointer value originating from a null store "
                                    "appears to be copied through pointer storage, "
                                    "checked against null, and dereferenced in the "
                                    "true branch. This limited heuristic does not "
                                    "prove general pointer aliases or reachability."
                                ),
                            )
                            null_alias_finding = True
                            break

                    if null_alias_finding:
                        break
                if null_alias_finding:
                    break
            if null_alias_finding:
                break
        if null_alias_finding:
            break

    # -------------------------------------------------
    # 6. Pointer-return review heuristic
    # -------------------------------------------------

    pointer_return_pattern = re.compile(
        r"^\s*ret\s+ptr\s+(%[-a-zA-Z$._0-9]+)\b",
        re.MULTILINE,
    )

    if pointer_return_pattern.search(ir_code):
        add_finding(
            "REVIEW",
            "Pointer return requires lifetime review",
            (
                "The IR returns a pointer value. Returning a pointer "
                "is not inherently unsafe. Check whether it refers "
                "to an object whose lifetime has ended."
            ),
        )

    # -------------------------------------------------
    # 7. Memory operation statistics
    # -------------------------------------------------

    load_count = len(re.findall(r"\bload\b", ir_code))
    store_count = len(re.findall(r"\bstore\b", ir_code))

    if load_count or store_count:
        add_finding(
            "INFO",
            "Memory operation summary",
            (
                f"Found {load_count} load instruction(s) and "
                f"{store_count} store instruction(s). These operations "
                "are normal LLVM IR instructions, not vulnerabilities "
                "by themselves."
            ),
        )

    # -------------------------------------------------
    # 8. Comparisons and branches
    # -------------------------------------------------

    has_comparison = bool(
        re.search(r"\b(?:icmp|fcmp)\b", ir_code)
    )
    has_branch = bool(
        re.search(r"^\s*br\b", ir_code, re.MULTILINE)
    )

    if has_comparison and has_branch:
        add_finding(
            "INFO",
            "Comparison and branch instructions detected",
            (
                "The IR contains comparisons and branches. Their "
                "presence does not prove that security checks are "
                "correct; inspect conditions and control-flow paths."
            ),
        )

    # -------------------------------------------------
    # 9. No configured patterns found
    # -------------------------------------------------

    if not findings:
        add_finding(
            "INFO",
            "No configured patterns found",
            (
                "The analyzer did not identify configured patterns. "
                "This does not establish that the program is safe."
            ),
        )

    return findings


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python static_analyzer.py "
            "<path-to-LLVM-IR-file>"
        )
        sys.exit(1)

    test_file = Path(sys.argv[1])
    results = analyze_ir_security(test_file)

    print("\n========== SecureIR Static Analysis ==========")
    print(f"Analyzed file: {test_file.name}")

    for index, finding in enumerate(results, start=1):
        print(f"\nFinding {index}: {finding['title']}")
        print(f"Severity: {finding['severity']}")
        print(f"Details: {finding['details']}")

    print("\nStatic analysis completed.")
    print(
        "Note: Findings are preliminary indicators, "
        "not confirmed vulnerabilities."
    )
