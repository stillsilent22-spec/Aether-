"""Fix: ensure 'from __future__ import annotations' is the first statement in every module."""
import pathlib
import re

MODULES = pathlib.Path("modules")
FUTURE_LINE = "from __future__ import annotations\n"

fixed = []
skipped = []
errors = []

for py_file in sorted(MODULES.glob("*.py")):
    try:
        src = py_file.read_text(encoding="utf-8", errors="replace")
        lines = src.splitlines(keepends=True)

        # Find first non-blank, non-comment, non-encoding line
        first_code_idx = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                first_code_idx = i
                break

        if first_code_idx is None:
            skipped.append(py_file.name)
            continue

        first_code = lines[first_code_idx].strip()

        # Already correct
        if first_code == "from __future__ import annotations":
            skipped.append(py_file.name)
            continue

        # Has __future__ somewhere later
        has_future = any(
            l.strip() == "from __future__ import annotations" for l in lines
        )

        if not has_future:
            skipped.append(py_file.name)
            continue

        # Remove all existing __future__ lines
        new_lines = [l for l in lines if l.strip() != "from __future__ import annotations"]

        # Prepend __future__ before first code line
        # Find first non-blank, non-comment line again in new_lines
        insert_idx = 0
        for i, line in enumerate(new_lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                insert_idx = i
                break

        new_lines.insert(insert_idx, FUTURE_LINE)
        new_src = "".join(new_lines)

        py_file.write_text(new_src, encoding="utf-8")
        fixed.append(py_file.name)

    except Exception as e:
        errors.append(f"{py_file.name}: {e}")

print(f"Fixed {len(fixed)} files:")
for f in fixed:
    print(f"  {f}")
if errors:
    print(f"\nErrors ({len(errors)}):")
    for e in errors:
        print(f"  {e}")
print(f"\nSkipped (already ok or no __future__): {len(skipped)}")
