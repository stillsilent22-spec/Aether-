#!/usr/bin/env python3
"""Heuristisches Tool: Suche nach ungenutzten Python-Funktionen/Methoden.

Erzeugt `tools/unused_defs_report.json` mit Verdachtsfällen.

Hinweis: Dies ist eine statische Heuristik (keine perfekte Abdeckung).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE_PARTS = ["/target/", "/.git/", "/aether_repo/extracted/", "/aether-symbiont/node_modules/", "/node_modules/", "/data/_pytest_tmp/"]


def is_excluded(path: Path) -> bool:
    s = str(path).replace("\\", "/")
    return any(part in s for part in EXCLUDE_PARTS)


class Analyzer(ast.NodeVisitor):
    def __init__(self, relpath: Path, defs: Dict, calls: Dict):
        self.relpath = relpath
        self.defs = defs
        self.calls = calls
        self.class_stack: List[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.class_stack:
            shortname = f"{self.class_stack[-1]}.{node.name}"
            kind = "method"
        else:
            shortname = node.name
            kind = "function"
        defid = f"{self.relpath}:{shortname}"
        self.defs[defid] = {
            "file": str(self.relpath),
            "name": shortname,
            "short": node.name,
            "lineno": node.lineno,
            "kind": kind,
        }
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return self.visit_FunctionDef(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name:
            self.calls[name] = self.calls.get(name, 0) + 1
        self.generic_visit(node)


def main() -> int:
    py_files = [p for p in ROOT.rglob("*.py") if not is_excluded(p)]
    defs: Dict[str, Dict] = {}
    calls: Dict[str, int] = {}

    for path in sorted(py_files):
        try:
            src = path.read_text(encoding="utf-8")
        except Exception:
            continue
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        rel = path.relative_to(ROOT)
        analyzer = Analyzer(rel, defs, calls)
        analyzer.visit(tree)

    candidates = []
    for defid, meta in defs.items():
        short = meta.get("short")
        # heuristik: private (leading underscore) überspringen
        if short.startswith("_"):
            continue
        used_count = calls.get(short, 0)
        if used_count == 0:
            candidates.append({**meta, "used_count": used_count})

    report = {
        "root": str(ROOT),
        "total_py_files": len(py_files),
        "total_defs": len(defs),
        "total_calls_names": len(calls),
        "candidates": sorted(candidates, key=lambda x: (x["file"], x["lineno"]))[:1000],
    }

    out_path = ROOT / "tools" / "unused_defs_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote report: {out_path} (candidates: {len(report['candidates'])})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
