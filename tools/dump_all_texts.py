#!/usr/bin/env python3
"""Dump every text file (line-by-line) into tools/full_read/ and create index.json."""
from __future__ import annotations
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = Path(__file__).resolve().parent / "full_read"
EXCLUDE_PARTS = ["/target/", "/.git/", "/aether_repo/extracted/", "/aether-symbiont/node_modules/", "/node_modules/", "/data/_pytest_tmp/", "/.venv/", "/build/", "/dist/"]
TEXT_EXTS = {'.py', '.md', '.rs', '.toml', '.json', '.yaml', '.yml', '.txt', '.js', '.ts', '.html', '.css', '.cfg', '.ini', '.spec', '.sh', '.ps1'}


def is_excluded(path: Path) -> bool:
    s = str(path).replace('\\', '/')
    return any(part in s for part in EXCLUDE_PARTS)


def is_likely_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    try:
        with path.open('rb') as f:
            head = f.read(2048)
            if b'\x00' in head:
                return False
            nonprint = sum(1 for b in head if b < 9 or (b > 13 and b < 32))
            if len(head) > 0 and (nonprint / len(head)) > 0.30:
                return False
            return True
    except Exception:
        return False


def main() -> int:
    out_files = []
    count = 0
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file():
            continue
        if is_excluded(p):
            continue
        try:
            if not is_likely_text(p):
                continue
            rel = p.relative_to(ROOT)
            dest = OUT_ROOT / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            txt = p.read_text(encoding='utf-8', errors='replace')
            dest.write_text(txt, encoding='utf-8')
            out_files.append({
                'path': str(rel).replace('\\', '/'),
                'lines': len(txt.splitlines()),
                'size': p.stat().st_size,
            })
            count += 1
        except Exception:
            continue

    index = {
        'root': str(ROOT),
        'count': count,
        'files': out_files,
    }
    (OUT_ROOT / 'index.json').write_text(json.dumps(index, indent=2), encoding='utf-8')
    print(f'Wrote {count} files into {OUT_ROOT} (index: {OUT_ROOT / "index.json"})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
